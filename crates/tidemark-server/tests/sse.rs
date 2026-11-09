//! B5 SSE-S3 at rest: the master key comes from a file or a `TIDEMARK_*` variable, objects
//! (single PUT, multipart, copy) round-trip, and no plaintext byte ever lands under `blobs/`
//! or `tmp/`. A configured key is never generated, and a different key cannot read the data.

mod common;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, ServerSideEncryption};
use common::*;
use std::path::Path;
use tidemark_blob::BlobStore as _;

/// Distinct pseudo-random bytes per `seed`, so a 64-byte window identifies its payload.
fn payload(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

fn single() -> Vec<u8> {
    payload(1, 300_000)
}

fn parts() -> [Vec<u8>; 2] {
    [payload(2, 5 * 1024 * 1024), payload(3, 100_000)]
}

/// 64-byte windows taken from every payload the test writes.
fn needles() -> Vec<Vec<u8>> {
    let [p1, p2] = parts();
    [single(), p1, p2]
        .iter()
        .flat_map(|p| [p[..64].to_vec(), p[p.len() / 2..p.len() / 2 + 64].to_vec()])
        .collect()
}

fn plaintext_on_disk(dir: &Path) -> bool {
    needles()
        .iter()
        .any(|n| tree_contains(&dir.join("blobs"), n) || tree_contains(&dir.join("tmp"), n))
}

fn hex(k: &[u8; 32]) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

fn encrypted(dir: &Path, env: &[(&str, String)]) -> tidemark_core::Config {
    let mut cfg = tidemark_server::test_support::test_config(dir);
    cfg.storage.encrypt_at_rest = true;
    cfg.with_env(env.iter().map(|(k, v)| (k.to_string(), v.clone())))
        .unwrap()
}

/// PUT (with `x-amz-server-side-encryption: AES256`), multipart and copy, read back.
async fn write_objects(node: &Node) {
    let s3 = &node.s3;
    node.bucket("sse").await;
    s3.put_object()
        .bucket("sse")
        .key("single")
        .server_side_encryption(ServerSideEncryption::Aes256)
        .body(ByteStream::from(single()))
        .send()
        .await
        .unwrap();
    let up = s3
        .create_multipart_upload()
        .bucket("sse")
        .key("multi")
        .send()
        .await
        .unwrap();
    let id = up.upload_id.unwrap();
    let mut done = Vec::new();
    for (i, p) in parts().into_iter().enumerate() {
        let n = i as i32 + 1;
        let r = s3
            .upload_part()
            .bucket("sse")
            .key("multi")
            .upload_id(&id)
            .part_number(n)
            .body(ByteStream::from(p))
            .send()
            .await
            .unwrap();
        done.push(
            CompletedPart::builder()
                .part_number(n)
                .e_tag(r.e_tag.unwrap())
                .build(),
        );
    }
    s3.complete_multipart_upload()
        .bucket("sse")
        .key("multi")
        .upload_id(&id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(done))
                .build(),
        )
        .send()
        .await
        .unwrap();
    s3.copy_object()
        .bucket("sse")
        .key("copied")
        .copy_source("sse/single")
        .send()
        .await
        .unwrap();
}

async fn read_back(node: &Node) {
    assert_eq!(node.get("sse", "single").await, single());
    assert_eq!(node.get("sse", "multi").await, parts().concat());
    assert_eq!(node.get("sse", "copied").await, single());
    let r = node
        .s3
        .get_object()
        .bucket("sse")
        .key("multi")
        .range("bytes=5242870-5242889")
        .send()
        .await
        .unwrap();
    let got = r.body.collect().await.unwrap().into_bytes();
    assert_eq!(&got[..], &parts().concat()[5_242_870..5_242_890]);
}

#[tokio::test]
async fn sse_s3_key_from_file_never_writes_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let secrets = tempfile::tempdir().unwrap();
    let key = [0x5a; 32];
    let key_file = secrets.path().join("master.key");
    std::fs::write(&key_file, key).unwrap();
    let file_env = [(
        "TIDEMARK_STORAGE_MASTER_KEY_FILE",
        key_file.display().to_string(),
    )];

    let node = Node::start(encrypted(dir.path(), &file_env)).await;
    write_objects(&node).await;
    read_back(&node).await;
    assert!(
        !plaintext_on_disk(dir.path()),
        "plaintext found under blobs/ or tmp/"
    );
    let (files, _) = blob_files(dir.path());
    assert!(files >= 3, "expected blob files, found {files}");
    assert!(all_encrypted(&dir.path().join("blobs")));
    assert!(
        !dir.path().join("keys").join("master.key").exists(),
        "a key was generated next to the data although one was configured"
    );
    node.stop().await;

    // The same key from the environment as hex reads the same data.
    let hex_env = [("TIDEMARK_STORAGE_MASTER_KEY", hex(&key))];
    let node = Node::start(encrypted(dir.path(), &hex_env)).await;
    read_back(&node).await;
    node.stop().await;

    // A different key cannot read it: the server refuses to start (IAM secrets are sealed
    // under the same key), and every blob fails authentication under that key while
    // verifying under the configured one.
    let wrong = [0x11; 32];
    let err = tidemark_server::Server::bind(encrypted(
        dir.path(),
        &[("TIDEMARK_STORAGE_MASTER_KEY", hex(&wrong))],
    ))
    .await
    .err()
    .expect("started with a different master key");
    assert!(format!("{err:#}").contains("cannot unseal"), "{err:#}");
    let store = tidemark_blob::FsBlobStore::open(dir.path(), false).unwrap();
    let ids = blob_ids(&dir.path().join("blobs"));
    assert!(ids.len() >= 3);
    for id in ids {
        let right = store
            .verify(&id, Some(&tidemark_blob::DataKey::new(key)))
            .await;
        assert!(right.unwrap(), "blob {id} does not verify under its key");
        let bad = store
            .verify(&id, Some(&tidemark_blob::DataKey::new(wrong)))
            .await;
        assert!(
            !bad.unwrap_or(false),
            "blob {id} verified under a wrong key"
        );
    }
}

#[tokio::test]
async fn sse_s3_key_from_env_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let env = [("TIDEMARK_STORAGE_MASTER_KEY", hex(&[0xc3; 32]))];
    let node = Node::start(encrypted(dir.path(), &env)).await;
    write_objects(&node).await;
    read_back(&node).await;
    assert!(!plaintext_on_disk(dir.path()));
    assert!(all_encrypted(&dir.path().join("blobs")));
    node.stop().await;
}

#[tokio::test]
async fn missing_configured_key_file_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let env = [(
        "TIDEMARK_STORAGE_MASTER_KEY_FILE",
        dir.path().join("nope").display().to_string(),
    )];
    let err = tidemark_server::Server::bind(encrypted(dir.path(), &env)).await;
    assert!(err.is_err(), "started without its configured master key");
    assert!(!dir.path().join("nope").exists());
    assert!(!dir.path().join("keys").join("master.key").exists());
}

/// The walk is not vacuous: without encryption the same payloads are found in clear.
#[tokio::test]
async fn unencrypted_store_is_found_by_the_plaintext_walk() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path()).await;
    node.bucket("sse").await;
    node.put("sse", "single", single()).await;
    assert!(plaintext_on_disk(dir.path()));
    node.stop().await;
}

/// Every file under `dir` is an `.enc` blob.
fn all_encrypted(dir: &Path) -> bool {
    std::fs::read_dir(dir).unwrap().flatten().all(|e| {
        let p = e.path();
        if p.is_dir() {
            all_encrypted(&p)
        } else {
            p.extension().is_some_and(|x| x == "enc")
        }
    })
}

/// Ids of the blob files under `dir`.
fn blob_ids(dir: &Path) -> Vec<tidemark_core::BlobId> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(blob_ids(&p));
        } else if let Some(h) = p.file_name().and_then(|n| n.to_str()) {
            out.push(h.trim_end_matches(".enc").parse().unwrap());
        }
    }
    out
}

fn sse_config(alg: ServerSideEncryption) -> aws_sdk_s3::types::ServerSideEncryptionConfiguration {
    use aws_sdk_s3::types::{
        ServerSideEncryptionByDefault, ServerSideEncryptionConfiguration, ServerSideEncryptionRule,
    };
    ServerSideEncryptionConfiguration::builder()
        .rules(
            ServerSideEncryptionRule::builder()
                .apply_server_side_encryption_by_default(
                    ServerSideEncryptionByDefault::builder()
                        .sse_algorithm(alg)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .build()
        .unwrap()
}

/// Put/Get/DeleteBucketEncryption: SSE-S3 only, and only on a store with a master key.
#[tokio::test]
async fn bucket_encryption_config_round_trips_on_an_encrypted_store() {
    let dir = tempfile::tempdir().unwrap();
    let env = [("TIDEMARK_STORAGE_MASTER_KEY", hex(&[0x5a; 32]))];
    let node = Node::start(encrypted(dir.path(), &env)).await;
    let s3 = &node.s3;
    node.bucket("enc").await;
    let get = || s3.get_bucket_encryption().bucket("enc").send();
    assert_eq!(
        code(get().await),
        "ServerSideEncryptionConfigurationNotFoundError"
    );
    s3.delete_bucket_encryption()
        .bucket("enc")
        .send()
        .await
        .unwrap();
    s3.put_bucket_encryption()
        .bucket("enc")
        .server_side_encryption_configuration(sse_config(ServerSideEncryption::Aes256))
        .send()
        .await
        .unwrap();
    let got = get().await.unwrap();
    let rule = &got.server_side_encryption_configuration().unwrap().rules()[0];
    assert_eq!(
        rule.apply_server_side_encryption_by_default()
            .unwrap()
            .sse_algorithm(),
        &ServerSideEncryption::Aes256
    );
    assert_eq!(
        code(
            s3.put_bucket_encryption()
                .bucket("enc")
                .server_side_encryption_configuration(sse_config(ServerSideEncryption::AwsKms))
                .send()
                .await
        ),
        "NotImplemented"
    );
    s3.delete_bucket_encryption()
        .bucket("enc")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(get().await),
        "ServerSideEncryptionConfigurationNotFoundError"
    );
    node.stop().await;
}

/// Without a master key, asking for bucket encryption is refused rather than recorded as true.
#[tokio::test]
async fn bucket_encryption_needs_a_master_key() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path()).await;
    node.bucket("plain").await;
    assert_eq!(
        code(
            node.s3
                .put_bucket_encryption()
                .bucket("plain")
                .server_side_encryption_configuration(sse_config(ServerSideEncryption::Aes256))
                .send()
                .await
        ),
        "InvalidRequest"
    );
    node.stop().await;
}

/// A master key other than the one the data dir was initialised with stops startup with a
/// message naming the key, instead of serving 500s on every authenticated request.
#[tokio::test]
async fn wrong_master_key_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path()).await;
    node.stop().await;
    for keep_root_in_config in [true, false] {
        let mut cfg = tidemark_server::test_support::test_config(dir.path());
        if !keep_root_in_config {
            cfg.auth.root_access_key = None;
            cfg.auth.root_secret_key = None;
        }
        let cfg = cfg
            .with_env([("TIDEMARK_STORAGE_MASTER_KEY".to_string(), hex(&[0x11; 32]))])
            .unwrap();
        let err = match tidemark_server::Server::bind(cfg).await {
            Ok(_) => panic!("started with the wrong master key"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("cannot unseal"), "{err}");
    }
    Node::open(dir.path()).await.stop().await;
}
