//! aws-sdk-s3 code paths over real HTTP against an in-process Tidemark server
//! (`tidemark_server::test_support::spawn`): [`S3Target`] replication (single-part with metadata and
//! tags, multipart with the same ETag, delete markers) and the S3 cold tier
//! ([`RemoteBlobStore`]: freeze, ranged read-through, verify, delete).
//! Version-id preservation over HTTP needs server support for `x-tidemark-version-id`; see
//! `replication.rs::two_server_http_round_trip`.

mod support3b;

use futures::StreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use support3b::*;
use tidemark_blob::remote_s3::{RemoteS3, S3Endpoint, build_client};
use tidemark_blob::tiered::{RemoteBlobStore, TierPolicy, TieredBlobStore};
use tidemark_blob::{BlobStore, FsBlobStore, WriteOpts};
use tidemark_engine::ObjectMeta;
use tidemark_engine::replication::*;
use tokio::io::AsyncWriteExt;

fn endpoint(
    addr: SocketAddr,
    creds: &tidemark_server::test_support::RootCreds,
    b: &str,
) -> S3Endpoint {
    S3Endpoint {
        endpoint: Some(format!("http://{addr}")),
        region: "us-east-1".into(),
        bucket: b.into(),
        prefix: String::new(),
        access_key: creds.access_key.clone(),
        secret_key: creds.secret_key.clone(),
        path_style: true,
    }
}

#[tokio::test]
async fn s3_target_replicates_over_http() {
    let sd = tempfile::tempdir().unwrap();
    let (addr, creds, server) = tidemark_server::test_support::spawn(sd.path()).await;
    let ep = endpoint(addr, &creds, "dst");
    let c = build_client(&ep);
    c.create_bucket().bucket("dst").send().await.unwrap();

    let d = tempfile::tempdir().unwrap();
    let src = open(d.path());
    bucket(&src, "src", true).await;
    src.put_bucket_replication(
        "src",
        "<ReplicationConfiguration><Rule><Status>Enabled</Status>\
         <Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule>\
         </ReplicationConfiguration>",
    )
    .await
    .unwrap();
    let meta = ObjectMeta {
        content_type: Some("text/x-tidemark".into()),
        user_metadata: [("origin".to_string(), "lab".to_string())].into(),
        ..Default::default()
    };
    let tags = [("team".to_string(), "a b&c".to_string())].into();
    put_meta(&src, "src", "dir/one", b"hello http", meta, tags).await;
    let parts = vec![data(5 << 20, 1), data(1234, 2)];
    let mp = put_multipart(&src, "src", "mp", &parts).await;
    put(&src, "src", "gone", b"x").await;
    src.delete_object("src", "gone", None, &root())
        .await
        .unwrap();

    let reg = Arc::new(TargetRegistry::new(&src, [1; 32]));
    let spool = d.path().join("tmp");
    reg.register(
        "arn:aws:s3:::dst",
        Arc::new(S3Target::new(&ep, false, &spool)),
    );
    let st = ReplicationWorker::new(src.clone(), reg)
        .tick()
        .await
        .unwrap();
    assert_eq!(st.delivered, 4, "{st:#?}");
    assert_eq!(st.transient_errors, 0);

    let o = c
        .get_object()
        .bucket("dst")
        .key("dir/one")
        .send()
        .await
        .unwrap();
    assert_eq!(o.content_type(), Some("text/x-tidemark"));
    assert_eq!(
        o.metadata()
            .and_then(|m| m.get("origin"))
            .map(String::as_str),
        Some("lab")
    );
    assert_eq!(
        o.body.collect().await.unwrap().into_bytes().as_ref(),
        b"hello http"
    );
    let t = c
        .get_object_tagging()
        .bucket("dst")
        .key("dir/one")
        .send()
        .await
        .unwrap();
    assert_eq!(t.tag_set()[0].value(), "a b&c");
    let m = c
        .head_object()
        .bucket("dst")
        .key("mp")
        .send()
        .await
        .unwrap();
    assert_eq!(
        m.e_tag().unwrap().trim_matches('"'),
        mp.etag,
        "same part layout"
    );
    assert!(
        c.head_object()
            .bucket("dst")
            .key("gone")
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(&spool).unwrap().count(),
        0,
        "spool cleaned"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn s3_cold_tier_over_http() {
    let sd = tempfile::tempdir().unwrap();
    let (addr, creds, server) = tidemark_server::test_support::spawn(sd.path()).await;
    let mut ep = endpoint(addr, &creds, "cold");
    ep.prefix = "tier/".into();
    build_client(&ep)
        .create_bucket()
        .bucket("cold")
        .send()
        .await
        .unwrap();
    let hd = tempfile::tempdir().unwrap();
    let t = TieredBlobStore::new(
        FsBlobStore::open(hd.path(), false).unwrap(),
        RemoteBlobStore::new(RemoteS3::new(&ep)),
        TierPolicy {
            min_idle: None,
            min_size: Some(1),
            ..Default::default()
        },
    );
    let payload = data(300_000, 7);
    let mut w = t.begin_write(WriteOpts::default()).await.unwrap();
    w.write_all(&payload).await.unwrap();
    let id = w.finish().await.unwrap().blob_id;
    let st = t.tier_tick(std::time::SystemTime::now(), 10).await.unwrap();
    assert_eq!(st.moved, 1);
    assert!(t.is_cold(&id));
    let names = RemoteS3::new(&ep).list("").await.unwrap();
    assert_eq!(names, vec![id.to_hex()]);
    let mut r = t.open(&id, 1000..250_000, None).await.unwrap();
    let mut got = Vec::new();
    while let Some(c) = r.next().await {
        got.extend_from_slice(&c.unwrap());
    }
    assert_eq!(got, &payload[1000..250_000]);
    assert!(t.verify(&id, None).await.unwrap());
    t.delete(&id).await.unwrap();
    assert!(!t.exists(&id).await);
    assert!(RemoteS3::new(&ep).list("").await.unwrap().is_empty());
    server.shutdown().await.unwrap();
}
