//! `[scan]`: uploads are streamed to a scanner before they are stored. Infected PUTs and
//! multipart uploads land in the quarantine bucket as `<bucket>/<key>` and the client gets
//! `400 VirusDetected`; copies of infected objects are refused; a dead scanner rejects (or, with
//! `on_error = "allow"`, stores) uploads; objects over `max_size` follow `on_oversize`. Both
//! scanner protocols (clamd INSTREAM, HTTP endpoint) are exercised against in-process fakes.

mod common;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use common::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tidemark_core::config::ScanFailMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What the fake scanners flag. The real EICAR string is kept out of the repository so local
/// antivirus does not quarantine this file.
const MARKER: &[u8] = b"TIDEMARK-TEST-MALWARE-MARKER";
const SIGNATURE: &str = "Tidemark-Test-Signature";

fn infected(len: usize) -> Vec<u8> {
    let mut v = vec![b'a'; len];
    let at = len / 2;
    v[at..at + MARKER.len()].copy_from_slice(MARKER);
    v
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A clamd that speaks INSTREAM and flags [`MARKER`]. Returns its address and a call counter.
async fn fake_clamd() -> (String, Arc<AtomicUsize>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut cmd = [0u8; 10];
                s.read_exact(&mut cmd).await.unwrap();
                assert_eq!(&cmd, b"zINSTREAM\0");
                let mut data = Vec::new();
                loop {
                    let n = s.read_u32().await.unwrap() as usize;
                    if n == 0 {
                        break;
                    }
                    assert!(n > 0);
                    let mut buf = vec![0u8; n];
                    s.read_exact(&mut buf).await.unwrap();
                    data.extend_from_slice(&buf);
                }
                let reply = if contains(&data, MARKER) {
                    format!("stream: {SIGNATURE} FOUND\0")
                } else {
                    "stream: OK\0".to_string()
                };
                s.write_all(reply.as_bytes()).await.unwrap();
            });
        }
    });
    (addr, calls)
}

/// An HTTP scan endpoint with the documented contract; records the key header it was sent.
async fn fake_http() -> (String, Arc<std::sync::Mutex<Vec<(String, String, usize)>>>) {
    use axum::{Router, body::Bytes, http::HeaderMap, routing::post};
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let app = Router::new().route(
        "/scan",
        post(move |h: HeaderMap, body: Bytes| {
            let seen = s2.clone();
            async move {
                let get = |n: &str| h.get(n).unwrap().to_str().unwrap().to_string();
                seen.lock().unwrap().push((
                    get("x-tidemark-bucket"),
                    get("x-tidemark-key"),
                    body.len(),
                ));
                if contains(&body, MARKER) {
                    format!(r#"{{"infected":true,"signature":"{SIGNATURE}"}}"#)
                } else {
                    r#"{"infected":false}"#.to_string()
                }
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (format!("http://{addr}/scan"), seen)
}

fn config(dir: &std::path::Path, endpoint: &str) -> tidemark_core::Config {
    let mut c = tidemark_server::test_support::test_config(dir);
    c.scan.endpoint = Some(endpoint.into());
    c
}

async fn put(node: &Node, bucket: &str, key: &str, data: Vec<u8>) -> Result<(), String> {
    node.s3
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(data))
        .send()
        .await
        .map(|_| ())
        .map_err(|e| {
            let status = e.raw_response().map(|r| r.status().as_u16()).unwrap_or(0);
            format!("{status} {}", code::<_, ()>(Err(e)))
        })
}

async fn exists(node: &Node, bucket: &str, key: &str) -> bool {
    node.s3
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .is_ok()
}

#[tokio::test]
async fn clamd_quarantines_infected_put_and_multipart() {
    let dir = tempfile::tempdir().unwrap();
    let (clamd, calls) = fake_clamd().await;
    let node = Node::start(config(dir.path(), &format!("clamd://{clamd}"))).await;
    let s3 = &node.s3;
    node.bucket("data").await;

    // The quarantine bucket exists from startup, versioned.
    let v = s3
        .get_bucket_versioning()
        .bucket("quarantine")
        .send()
        .await
        .unwrap();
    assert_eq!(v.status().map(|s| s.as_str()), Some("Enabled"));

    // Clean upload: stored, scanned once.
    put(&node, "data", "clean.txt", b"hello".to_vec())
        .await
        .unwrap();
    assert_eq!(node.get("data", "clean.txt").await, b"hello");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Infected PUT: refused, absent from the target, present in quarantine with the verdict.
    let body = infected(300_000);
    assert_eq!(
        put(&node, "data", "dir/evil.bin", body.clone())
            .await
            .unwrap_err(),
        "400 VirusDetected"
    );
    assert!(!exists(&node, "data", "dir/evil.bin").await);
    let q = s3
        .head_object()
        .bucket("quarantine")
        .key("data/dir/evil.bin")
        .send()
        .await
        .unwrap();
    let m = q.metadata().unwrap();
    assert_eq!(m["tidemark-scan-signature"], SIGNATURE);
    assert_eq!(m["tidemark-source-bucket"], "data");
    assert_eq!(m["tidemark-source-key"], "dir/evil.bin");
    assert_eq!(node.get("quarantine", "data/dir/evil.bin").await, body);

    // Infected multipart: the marker sits in the last part, so only the assembled object shows
    // it. Complete fails, the upload is gone, the object is in quarantine.
    let up = s3
        .create_multipart_upload()
        .bucket("data")
        .key("mp.bin")
        .send()
        .await
        .unwrap();
    let id = up.upload_id().unwrap();
    let mut done = Vec::new();
    let parts = [vec![b'b'; 5 * 1024 * 1024], infected(100_000)];
    for (i, p) in parts.iter().enumerate() {
        let r = s3
            .upload_part()
            .bucket("data")
            .key("mp.bin")
            .upload_id(id)
            .part_number(i as i32 + 1)
            .body(ByteStream::from(p.clone()))
            .send()
            .await
            .unwrap();
        done.push(
            CompletedPart::builder()
                .part_number(i as i32 + 1)
                .e_tag(r.e_tag().unwrap())
                .build(),
        );
    }
    let r = s3
        .complete_multipart_upload()
        .bucket("data")
        .key("mp.bin")
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(done))
                .build(),
        )
        .send()
        .await;
    assert_eq!(code(r), "VirusDetected");
    assert!(!exists(&node, "data", "mp.bin").await);
    let ups = s3
        .list_multipart_uploads()
        .bucket("data")
        .send()
        .await
        .unwrap();
    assert!(ups.uploads().is_empty());
    let got = node.get("quarantine", "data/mp.bin").await;
    assert_eq!(got.len(), parts[0].len() + parts[1].len());

    // Copying out of quarantine into a data bucket is refused; nothing is written.
    let r = s3
        .copy_object()
        .bucket("data")
        .key("smuggled.bin")
        .copy_source("quarantine/data/dir/evil.bin")
        .send()
        .await;
    assert_eq!(code(r), "VirusDetected");
    assert!(!exists(&node, "data", "smuggled.bin").await);

    // Writes into the quarantine bucket itself are not scanned (no extra clamd call).
    let before = calls.load(Ordering::SeqCst);
    put(&node, "quarantine", "note.txt", b"x".to_vec())
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), before);

    // fsck agrees the data dir is consistent (no leaked blobs from the redirected commits).
    let rep = node
        .engine()
        .fsck(tidemark_server::tidemark_engine::fsck::FsckOptions {
            orphan_min_age: std::time::Duration::ZERO,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(rep.is_clean(), "{rep:?}");

    // Restart: the quarantine bucket already exists, startup still succeeds.
    node.stop().await;
    let node = Node::start(config(dir.path(), &format!("clamd://{clamd}"))).await;
    assert_eq!(node.get("data", "clean.txt").await, b"hello");
    node.stop().await;
}

#[tokio::test]
async fn http_endpoint_contract() {
    let dir = tempfile::tempdir().unwrap();
    let (ep, seen) = fake_http().await;
    let node = Node::start(config(dir.path(), &ep)).await;
    node.bucket("data").await;

    put(&node, "data", "a b/ü.txt", b"hello".to_vec())
        .await
        .unwrap();
    assert_eq!(
        put(&node, "data", "evil", infected(1000))
            .await
            .unwrap_err(),
        "400 VirusDetected"
    );
    assert_eq!(node.get("quarantine", "data/evil").await, infected(1000));
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            ("data".into(), "a%20b/%C3%BC.txt".into(), 5),
            ("data".into(), "evil".into(), 1000),
        ]
    );
    node.stop().await;
}

#[tokio::test]
async fn scanner_down_and_oversize_policies() {
    // Nothing listens on this port.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let dir = tempfile::tempdir().unwrap();

    // Default: fail closed with 503, nothing stored.
    let node = Node::start(config(dir.path(), &format!("clamd://{dead}"))).await;
    node.bucket("data").await;
    assert_eq!(
        put(&node, "data", "k", b"x".to_vec()).await.unwrap_err(),
        "503 ServiceUnavailable"
    );
    assert!(!exists(&node, "data", "k").await);
    node.stop().await;

    // on_error = allow: stored unscanned.
    let mut c = config(dir.path(), &format!("clamd://{dead}"));
    c.scan.on_error = ScanFailMode::Allow;
    let node = Node::start(c).await;
    put(&node, "data", "k", b"x".to_vec()).await.unwrap();
    assert_eq!(node.get("data", "k").await, b"x");
    node.stop().await;

    // Over max_size: allow (default) stores without calling the scanner; reject refuses.
    let (clamd, calls) = fake_clamd().await;
    let mut c = config(dir.path(), &format!("clamd://{clamd}"));
    c.scan.max_size = 1000;
    let node = Node::start(c.clone()).await;
    put(&node, "data", "big", infected(2000)).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    node.stop().await;
    c.scan.on_oversize = ScanFailMode::Reject;
    let node = Node::start(c).await;
    assert_eq!(
        put(&node, "data", "big2", infected(2000))
            .await
            .unwrap_err(),
        "400 EntityTooLarge"
    );
    assert!(!exists(&node, "data", "big2").await);
    node.stop().await;
}

#[test]
fn bad_scan_config_is_rejected() {
    let mut c = tidemark_core::Config::default();
    c.scan.endpoint = Some("tcp://x".into());
    c.scan.quarantine_bucket = "Q".into();
    let p = c.validate().join("\n");
    assert!(p.contains("scan.endpoint"), "{p}");
    assert!(p.contains("scan.quarantine_bucket"), "{p}");
}
