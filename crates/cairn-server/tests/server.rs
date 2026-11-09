//! Server lifecycle: restart preserves data, /healthz and /readyz, graceful shutdown.

mod common;
use common::*;

#[tokio::test]
async fn restart_preserves_data() {
    let mut env = Env::new().await;
    env.bucket("persist").await;
    env.put("persist", "a/b", "durable bytes").await;
    let up = env
        .s3
        .create_multipart_upload()
        .bucket("persist")
        .key("mpu")
        .send()
        .await
        .unwrap();
    env.restart().await;
    assert_eq!(env.get("persist", "a/b").await, b"durable bytes");
    let lu = env
        .s3
        .list_multipart_uploads()
        .bucket("persist")
        .send()
        .await
        .unwrap();
    assert_eq!(lu.uploads()[0].upload_id(), up.upload_id());
    let names: Vec<_> = env
        .s3
        .list_buckets()
        .send()
        .await
        .unwrap()
        .buckets()
        .iter()
        .map(|b| b.name().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["persist"]);
    // A clean shutdown leaves no RUNNING marker behind.
    env.handle.take().unwrap().shutdown().await.unwrap();
    assert!(!env.dir.path().join("meta").join("RUNNING").exists());
}

#[tokio::test]
async fn health_and_readiness() {
    let env = Env::new().await;
    let r = reqwest::get(env.url("/healthz")).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert!(r.headers().contains_key("x-amz-request-id"));
    let r = reqwest::get(env.url("/readyz")).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(r.text().await.unwrap().trim(), "ready");
    // Readiness fails when the data directory is not writable.
    let tmp = env.dir.path().join("tmp");
    std::fs::remove_dir_all(&tmp).unwrap();
    std::fs::write(&tmp, b"not a directory").unwrap();
    let r = reqwest::get(env.url("/readyz")).await.unwrap();
    assert_eq!(r.status().as_u16(), 503);
    std::fs::remove_file(&tmp).unwrap();
    std::fs::create_dir(&tmp).unwrap();
    let r = reqwest::get(env.url("/readyz")).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    env.stop().await;
}

#[tokio::test]
async fn graceful_shutdown_drains_in_flight_requests() {
    let mut env = Env::new().await;
    env.bucket("grace").await;
    let big: Vec<u8> = vec![42u8; 8 * 1024 * 1024];
    let s3 = env.s3.clone();
    let upload = tokio::spawn(async move {
        s3.put_object()
            .bucket("grace")
            .key("big")
            .body(big.into())
            .send()
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    env.handle.take().unwrap().shutdown().await.unwrap();
    let r = upload.await.unwrap();
    // Either the upload completed during the drain, or it never started before the listener
    // closed; it must never be half-committed.
    let completed = r.is_ok();
    let (addr, creds, handle) = cairn_server::test_support::spawn(env.dir.path()).await;
    let s3 = client(addr, &creds);
    let h = s3.head_object().bucket("grace").key("big").send().await;
    if completed {
        assert_eq!(h.unwrap().content_length(), Some(8 * 1024 * 1024));
    } else if let Ok(h) = h {
        assert_eq!(h.content_length(), Some(8 * 1024 * 1024));
    }
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_triggered_before_run_still_stops_and_failed_bind_releases_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let server = cairn_server::Server::bind(cairn_server::test_support::test_config(dir.path()))
        .await
        .unwrap();
    server.shutdown_trigger().trigger();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        server.run_until(std::future::pending::<()>()),
    )
    .await
    .expect("a shutdown requested before run_until was lost")
    .unwrap();

    let bad = cairn_server::test_support::test_config(dir.path())
        .with_env([("CAIRN_STORAGE_MASTER_KEY".to_string(), "11".repeat(32))])
        .unwrap();
    let first = cairn_server::Server::bind(bad.clone()).await;
    assert!(first.is_err(), "bound with a wrong master key");
    let again = cairn_server::Server::bind(bad).await.err().unwrap();
    assert!(
        !format!("{again:#}").contains("already open"),
        "a failed bind kept the metadata store locked: {again:#}"
    );
}

/// Bucket CORS is shelved, so S3 preflights are answered as S3 does for a bucket without a
/// CORS configuration: 400 without Origin / Access-Control-Request-Method, else 403.
#[tokio::test]
async fn s3_preflight_without_cors_configuration() {
    let env = Env::new().await;
    env.bucket("preflight").await;
    let c = reqwest::Client::new();
    let url = env.url("/preflight/key");
    let r = c
        .request(reqwest::Method::OPTIONS, &url)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = c
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", "https://example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = c
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", "https://example.com")
        .header("access-control-request-method", "GET")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert!(
        r.text()
            .await
            .unwrap()
            .contains("<Code>AccessForbidden</Code>")
    );
}
