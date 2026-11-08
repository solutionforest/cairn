//! Lane 1: a GET of a version whose blob is damaged fails loudly (C3), and the scrubber that
//! `serve` spawns with `storage.scrub = true` finds the damage on its own (C4).

mod common;
use common::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn blob_paths(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.join("blobs")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn flip_byte(p: &Path, at: usize) {
    let mut b = std::fs::read(p).unwrap();
    b[at] ^= 0xff;
    std::fs::write(p, b).unwrap();
}

async fn raw_get(env_url: String) -> reqwest::Response {
    // Presign-free path: the bucket is made public for this read, so plain HTTP shows exactly
    // what a client receives (status, headers, body framing).
    reqwest::get(env_url).await.unwrap()
}

async fn make_public(env: &Env, bucket: &str) {
    let bp = serde_json::json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":format!("arn:aws:s3:::{bucket}/*")}]});
    env.s3
        .put_bucket_policy()
        .bucket(bucket)
        .policy(bp.to_string())
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn get_of_corrupt_blob_never_completes() {
    let env = Env::new().await;
    env.bucket("dmg").await;
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    env.put("dmg", "big", data.clone()).await;
    env.put("dmg", "small", "tiny body").await;
    make_public(&env, "dmg").await;
    assert_eq!(env.get("dmg", "big").await, data);
    for p in blob_paths(env.dir.path()) {
        let len = std::fs::metadata(&p).unwrap().len() as usize;
        flip_byte(&p, len / 2);
    }
    // The SDK sees an error, not silently wrong bytes.
    for key in ["big", "small"] {
        let r = env.s3.get_object().bucket("dmg").key(key).send().await;
        let failed = match r {
            Err(_) => true,
            Ok(o) => o.body.collect().await.is_err(),
        };
        assert!(
            failed,
            "{key}: damaged bytes were served as a complete response"
        );
    }
    // At the HTTP level the body is cut short (content-length never satisfied).
    let r = raw_get(env.url("/dmg/big")).await;
    assert!(
        r.bytes().await.is_err(),
        "truncated body must surface as an error"
    );
    env.stop().await;
}

#[tokio::test]
async fn get_of_missing_blob_is_500_damaged() {
    let env = Env::new().await;
    env.bucket("dmg").await;
    env.put("dmg", "k", "will vanish").await;
    make_public(&env, "dmg").await;
    for p in blob_paths(env.dir.path()) {
        std::fs::remove_file(p).unwrap();
    }
    let r = raw_get(env.url("/dmg/k")).await;
    assert_eq!(r.status().as_u16(), 500);
    assert_eq!(
        r.headers()
            .get("x-cairn-damaged")
            .map(|v| v.to_str().unwrap()),
        Some("true")
    );
    assert!(r.text().await.unwrap().contains("damaged"));
    env.stop().await;
}

#[tokio::test]
async fn serve_spawns_scrub_which_marks_damage() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (addr, creds, h) = cairn_server::test_support::spawn(dir.path()).await;
        let c = client(addr, &creds);
        c.create_bucket().bucket("dmg").send().await.unwrap();
        c.put_object()
            .bucket("dmg")
            .key("k")
            .body(aws_sdk_s3::primitives::ByteStream::from_static(
                b"scrub me please",
            ))
            .send()
            .await
            .unwrap();
        h.shutdown().await.unwrap();
    }
    for p in blob_paths(dir.path()) {
        flip_byte(&p, 0);
    }
    let mut cfg = cairn_server::test_support::test_config(dir.path());
    cfg.storage.scrub = true;
    cfg.storage.scrub_bytes_per_sec = 0;
    let (addr, creds, h) = cairn_server::test_support::spawn_with(cfg).await;
    let c = client(addr, &creds);
    let mut damaged = false;
    for _ in 0..100 {
        if let Err(e) = c.get_object().bucket("dmg").key("k").send().await
            && e.raw_response()
                .is_some_and(|r| r.headers().get("x-cairn-damaged") == Some("true"))
        {
            damaged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(damaged, "the background scrubber did not record the damage");
    h.shutdown().await.unwrap();
}
