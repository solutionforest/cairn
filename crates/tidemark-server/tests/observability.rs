//! Operability proofs: `/metrics` minimal set (PRODUCTION-READINESS D2) and the audit JSONL for
//! mutating and denied requests, correlated by request id (D3).

mod common;

use aws_sdk_s3::operation::RequestId as _;
use aws_sdk_s3::primitives::ByteStream;
use common::Env;
use std::time::Duration;
use tidemark_server::test_support::RootCreds;

fn sample(text: &str, series: &str) -> Option<f64> {
    text.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        l.strip_prefix(series)?
            .strip_prefix(' ')?
            .trim()
            .parse()
            .ok()
    })
}

#[tokio::test]
async fn metrics_minimal_set() {
    let env = Env::new().await;
    env.bucket("metrics-bucket").await;
    env.put("metrics-bucket", "k", b"hello metrics".to_vec())
        .await;
    assert_eq!(env.get("metrics-bucket", "k").await, b"hello metrics");

    let r = reqwest::get(env.url("/metrics")).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let text = r.text().await.unwrap();

    for (series, min) in [
        (
            r#"tidemark_requests_total{op="CreateBucket",status="200"}"#,
            1.0,
        ),
        (
            r#"tidemark_requests_total{op="PutObject",status="200"}"#,
            1.0,
        ),
        (
            r#"tidemark_requests_total{op="GetObject",status="200"}"#,
            1.0,
        ),
        (
            r#"tidemark_request_duration_seconds_count{op="PutObject"}"#,
            1.0,
        ),
        ("tidemark_bytes_in_total", 13.0),
        ("tidemark_bytes_out_total", 13.0),
    ] {
        let v = sample(&text, series).unwrap_or_else(|| panic!("missing {series}:\n{text}"));
        assert!(v >= min, "{series} = {v}, want >= {min}");
    }
    for gauge in [
        "tidemark_blobs",
        "tidemark_blob_bytes",
        "tidemark_trash_bytes",
        "tidemark_gc_runs_total",
    ] {
        assert!(sample(&text, gauge).is_some(), "missing {gauge}:\n{text}");
    }
    env.stop().await;
}

#[tokio::test]
async fn audit_records_mutating_and_denied_requests() {
    let env = Env::new().await;
    env.bucket("audit-bucket").await;
    let put = env
        .s3
        .put_object()
        .bucket("audit-bucket")
        .key("doc.txt")
        .body(ByteStream::from_static(b"audited"))
        .send()
        .await
        .unwrap();
    let put_rid = put.request_id().expect("x-amz-request-id").to_string();
    env.get("audit-bucket", "doc.txt").await;

    let bad = common::client(
        env.addr,
        &RootCreds {
            access_key: env.creds.access_key.clone(),
            secret_key: "definitely-not-the-secret-0000000000000".into(),
        },
    );
    let denied = bad
        .get_object()
        .bucket("audit-bucket")
        .key("doc.txt")
        .send()
        .await;
    assert_eq!(common::status(denied), 403);

    let path = env.dir.path().join("audit").join("audit.jsonl");
    let mut records = Vec::new();
    for _ in 0..50 {
        if let Ok(text) = std::fs::read_to_string(&path) {
            records = text
                .lines()
                .map(|l| {
                    serde_json::from_str::<serde_json::Value>(l).expect("one JSON object per line")
                })
                .collect();
            if records.iter().any(|r| r["status"] == 403) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(!raw.contains(&env.creds.secret_key), "secret in audit log");

    let put_rec = records
        .iter()
        .find(|r| r["action"] == "PutObject")
        .unwrap_or_else(|| panic!("no PutObject record:\n{raw}"));
    assert_eq!(put_rec["request_id"], put_rid.as_str());
    assert_eq!(put_rec["status"], 200);
    assert_eq!(put_rec["api"], "s3");
    assert_eq!(put_rec["resource"], "arn:aws:s3:::audit-bucket/doc.txt");
    assert!(records.iter().any(|r| r["action"] == "CreateBucket"));
    assert!(
        !records
            .iter()
            .any(|r| r["action"] == "GetObject" && r["status"] == 200),
        "successful reads are not audited by default:\n{raw}"
    );
    assert!(
        records.iter().any(|r| r["status"] == 403),
        "denied request not audited:\n{raw}"
    );
    env.stop().await;
}
