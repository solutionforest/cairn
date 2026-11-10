//! Backups of a running server (`POST/GET /_tidemark/v1/backup`, BUILD-PLAN 2.2): the offline
//! `tidemark backup` cannot open a data directory the server holds, so the server makes them.

mod common;
use common::client;
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;
use tidemark_admin::client::{AdminClient, ClientError};
use tidemark_auth::SecretString;
use tidemark_engine::backup::{self, BackupLocation, RestoreOptions};
use tidemark_server::test_support::{spawn_with, test_config};

fn admin(addr: std::net::SocketAddr, ak: &str, sk: &str) -> AdminClient {
    AdminClient::new(
        &format!("http://{addr}"),
        ak,
        SecretString::new(sk),
        None,
        "us-east-1",
    )
    .unwrap()
}

fn api_status(e: ClientError) -> (u16, String) {
    match e {
        ClientError::Api { status, code, .. } => (status, code),
        other => panic!("not an API error: {other}"),
    }
}

async fn wait_done(a: &AdminClient) -> Value {
    for _ in 0..600 {
        let v = a.call("GET", "/backup", &[], None).await.unwrap();
        if v["state"] != "running" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("backup did not finish");
}

async fn metric(addr: std::net::SocketAddr, series: &str) -> f64 {
    let t = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    t.lines()
        .find_map(|l| {
            l.strip_prefix(series)?
                .strip_prefix(' ')?
                .trim()
                .parse()
                .ok()
        })
        .unwrap_or(0.0)
}

fn config(data: &Path, backups: &Path, pass: &Path) -> tidemark_core::Config {
    let mut c = test_config(data);
    c.backup.dir = Some(backups.to_path_buf());
    c.backup.passphrase_file = Some(pass.to_path_buf());
    c
}

#[tokio::test]
async fn backup_of_a_running_server_restores() {
    let t = tempfile::tempdir().unwrap();
    let (data, backups, pass) = (
        t.path().join("data"),
        t.path().join("backups"),
        t.path().join("pass"),
    );
    std::fs::write(&pass, "correct horse battery staple\n").unwrap();
    let (addr, creds, h) = spawn_with(config(&data, &backups, &pass)).await;
    let s3 = client(addr, &creds);
    let a = admin(addr, &creds.access_key, &creds.secret_key);

    let e = a.call("GET", "/backup", &[], None).await.unwrap_err();
    assert_eq!(api_status(e).0, 404, "no job before the first backup");
    assert_eq!(
        metric(addr, "tidemark_backup_last_success_timestamp_seconds").await,
        0.0
    );

    s3.create_bucket().bucket("live").send().await.unwrap();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    for (k, v) in [("a", b"alpha".to_vec()), ("big", big.clone())] {
        s3.put_object()
            .bucket("live")
            .key(k)
            .body(v.into())
            .send()
            .await
            .unwrap();
    }

    let started = a
        .call("POST", "/backup", &[], Some(&json!({"set": "w1"})))
        .await
        .unwrap();
    assert_eq!(started["set"], "w1");
    let first = wait_done(&a).await;
    assert_eq!(first["state"], "succeeded", "{first}");
    assert_eq!(first["report"]["mode"], "Full", "a new set starts full");

    // Writes keep working during and after; the next run only uploads the new blob.
    s3.put_object()
        .bucket("live")
        .key("later")
        .body(b"after the first backup".to_vec().into())
        .send()
        .await
        .unwrap();
    a.call("POST", "/backup", &[], Some(&json!({"set": "w1"})))
        .await
        .unwrap();
    let second = wait_done(&a).await;
    assert_eq!(second["state"], "succeeded", "{second}");
    assert_eq!(second["report"]["mode"], "Incremental");
    assert_eq!(second["report"]["blobs_uploaded"], 1);
    assert!(metric(addr, "tidemark_backup_last_success_timestamp_seconds").await > 0.0);
    assert_eq!(
        metric(addr, r#"tidemark_backup_runs_total{result="succeeded"}"#).await,
        2.0
    );
    h.shutdown().await.unwrap();

    let ids = backup::list_backups(&BackupLocation::Dir(backups.join("w1")))
        .await
        .unwrap();
    assert_eq!(ids.len(), 2);

    // A restart reads the newest manifest back, so it does not look like a missed backup.
    let (addr2, _, h2) = spawn_with(config(&data, &backups, &pass)).await;
    assert!(metric(addr2, "tidemark_backup_last_success_timestamp_seconds").await > 0.0);
    h2.shutdown().await.unwrap();

    let restored = t.path().join("restored");
    backup::restore(
        &BackupLocation::Dir(backups.join("w1")),
        &restored,
        &RestoreOptions {
            manifest: None,
            passphrase: Some(zeroize::Zeroizing::new(
                "correct horse battery staple".into(),
            )),
        },
    )
    .await
    .unwrap();
    let (addr3, creds3, h3) = spawn_with(test_config(&restored)).await;
    let s3 = client(addr3, &creds3);
    for (k, want) in [
        ("a", b"alpha".to_vec()),
        ("big", big),
        ("later", b"after the first backup".to_vec()),
    ] {
        let got = s3
            .get_object()
            .bucket("live")
            .key(k)
            .send()
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .into_bytes();
        assert_eq!(got.as_ref(), want.as_slice(), "{k}");
    }
    h3.shutdown().await.unwrap();
}

#[tokio::test]
async fn backup_requests_are_checked() {
    let t = tempfile::tempdir().unwrap();
    let (data, backups, pass) = (
        t.path().join("data"),
        t.path().join("backups"),
        t.path().join("pass"),
    );
    std::fs::write(&pass, "pw-pw-pw-pw\n").unwrap();

    // Off unless backup.dir is set.
    let (addr, creds, h) = spawn_with(test_config(&t.path().join("off"))).await;
    let a = admin(addr, &creds.access_key, &creds.secret_key);
    let e = a
        .call("POST", "/backup", &[], Some(&json!({"set": "w1"})))
        .await
        .unwrap_err();
    assert_eq!(api_status(e), (409, "BackupNotConfigured".into()));
    h.shutdown().await.unwrap();

    let (addr, creds, h) = spawn_with(config(&data, &backups, &pass)).await;
    let a = admin(addr, &creds.access_key, &creds.secret_key);
    for bad in [
        "",
        "..",
        "../escape",
        "a/b",
        ".hidden",
        "x y",
        &"n".repeat(65),
    ] {
        let e = a
            .call("POST", "/backup", &[], Some(&json!({"set": bad})))
            .await
            .unwrap_err();
        assert_eq!(api_status(e).0, 400, "set {bad:?} was accepted");
    }
    assert!(!t.path().join("escape").exists());

    // A user without tidemark:Backup is refused.
    a.call("POST", "/users", &[], Some(&json!({"name": "bob"})))
        .await
        .unwrap();
    let k = a
        .call("POST", "/users/bob/access-keys", &[], None)
        .await
        .unwrap();
    let bob = admin(
        addr,
        k["access_key_id"].as_str().unwrap(),
        k["secret_access_key"].as_str().unwrap(),
    );
    let e = bob
        .call("POST", "/backup", &[], Some(&json!({"set": "w1"})))
        .await
        .unwrap_err();
    assert_eq!(api_status(e).0, 403);
    assert!(!backups.join("w1").exists());

    // A wrong passphrase for an existing encrypted set fails the job, not the server.
    a.call("POST", "/backup", &[], Some(&json!({"set": "w1"})))
        .await
        .unwrap();
    assert_eq!(wait_done(&a).await["state"], "succeeded");
    std::fs::write(&pass, "a different passphrase\n").unwrap();
    a.call("POST", "/backup", &[], Some(&json!({"set": "w1"})))
        .await
        .unwrap();
    let failed = wait_done(&a).await;
    assert_eq!(failed["state"], "failed", "{failed}");
    assert!(failed["error"].as_str().unwrap().len() > 3);
    assert_eq!(
        metric(addr, r#"tidemark_backup_runs_total{result="failed"}"#).await,
        1.0
    );
    h.shutdown().await.unwrap();
}
