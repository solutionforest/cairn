//! Operability proofs through the binary: `cairn config check` shows the effective config with
//! `CAIRN_*` overrides applied and secrets masked (PRODUCTION-READINESS D5); `--log-format json`
//! emits one JSON object per line carrying the request id returned as `x-amz-request-id` (D3).

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const SECRET: &str = "obs-test-root-secret-value-9f8e7d6c5b4a";

fn init(data: &std::path::Path) -> std::path::PathBuf {
    let out = Command::new(env!("CARGO_BIN_EXE_cairn"))
        .args(["init", "--data-dir"])
        .arg(data)
        .args(["--listen", "127.0.0.1:0"])
        .env("CAIRN_ROOT_ACCESS_KEY", "OBSTESTROOT")
        .env("CAIRN_ROOT_SECRET", SECRET)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    data.join("cairn.toml")
}

#[test]
fn config_check_applies_env_overrides_and_masks_secrets() {
    let d = tempfile::tempdir().unwrap();
    let cfg = init(&d.path().join("data"));
    let out = Command::new(env!("CARGO_BIN_EXE_cairn"))
        .args(["config", "check", "--config"])
        .arg(&cfg)
        .env("CAIRN_SERVER_REGION", "eu-test-1")
        .env("CAIRN_LOG_LEVEL", "debug")
        .env("CAIRN_ROOT_ACCESS_KEY", "OBSTESTROOT")
        .env("CAIRN_ROOT_SECRET", SECRET)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("region = \"eu-test-1\""), "{stdout}");
    assert!(stdout.contains("level = \"debug\""), "{stdout}");
    assert!(
        stdout.contains("root_secret_key = \"********\""),
        "{stdout}"
    );
    assert!(
        !stdout.contains(SECRET) && !stderr.contains(SECRET),
        "secret printed"
    );

    let schema = Command::new(env!("CARGO_BIN_EXE_cairn"))
        .args(["config", "schema"])
        .output()
        .unwrap();
    let schema = String::from_utf8_lossy(&schema.stdout);
    assert!(schema.contains("CAIRN_<SECTION>_<KEY>"), "{schema}");
    let rows: Vec<&str> = schema.lines().filter(|l| l.starts_with("| `")).collect();
    assert!(rows.len() > 20, "{schema}");
    for row in rows {
        let default = row.split('|').nth(2).unwrap_or("").trim();
        assert!(!default.is_empty(), "key without a default: {row}");
    }
}

#[test]
fn json_logs_carry_the_request_id() {
    let d = tempfile::tempdir().unwrap();
    let cfg = init(&d.path().join("data"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_cairn"))
        .args(["--log-format", "json", "serve", "--config"])
        .arg(&cfg)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for l in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    let next = |rx: &mpsc::Receiver<String>| {
        rx.recv_timeout(Duration::from_secs(30))
            .expect("server log line")
    };
    let addr = loop {
        let line = next(&rx);
        let v: serde_json::Value = serde_json::from_str(&line).expect("JSON log line");
        if v["fields"]["message"] == "cairn listening" {
            break v["fields"]["addr"].as_str().unwrap().to_string();
        }
    };

    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let rid = resp
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("x-amz-request-id")
                .then(|| v.trim().to_string())
        })
        .unwrap_or_else(|| panic!("no x-amz-request-id:\n{resp}"));

    let found = loop {
        let line = next(&rx);
        assert!(!line.contains(SECRET), "secret logged");
        let v: serde_json::Value = serde_json::from_str(&line).expect("JSON log line");
        if v["span"]["id"] == rid.as_str() {
            break v;
        }
    };
    assert_eq!(found["span"]["path"], "/healthz");

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.wait();
}
