//! End-to-end: `cairn init`, `cairn config check`, `cairn serve`, `/healthz`, SIGTERM shutdown.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

fn http_get(addr: &str, path: &str) -> String {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn init_check_serve_sigterm() {
    let bin = env!("CARGO_BIN_EXE_cairn");
    let d = tempfile::tempdir().unwrap();
    let data = d.path().join("data");
    let out = Command::new(bin)
        .args(["init", "--data-dir"])
        .arg(&data)
        .args(["--listen", "127.0.0.1:0"])
        .env_remove("CAIRN_ROOT_ACCESS_KEY")
        .env_remove("CAIRN_ROOT_SECRET")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("access key: CAIRN"), "{stdout}");
    let cfg = data.join("cairn.toml");

    let check = Command::new(bin)
        .args(["config", "check", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(check.status.success());
    let shown = String::from_utf8_lossy(&check.stdout);
    assert!(shown.contains("********"));
    let secret = std::fs::read_to_string(&cfg)
        .unwrap()
        .lines()
        .find(|l| l.starts_with("root_secret_key"))
        .unwrap()
        .to_string();
    assert!(!shown.contains(&secret), "secret must be masked");

    let mut child = Command::new(bin)
        .args(["serve", "--log-format", "json", "--config"])
        .arg(&cfg)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let addr = loop {
        let line = lines.next().expect("server exited early").unwrap();
        assert!(
            !line.contains(&secret[secret.find('"').unwrap()..]),
            "secret logged"
        );
        if line.contains("cairn listening") {
            let v: &str = line.split("\"addr\":\"").nth(1).unwrap();
            break v.split('"').next().unwrap().to_string();
        }
    };
    let resp = http_get(&addr, "/healthz");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(http_get(&addr, "/readyz").starts_with("HTTP/1.1 200"));
    assert!(data.join("meta").join("RUNNING").exists());

    let kill = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(kill.success());
    let mut waited = 0;
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        std::thread::sleep(Duration::from_millis(100));
        waited += 1;
        assert!(waited < 100, "server did not exit after SIGTERM");
    };
    assert!(status.success(), "{status:?}");
    for l in lines.map_while(Result::ok) {
        assert!(
            !l.contains(&secret[secret.find('"').unwrap()..]),
            "secret logged"
        );
    }
    assert!(
        !data.join("meta").join("RUNNING").exists(),
        "clean shutdown removes the RUNNING marker"
    );
}

#[test]
fn example_config_parses() {
    let c =
        cairn_core::Config::from_toml(include_str!("../../../docs/examples/cairn.toml")).unwrap();
    assert_eq!(
        c,
        cairn_core::Config {
            storage: cairn_core::config::StorageConfig {
                data_dir: "/var/lib/cairn".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    );
}
