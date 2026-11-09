//! End-to-end through the `tidemark` binary: `init` seals the root credential (never logged),
//! `serve` authenticates with it, and `tidemark trash` / `tidemark pitr` / `tidemark admin` undo
//! deletes online (`--endpoint`) and offline (`--data-dir`, server stopped).

use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_tidemark");

struct Serve {
    child: Child,
    addr: String,
    logs: Arc<Mutex<Vec<String>>>,
}

impl Serve {
    fn start(cfg: &Path) -> Serve {
        let mut child = Command::new(BIN)
            .args(["serve", "--log-format", "json", "--config"])
            .arg(cfg)
            .env("RUST_LOG", "debug")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let logs = Arc::new(Mutex::new(Vec::new()));
        let l2 = logs.clone();
        let err = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(err).lines().map_while(Result::ok) {
                l2.lock().unwrap().push(l);
            }
        });
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let addr = loop {
            let line = lines.next().expect("server exited early").unwrap();
            logs.lock().unwrap().push(line.clone());
            if line.contains("tidemark listening") {
                let v: &str = line.split("\"addr\":\"").nth(1).unwrap();
                break v.split('"').next().unwrap().to_string();
            }
        };
        let l3 = logs.clone();
        std::thread::spawn(move || {
            for l in lines.map_while(Result::ok) {
                l3.lock().unwrap().push(l);
            }
        });
        Serve { child, addr, logs }
    }

    fn stop(mut self) -> Vec<String> {
        let ok = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(ok.success());
        for _ in 0..150 {
            if let Some(s) = self.child.try_wait().unwrap() {
                assert!(s.success(), "{s:?}");
                std::thread::sleep(Duration::from_millis(100));
                return self.logs.lock().unwrap().clone();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("server did not exit after SIGTERM");
    }
}

fn s3(addr: &str, ak: &str, sk: &str) -> Client {
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(format!("http://{addr}"))
        .force_path_style(true)
        .credentials_provider(aws_credential_types::Credentials::new(
            ak, sk, None, None, "test",
        ))
        .http_client(aws_smithy_http_client::Builder::new().build_http())
        .build();
    Client::from_conf(conf)
}

async fn get(c: &Client, b: &str, k: &str) -> Option<Vec<u8>> {
    match c.get_object().bucket(b).key(k).send().await {
        Ok(o) => Some(o.body.collect().await.unwrap().into_bytes().to_vec()),
        Err(_) => None,
    }
}

async fn put(c: &Client, b: &str, k: &str, v: &'static [u8]) {
    c.put_object()
        .bucket(b)
        .key(k)
        .body(ByteStream::from_static(v))
        .send()
        .await
        .unwrap();
}

fn tidemark(args: &[&str], extra: &[String]) -> Output {
    let out = Command::new(BIN)
        .args(args)
        .args(extra)
        .env_remove("TIDEMARK_CONFIG")
        .env_remove("TIDEMARK_ACCESS_KEY")
        .env_remove("TIDEMARK_SECRET_KEY")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "tidemark {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&o.stdout)))
}

async fn instant() -> String {
    tokio::time::sleep(Duration::from_millis(20)).await;
    let t = jiff::Timestamp::now().to_string();
    tokio::time::sleep(Duration::from_millis(20)).await;
    t
}

fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if std::fs::read(&p)
                .unwrap()
                .windows(needle.len())
                .any(|w| w == needle)
            {
                hits.push(p);
            }
        }
    }
    hits
}

#[tokio::test(flavor = "multi_thread")]
async fn init_seals_root_and_cli_undoes_deletes() {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().join("data");
    let out = Command::new(BIN)
        .args(["init", "--data-dir"])
        .arg(&data)
        .args(["--listen", "127.0.0.1:0"])
        .env_remove("TIDEMARK_ROOT_ACCESS_KEY")
        .env_remove("TIDEMARK_ROOT_SECRET")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let field = |p: &str| {
        stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix(p))
            .unwrap()
            .trim()
            .to_string()
    };
    let (ak, sk) = (field("access key: "), field("secret key: "));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains(&sk),
        "init must not log the secret"
    );
    // Sealed: the secret is nowhere in the data directory in plain text.
    assert_eq!(
        files_containing(&data, sk.as_bytes()),
        Vec::<PathBuf>::new()
    );
    let cfg = data.join("tidemark.toml");

    // Serve authenticates with the sealed credential (it is not in the config).
    let srv = Serve::start(&cfg);
    let addr = srv.addr.clone();
    let c = s3(&addr, &ak, &sk);
    c.create_bucket().bucket("photos").send().await.unwrap();
    put(&c, "photos", "cat.jpg", b"v1").await;
    let t_v1 = instant().await;
    put(&c, "photos", "cat.jpg", b"v2").await;
    put(&c, "photos", "dog.jpg", b"dog").await;
    let t_v2 = instant().await;
    for k in ["cat.jpg", "dog.jpg"] {
        c.delete_object()
            .bucket("photos")
            .key(k)
            .send()
            .await
            .unwrap();
    }
    c.delete_bucket().bucket("photos").send().await.unwrap();
    assert!(get(&c, "photos", "cat.jpg").await.is_none());

    let online = vec![
        "--endpoint".to_string(),
        format!("http://{addr}"),
        "--access-key".to_string(),
        ak.clone(),
        "--secret-key".to_string(),
        sk.clone(),
    ];

    // `tidemark admin` is mounted and speaks JSON.
    let who = json(&tidemark(&["admin", "--json", "whoami"], &online));
    assert!(who.to_string().contains("root"), "{who}");

    // Trash lists the deleted bucket; one command brings everything back.
    let ls = json(&tidemark(&["trash", "ls", "--json"], &online));
    assert_eq!(ls["buckets"][0]["name"], "photos", "{ls}");
    let r = json(&tidemark(
        &["trash", "restore", "--bucket", "photos", "--all", "--json"],
        &online,
    ));
    assert!(r["bucket_restored"].is_string(), "{r}");
    assert_eq!(r["failed"], 0, "{r}");
    assert_eq!(get(&c, "photos", "cat.jpg").await.unwrap(), b"v2");
    assert_eq!(get(&c, "photos", "dog.jpg").await.unwrap(), b"dog");

    // PITR to before the overwrite, online.
    let r = json(&tidemark(
        &[
            "pitr", "restore", "--bucket", "photos", "--at", &t_v1, "--json",
        ],
        &online,
    ));
    assert!(r["restored"].as_u64().unwrap() >= 1, "{r}");
    assert_eq!(get(&c, "photos", "cat.jpg").await.unwrap(), b"v1");
    assert!(get(&c, "photos", "dog.jpg").await.is_none());

    // A single deleted key, by name.
    c.delete_object()
        .bucket("photos")
        .key("cat.jpg")
        .send()
        .await
        .unwrap();
    tidemark(
        &["trash", "restore", "--bucket", "photos", "--key", "cat.jpg"],
        &online,
    );
    assert_eq!(get(&c, "photos", "cat.jpg").await.unwrap(), b"v1");

    let logs = srv.stop();
    assert!(!logs.is_empty());
    for l in &logs {
        assert!(!l.contains(&sk), "secret logged: {l}");
    }

    // Offline (server stopped): dry run, then PITR forward again to t_v2.
    let dd = vec!["--data-dir".to_string(), data.display().to_string()];
    let r = json(&tidemark(
        &[
            "pitr",
            "restore",
            "--bucket",
            "photos",
            "--at",
            &t_v2,
            "--dry-run",
            "--json",
        ],
        &dd,
    ));
    assert_eq!(r["dry_run"], true, "{r}");
    assert!(r["restored"].as_u64().unwrap() >= 2, "{r}");
    tidemark(
        &["pitr", "restore", "--bucket", "photos", "--at", &t_v2],
        &dd,
    );
    let diff = json(&tidemark(
        &[
            "pitr", "diff", "--bucket", "photos", "--at", &t_v2, "--json",
        ],
        &dd,
    ));
    assert_eq!(diff["items"].as_array().unwrap().len(), 0, "{diff}");
    let ls = tidemark(&["trash", "ls", "--bucket", "photos"], &dd);
    assert!(String::from_utf8_lossy(&ls.stdout).contains("photos/cat.jpg"));

    let srv = Serve::start(&cfg);
    let c = s3(&srv.addr, &ak, &sk);
    assert_eq!(get(&c, "photos", "cat.jpg").await.unwrap(), b"v2");
    assert_eq!(get(&c, "photos", "dog.jpg").await.unwrap(), b"dog");
    for l in srv.stop() {
        assert!(!l.contains(&sk), "secret logged: {l}");
    }
}
