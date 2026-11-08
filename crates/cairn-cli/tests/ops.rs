//! End-to-end through the `cairn` binary: `fsck [--repair]`, `scrub`, `backup` + `restore`
//! round-trip, `migrate --dry-run`, and startup migration of a v1 database.

use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_cairn");
const AK: &str = "CAIRNOPSTESTROOT0000";
const SK: &str = "ops-test-root-secret-0000000000000000000";

fn cmd() -> Command {
    let mut c = Command::new(BIN);
    c.env_remove("CAIRN_CONFIG")
        .env_remove("CAIRN_ROOT_ACCESS_KEY")
        .env_remove("CAIRN_ROOT_SECRET");
    c
}

fn run(args: &[&str]) -> Output {
    cmd().args(args).output().unwrap()
}

fn ok(args: &[&str]) -> Output {
    let o = run(args);
    assert!(
        o.status.success(),
        "cairn {args:?}:\n{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    o
}

fn json_prefix(o: &Output) -> serde_json::Value {
    let s = String::from_utf8_lossy(&o.stdout);
    let mut de = serde_json::Deserializer::from_str(&s).into_iter::<serde_json::Value>();
    de.next()
        .unwrap_or_else(|| panic!("no JSON in {s}"))
        .unwrap()
}

struct Serve {
    child: Child,
    addr: String,
}

impl Serve {
    fn start(cfg: &Path, env: &[(&str, &str)]) -> Serve {
        let mut c = cmd();
        c.args(["serve", "--log-format", "json", "--config"])
            .arg(cfg)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in env {
            c.env(k, v);
        }
        let mut child = c.spawn().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let addr = loop {
            let line = lines.next().expect("server exited early").unwrap();
            if line.contains("cairn listening") {
                let v: &str = line.split("\"addr\":\"").nth(1).unwrap();
                break v.split('"').next().unwrap().to_string();
            }
        };
        std::thread::spawn(move || for _ in lines.map_while(Result::ok) {});
        Serve { child, addr }
    }

    fn stop(mut self) {
        Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        for _ in 0..150 {
            if let Some(s) = self.child.try_wait().unwrap() {
                assert!(s.success(), "{s:?}");
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("server did not stop");
    }
}

fn s3(addr: &str) -> Client {
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(format!("http://{addr}"))
        .force_path_style(true)
        .credentials_provider(aws_credential_types::Credentials::new(
            AK, SK, None, None, "test",
        ))
        .http_client(aws_smithy_http_client::Builder::new().build_http())
        .build();
    Client::from_conf(conf)
}

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
    out.sort();
    out
}

fn write_config(path: &Path, data: &Path) {
    std::fs::write(
        path,
        format!(
            "[server]\nlisten = \"127.0.0.1:0\"\n\n[storage]\ndata_dir = {:?}\nfsync = false\n",
            data.display().to_string()
        ),
    )
    .unwrap();
}

fn objects() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("a.txt", b"alpha".to_vec()),
        (
            "dir/b.bin",
            (0..200_000u32).map(|i| (i % 253) as u8).collect(),
        ),
        ("c.txt", b"gamma gamma".to_vec()),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn fsck_scrub_backup_restore_migrate_through_the_binary() {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().join("data");
    let o = cmd()
        .args(["init", "--data-dir"])
        .arg(&data)
        .args(["--listen", "127.0.0.1:0"])
        .env("CAIRN_ROOT_ACCESS_KEY", AK)
        .env("CAIRN_ROOT_SECRET", SK)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let cfg = data.join("cairn.toml");
    let dd = data.to_str().unwrap();

    let srv = Serve::start(&cfg, &[]);
    let c = s3(&srv.addr);
    c.create_bucket().bucket("ops").send().await.unwrap();
    for (k, v) in objects() {
        c.put_object()
            .bucket("ops")
            .key(k)
            .body(ByteStream::from(v))
            .send()
            .await
            .unwrap();
    }
    srv.stop();

    // Clean store: fsck exit 0.
    let o = ok(&["fsck", "--data-dir", dd, "--verify", "full", "--json"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains('{'));

    // Encrypted backup including keys, then list it.
    let set = d.path().join("backup");
    let pf = d.path().join("pass");
    std::fs::write(&pf, "correct horse battery staple\n").unwrap();
    let (set_s, pf_s) = (set.to_str().unwrap(), pf.to_str().unwrap());
    let rep = json_prefix(&ok(&[
        "backup",
        "--data-dir",
        dd,
        "--to",
        set_s,
        "--passphrase-file",
        pf_s,
        "--include-keys",
    ]));
    let id = rep["id"].as_str().unwrap().to_string();
    let ls = ok(&["backup", "ls", "--from", set_s]);
    assert!(String::from_utf8_lossy(&ls.stdout).contains(&id));

    // Corrupt one blob: scrub and fsck both report it (exit 1); repair runs.
    let victim = blob_paths(&data)
        .into_iter()
        .max_by_key(|p| std::fs::metadata(p).unwrap().len())
        .unwrap();
    let mut b = std::fs::read(&victim).unwrap();
    b[1000] ^= 0x55;
    std::fs::write(&victim, b).unwrap();
    let o = run(&["scrub", "--data-dir", dd, "--rate", "0"]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    let rep = json_prefix(&o);
    assert_eq!(rep["corrupt"].as_array().unwrap().len(), 1, "{rep}");
    let o = run(&["fsck", "--data-dir", dd, "--verify", "full", "--json"]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    let o = run(&[
        "fsck",
        "--data-dir",
        dd,
        "--verify",
        "full",
        "--repair",
        "--json",
    ]);
    assert!(matches!(o.status.code(), Some(0 | 1)), "{o:?}");

    // The damaged object is refused loudly by the server; the others still read.
    let srv = Serve::start(&cfg, &[]);
    let c = s3(&srv.addr);
    let e = c.get_object().bucket("ops").key("dir/b.bin").send().await;
    let failed = match e {
        Err(_) => true,
        Ok(o) => o.body.collect().await.is_err(),
    };
    assert!(failed, "damaged object was served");
    let a = c
        .get_object()
        .bucket("ops")
        .key("a.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        a.body.collect().await.unwrap().into_bytes().as_ref(),
        b"alpha"
    );
    srv.stop();

    // Restore the backup into a new directory; every object comes back byte-identical.
    let data2 = d.path().join("restored");
    let o = ok(&[
        "restore",
        "--from",
        set_s,
        "--data-dir",
        data2.to_str().unwrap(),
        "--passphrase-file",
        pf_s,
    ]);
    assert_eq!(json_prefix(&o)["id"], id.as_str());
    let o = ok(&[
        "migrate",
        "--dry-run",
        "--data-dir",
        data2.to_str().unwrap(),
    ]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("no migrations needed"), "{out}");
    assert!(out.contains("dry run: nothing was written"), "{out}");
    let cfg2 = d.path().join("restored.toml");
    write_config(&cfg2, &data2);
    let srv = Serve::start(&cfg2, &[]);
    let c = s3(&srv.addr);
    for (k, v) in objects() {
        let got = c.get_object().bucket("ops").key(k).send().await.unwrap();
        assert_eq!(
            got.body.collect().await.unwrap().into_bytes().to_vec(),
            v,
            "{k}"
        );
    }
    srv.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_database_dry_run_writes_nothing_and_serve_migrates_it() {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().join("data");
    std::fs::create_dir_all(data.join("meta")).unwrap();
    let db = data.join("meta").join("cairn.redb");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../cairn-meta/tests/fixtures/meta-v1.redb"
        ),
        &db,
    )
    .unwrap();
    let dd = data.to_str().unwrap();
    let o = ok(&["migrate", "--dry-run", "--data-dir", dd]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("schema version: 1 -> "), "{out}");
    assert!(out.contains("dry run: nothing was written"), "{out}");

    // `serve` runs migrations at startup and comes up on the old database.
    let cfg = d.path().join("cairn.toml");
    write_config(&cfg, &data);
    let srv = Serve::start(
        &cfg,
        &[("CAIRN_ROOT_ACCESS_KEY", AK), ("CAIRN_ROOT_SECRET", SK)],
    );
    let c = s3(&srv.addr);
    c.list_buckets().send().await.unwrap();
    srv.stop();
    let o = ok(&["migrate", "--dry-run", "--data-dir", dd]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("no migrations needed"));
}
