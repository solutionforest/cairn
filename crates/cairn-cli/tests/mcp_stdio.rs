//! `cairn mcp --stdio` through the binary obeys the same IAM as S3 (DESIGN §0 claim 4): an
//! explicit `s3:GetObject` deny applies to `get_object`, and `as_of` needs `cairn:TimeTravel`.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_cairn");
const AK: &str = "CAIRNMCPTESTROOT0000";
const SK: &str = "mcp-test-root-secret-00000000000000000000";

fn s3(addr: &str) -> aws_sdk_s3::Client {
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
    aws_sdk_s3::Client::from_conf(conf)
}

/// Start `serve`, run `f` against it, stop it.
async fn with_server<F, Fut>(cfg: &std::path::Path, f: F)
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut child = Command::new(BIN)
        .args(["serve", "--log-format", "json", "--config"])
        .arg(cfg)
        .env_remove("CAIRN_CONFIG")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let addr = loop {
        let line = lines.next().expect("server exited early").unwrap();
        if line.contains("cairn listening") {
            let v: &str = line.split("\"addr\":\"").nth(1).unwrap();
            break v.split('"').next().unwrap().to_string();
        }
    };
    std::thread::spawn(move || for _ in lines.map_while(Result::ok) {});
    f(addr).await;
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    for _ in 0..150 {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("server did not stop");
}

#[tokio::test(flavor = "multi_thread")]
async fn stdio_mcp_applies_s3_policy_and_time_travel_gate() {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().join("data");
    let o = Command::new(BIN)
        .args(["init", "--data-dir"])
        .arg(&data)
        .args(["--listen", "127.0.0.1:0"])
        .env("CAIRN_ROOT_ACCESS_KEY", AK)
        .env("CAIRN_ROOT_SECRET", SK)
        .output()
        .unwrap();
    assert!(o.status.success());
    let cfg = data.join("cairn.toml");

    let mut agent = (String::new(), String::new());
    with_server(&cfg, |addr| {
        let agent = &mut agent;
        async move {
            let c = s3(&addr);
            c.create_bucket().bucket("docs").send().await.unwrap();
            for k in ["open.txt", "secret/plan.txt"] {
                c.put_object()
                    .bucket("docs")
                    .key(k)
                    .body(aws_sdk_s3::primitives::ByteStream::from_static(b"hello"))
                    .send()
                    .await
                    .unwrap();
            }
            let a = cairn_admin::AdminClient::new(
                &format!("http://{addr}"),
                AK,
                cairn_auth::SecretString::new(SK),
                None,
                "us-east-1",
            )
            .unwrap();
            a.call("POST", "/users", &[], Some(&json!({"name": "agent"})))
                .await
                .unwrap();
            a.call(
                "PUT",
                "/users/agent/policies/p",
                &[],
                Some(&json!({"document": {"Version":"2012-10-17","Statement":[
                    {"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::docs","arn:aws:s3:::docs/*"]},
                    {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::docs/secret/*"}]}})),
            )
            .await
            .unwrap();
            let k = a
                .call("POST", "/users/agent/access-keys", &[], None)
                .await
                .unwrap();
            *agent = (
                k["access_key_id"].as_str().unwrap().to_string(),
                k["secret_access_key"].as_str().unwrap().to_string(),
            );
        }
    })
    .await;

    let mut child = Command::new(BIN)
        .args(["mcp", "--stdio", "--data-dir"])
        .arg(&data)
        .env_remove("CAIRN_CONFIG")
        .env("CAIRN_ACCESS_KEY_ID", &agent.0)
        .env("CAIRN_SECRET_ACCESS_KEY", &agent.1)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut send = |v: Value| {
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    };
    let mut recv = |id: u64| -> Value {
        loop {
            let line = out.next().expect("mcp exited").unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    };
    send(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
    );
    assert!(recv(1)["result"].is_object());
    send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let call = |id: u64, name: &str, args: Value| json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}});

    send(call(
        2,
        "get_object",
        json!({"bucket":"docs","key":"open.txt"}),
    ));
    let r = recv(2)["result"].clone();
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(r["structuredContent"]["content"], "hello", "{r}");

    send(call(
        3,
        "get_object",
        json!({"bucket":"docs","key":"secret/plan.txt"}),
    ));
    let r = recv(3)["result"].clone();
    assert_eq!(r["isError"], true, "{r}");
    assert_eq!(r["structuredContent"]["error"], "AccessDenied", "{r}");

    let now = jiff::Timestamp::now().to_string();
    send(call(
        4,
        "get_object",
        json!({"bucket":"docs","key":"open.txt","as_of":now}),
    ));
    let r = recv(4)["result"].clone();
    assert_eq!(r["isError"], true, "{r}");
    assert_eq!(r["structuredContent"]["error"], "AccessDenied", "{r}");

    drop(send);
    let _ = child.kill();
    let _ = child.wait();
}
