//! HTTP sinks against a local fake receiver on 127.0.0.1:0, one test per auth mode, plus retry
//! classification through the worker and the SSE stream.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tidemark_core::BucketId;
use tidemark_events::sigv4;
use tidemark_events::sink::{Delivery, Sink, SinkError, hmac_signature};
use tidemark_events::{
    DeliveryWorker, Event, EventName, EventsError, NotificationConfiguration, Outbox, OutboxRecord,
    SinkConfig, SseBroadcast, Target, WebhookSink, WorkerOptions, notification, sse_router,
};
use tidemark_meta::{MetaStore, RedbMetaStore};
use tokio::sync::watch;

#[derive(Clone, Debug)]
struct Received {
    path: String,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Clone, Default)]
struct Fake {
    got: Arc<Mutex<Vec<Received>>>,
    statuses: Arc<Mutex<VecDeque<u16>>>,
}

async fn record(State(f): State<Fake>, uri: Uri, headers: HeaderMap, body: Bytes) -> StatusCode {
    f.got.lock().unwrap().push(Received {
        path: uri.path().to_string(),
        headers,
        body,
    });
    let code = f.statuses.lock().unwrap().pop_front().unwrap_or(200);
    StatusCode::from_u16(code).unwrap()
}

async fn fake_server(statuses: &[u16]) -> (String, Fake) {
    let f = Fake::default();
    f.statuses.lock().unwrap().extend(statuses);
    let app = axum::Router::new()
        .fallback(axum::routing::post(record))
        .with_state(f.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), f)
}

fn sink(toml_src: &str) -> WebhookSink {
    let cfg: SinkConfig = toml::from_str(toml_src).unwrap();
    WebhookSink::from_config(cfg).unwrap()
}

fn delivery(seq: u64, key: &str, sink_id: &str) -> Delivery {
    Delivery {
        seq,
        record: OutboxRecord {
            event: Event::new(EventName::ObjectCreatedPut, "bkt", key),
            targets: vec![Target {
                arn: format!("arn:tidemark:sink::{sink_id}"),
                configuration_id: "cfg".into(),
            }],
            only_sink: None,
        },
        configuration_id: "cfg".into(),
    }
}

fn header<'a>(r: &'a Received, name: &str) -> &'a str {
    r.headers
        .get(name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .to_str()
        .unwrap()
}

#[tokio::test]
async fn hmac_webhook() {
    let (url, fake) = fake_server(&[]).await;
    let s = sink(&format!(
        r#"id = "hook"
        url = "{url}/in"
        auth = {{ mode = "hmac", secret = "s3kr1t-hmac" }}"#
    ));
    assert_eq!(s.batch_size(), 10);
    let batch = [delivery(1, "a.jpg", "hook"), delivery(2, "b c.jpg", "hook")];
    s.deliver(&batch).await.unwrap();
    let got = fake.got.lock().unwrap()[0].clone();
    assert_eq!(got.path, "/in");
    assert_eq!(header(&got, "content-type"), "application/json");
    assert_eq!(header(&got, "x-tidemark-sink"), "hook");
    assert_eq!(
        header(&got, "x-tidemark-idempotency-key"),
        "0000000000000001,0000000000000002"
    );
    assert!(header(&got, "user-agent").starts_with("tidemark/"));
    let ts = header(&got, "x-tidemark-timestamp");
    let age = jiff::Timestamp::now().as_second() - ts.parse::<i64>().unwrap();
    assert!((0..60).contains(&age));
    assert_eq!(
        header(&got, "x-tidemark-signature"),
        format!("v1={}", hmac_signature("s3kr1t-hmac", ts, &got.body))
    );
    assert_ne!(
        header(&got, "x-tidemark-signature"),
        format!("v1={}", hmac_signature("wrong", ts, &got.body))
    );
    let v: serde_json::Value = serde_json::from_slice(&got.body).unwrap();
    let recs = v["Records"].as_array().unwrap();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[1]["s3"]["object"]["key"], "b+c.jpg");
    assert_eq!(recs[0]["s3"]["configurationId"], "cfg");
    assert!(got.headers.get("authorization").is_none());
}

#[tokio::test]
async fn bearer_function_sink() {
    let (url, fake) = fake_server(&[]).await;
    let s = sink(&format!(
        r#"id = "fn-thumb"
        url = "{url}/fn"
        auth = {{ mode = "bearer", token = "tok-123" }}"#
    ));
    assert_eq!(
        s.batch_size(),
        1,
        "function sinks default to one record per call"
    );
    s.deliver(&[delivery(5, "x", "fn-thumb")]).await.unwrap();
    let got = fake.got.lock().unwrap()[0].clone();
    assert_eq!(header(&got, "authorization"), "Bearer tok-123");
    assert_eq!(
        header(&got, "x-tidemark-idempotency-key"),
        "0000000000000005"
    );
    assert!(got.headers.get("x-tidemark-signature").is_none());
}

#[tokio::test]
async fn cf_access_function_sink() {
    let (url, fake) = fake_server(&[]).await;
    let s = sink(&format!(
        r#"id = "worker"
        url = "{url}/"
        auth = {{ mode = "cf-access", client_id = "abc.access", client_secret = "cf-secret" }}"#
    ));
    s.deliver(&[delivery(1, "x", "worker")]).await.unwrap();
    let got = fake.got.lock().unwrap()[0].clone();
    assert_eq!(header(&got, "cf-access-client-id"), "abc.access");
    assert_eq!(header(&got, "cf-access-client-secret"), "cf-secret");
}

#[tokio::test]
async fn sigv4_lambda_function_sink() {
    let (url, fake) = fake_server(&[202]).await;
    let s = sink(&format!(
        r#"id = "lambda-thumb"
        url = "{url}"
        arns = ["arn:aws:lambda:us-west-2:123456789012:function:thumb"]
        [auth]
        mode = "sigv4-lambda"
        access_key_id = "AKIDEXAMPLE"
        secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        session_token = "sess-tok"
        region = "us-west-2"
        function = "arn:aws:lambda:us-west-2:123456789012:function:thumb"
        "#
    ));
    assert!(s.url().path().ends_with(
        "/functions/arn%3Aaws%3Alambda%3Aus-west-2%3A123456789012%3Afunction%3Athumb/invocations"
    ));
    s.deliver(&[delivery(9, "k", "lambda-thumb")])
        .await
        .unwrap();
    let got = fake.got.lock().unwrap()[0].clone();
    assert!(got.path.starts_with("/2015-03-31/functions/"));
    assert_eq!(header(&got, "x-amz-invocation-type"), "Event");
    assert_eq!(header(&got, "x-amz-security-token"), "sess-tok");
    let auth = header(&got, "authorization");
    let date = header(&got, "x-amz-date");
    assert!(auth.starts_with(&format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{}/us-west-2/lambda/aws4_request, ",
        &date[..8]
    )));
    let signed_names = auth
        .split("SignedHeaders=")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap();
    assert_eq!(
        signed_names,
        "content-type;host;x-amz-date;x-amz-invocation-type;x-amz-security-token"
    );
    // Re-verify as the receiving service would, from the request it actually saw.
    let headers: Vec<(String, String)> = signed_names
        .split(';')
        .map(|n| (n.to_string(), header(&got, n).to_string()))
        .collect();
    let req = sigv4::SignableRequest {
        method: "POST",
        path: s.url().path(),
        query: "",
        headers: &headers,
        payload: &got.body,
    };
    let scope = sigv4::Scope {
        amz_date: date,
        region: "us-west-2",
        service: "lambda",
    };
    assert_eq!(
        sigv4::authorization(
            &req,
            &scope,
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        ),
        auth
    );
    // Alias ARN routing (LambdaFunctionConfigurations point at the AWS ARN).
    let mut d = delivery(1, "k", "other");
    d.record.targets[0].arn = "arn:aws:lambda:us-west-2:123456789012:function:thumb".into();
    assert_eq!(s.accepts(&d.record).as_deref(), Some("cfg"));
    d.record.targets[0].arn = "arn:aws:lambda:us-west-2:123456789012:function:other".into();
    assert_eq!(s.accepts(&d.record), None);
}

#[tokio::test]
async fn status_classification_and_function_errors() {
    let (url, _fake) = fake_server(&[500, 429, 408, 404, 301]).await;
    let s = sink(&format!("id = \"h\"\nurl = \"{url}\""));
    let d = [delivery(1, "k", "h")];
    assert!(matches!(s.deliver(&d).await, Err(SinkError::Retryable(_))));
    assert!(matches!(s.deliver(&d).await, Err(SinkError::Retryable(_))));
    assert!(matches!(s.deliver(&d).await, Err(SinkError::Retryable(_))));
    assert_eq!(
        s.deliver(&d).await,
        Err(SinkError::Permanent("HTTP 404 Not Found".into()))
    );
    assert!(
        matches!(s.deliver(&d).await, Err(SinkError::Permanent(_))),
        "redirects not followed"
    );
    assert!(s.deliver(&d).await.is_ok());

    let dead = sink("id = \"h\"\nurl = \"http://127.0.0.1:1/\"");
    match dead.deliver(&d).await {
        Err(SinkError::Retryable(m)) => assert!(!m.contains("127.0.0.1:1"), "url stripped: {m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn config_validation_and_redaction() {
    let bad = [
        ("id = \"has space\"\nurl = \"http://x\"", "id must be"),
        ("id = \"h\"", "url is required"),
        ("id = \"h\"\nurl = \"ftp://x\"", "http or https"),
        ("id = \"h\"\nurl = \"http://u:p@x/\"", "credentials"),
        (
            "id = \"h\"\nurl = \"http://x\"\nauth = { mode = \"hmac\", secret = \"\" }",
            "secret is empty",
        ),
        (
            "id = \"h\"\nauth = { mode = \"sigv4-lambda\", access_key_id = \"a\", secret_access_key = \"b\", region = \"\", function = \"f\" }",
            "region and function",
        ),
    ];
    for (src, want) in bad {
        let cfg: SinkConfig = toml::from_str(src).unwrap();
        let err = WebhookSink::from_config(cfg).unwrap_err().to_string();
        assert!(err.contains(want), "{src}: {err}");
    }
    assert!(toml::from_str::<SinkConfig>("id = \"h\"\nauth = { mode = \"basic\" }").is_err());

    let src = r#"id = "h"
        url = "https://example.com/hook"
        auth = { mode = "sigv4-lambda", access_key_id = "AK", secret_access_key = "very-secret-key", session_token = "very-secret-token", region = "r", function = "f" }"#;
    let cfg: SinkConfig = toml::from_str(src).unwrap();
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("very-secret"), "{dbg}");
    let s = WebhookSink::from_config(cfg).unwrap();
    assert!(!format!("{s:?}").contains("very-secret"));
    for src in [
        "id = \"h\"\nurl = \"http://x\"\nauth = { mode = \"bearer\", token = \"very-secret\" }",
        "id = \"h\"\nurl = \"http://x\"\nauth = { mode = \"hmac\", secret = \"very-secret\" }",
        "id = \"h\"\nurl = \"http://x\"\nauth = { mode = \"cf-access\", client_id = \"i\", client_secret = \"very-secret\" }",
    ] {
        let cfg: SinkConfig = toml::from_str(src).unwrap();
        assert!(!format!("{cfg:?}").contains("very-secret"));
        assert!(!format!("{:?}", WebhookSink::from_config(cfg).unwrap()).contains("very-secret"));
    }
}

#[tokio::test]
async fn worker_retries_then_delivers_end_to_end() {
    let (url, fake) = fake_server(&[503, 500]).await;
    let dir = tempfile::tempdir().unwrap();
    let store = RedbMetaStore::open(&dir.path().join("m.redb")).unwrap();
    let cfg = NotificationConfiguration::from_xml(
        "<NotificationConfiguration><QueueConfiguration><Id>c1</Id><Queue>arn:tidemark:sink::hook</Queue>\
         <Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>",
    )
    .unwrap();
    let ob = Outbox::new(false);
    let o = ob.clone();
    store
        .write(move |txn| {
            notification::store(txn, BucketId(1), &cfg)?;
            o.append(
                txn,
                BucketId(1),
                &Event::new(EventName::ObjectCreatedPut, "b", "k"),
            )?;
            Ok::<_, EventsError>(())
        })
        .await
        .unwrap();
    let s = sink(&format!(
        "id = \"hook\"\nurl = \"{url}/\"\nauth = {{ mode = \"hmac\", secret = \"x\" }}"
    ));
    let opts = WorkerOptions {
        base_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        ..WorkerOptions::default()
    };
    let w = DeliveryWorker::new(store.clone(), ob, Arc::new(s)).with_options(opts);
    let (_tx, mut rx) = watch::channel(false);
    assert_eq!(w.run_once(&mut rx).await.unwrap(), 1);
    let got = fake.got.lock().unwrap().clone();
    assert_eq!(got.len(), 3, "two retryable failures, then success");
    assert!(
        got.iter()
            .all(|r| header(r, "x-tidemark-idempotency-key") == "0000000000000001")
    );
    let r = store.read().unwrap();
    assert_eq!(Outbox::cursor(&r, "hook").unwrap(), 1);
    assert!(Outbox::dlq(&r, "hook", 10).unwrap().is_empty());
}

#[tokio::test]
async fn sse_stream_filters_and_frames() {
    let b = SseBroadcast::new(16);
    let app = sse_router(b.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut resp = reqwest::get(format!(
        "http://{addr}/_tidemark/v1/events?filter=s3:ObjectCreated:*&prefix=img/"
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "text/event-stream"
    );
    for _ in 0..200 {
        if b.subscribers() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mk = |seq, name, key: &str| Delivery {
        seq,
        record: OutboxRecord {
            event: Event::new(name, "bkt", key),
            targets: vec![],
            only_sink: None,
        },
        configuration_id: String::new(),
    };
    assert_eq!(
        b.accepts(&mk(1, EventName::TidemarkPitrRestore, "x").record),
        Some(String::new())
    );
    b.deliver(&[
        mk(1, EventName::ObjectRemovedDelete, "img/a"),
        mk(2, EventName::ObjectCreatedPut, "doc/a"),
        mk(3, EventName::ObjectCreatedPut, "img/b.png"),
    ])
    .await
    .unwrap();
    let mut text = String::new();
    while !text.contains("\n\n") {
        let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    assert!(text.contains("event: s3:ObjectCreated:Put\n"), "{text}");
    assert!(text.contains("id: 3\n"), "{text}");
    assert!(text.contains("img/b.png"), "{text}");
    assert!(
        !text.contains("doc/a") && !text.contains("id: 1\n"),
        "{text}"
    );
}
