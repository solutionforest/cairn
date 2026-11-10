//! Regression tests for docs/SECURITY-REVIEW-2026-11-10.md. Each test names its finding.

mod common;
use common::*;
use serde_json::json;
use std::time::Duration;
use tidemark_admin::client::AdminClient;
use tidemark_auth::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Key {
    ak: String,
    sk: String,
}

async fn user_key(env: &Env, name: &str, policy: serde_json::Value) -> Key {
    let a = AdminClient::new(
        &env.url(""),
        &env.creds.access_key,
        SecretString::new(&env.creds.secret_key),
        None,
        "us-east-1",
    )
    .unwrap();
    a.call("POST", "/users", &[], Some(&json!({ "name": name })))
        .await
        .unwrap();
    a.call(
        "PUT",
        &format!("/users/{name}/policies/inline"),
        &[],
        Some(&json!({ "document": policy })),
    )
    .await
    .unwrap();
    let k = a
        .call("POST", &format!("/users/{name}/access-keys"), &[], None)
        .await
        .unwrap();
    Key {
        ak: k["access_key_id"].as_str().unwrap().into(),
        sk: k["secret_access_key"].as_str().unwrap().into(),
    }
}

/// Header-signed request headers (host first) for `method path?query`.
fn signed(
    env: &Env,
    key: &Key,
    method: &str,
    path: &str,
    query: &str,
    extra: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut hs = vec![("host".to_string(), env.addr.to_string())];
    hs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let add = tidemark_auth::sigv4::sign_headers(
        method,
        path,
        query,
        &hs,
        b"",
        &key.ak,
        &SecretString::new(&key.sk),
        None,
        tidemark_auth::Ts::now(),
        "us-east-1",
        "s3",
    );
    hs.extend(add);
    hs
}

/// Send a raw HTTP/1.1 request with `target` as the request-target; returns the status code.
async fn raw(env: &Env, method: &str, target: &str, headers: &[(String, String)]) -> u16 {
    let mut s = tokio::net::TcpStream::connect(env.addr).await.unwrap();
    let mut req = format!("{method} {target} HTTP/1.1\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf);
    head.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[tokio::test]
async fn sec1_absolute_https_uri_does_not_count_as_secure_transport() {
    let env = Env::new().await;
    env.bucket("tls").await;
    env.put("tls", "k", "secret").await;
    env.s3
        .put_bucket_policy()
        .bucket("tls")
        .policy(
            json!({"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*",
                "Action":"s3:*","Resource":["arn:aws:s3:::tls","arn:aws:s3:::tls/*"],
                "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]})
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    let key = user_key(
        &env,
        "alice",
        json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}),
    )
    .await;
    let hs = signed(&env, &key, "GET", "/tls/k", "", &[]);
    assert_eq!(raw(&env, "GET", "/tls/k", &hs).await, 403);
    let hs = signed(&env, &key, "GET", "/tls/k", "", &[]);
    let target = format!("https://{}/tls/k", env.addr);
    assert_eq!(raw(&env, "GET", &target, &hs).await, 403);
    env.stop().await;
}

#[tokio::test]
async fn sec3_object_attributes_as_of_needs_time_travel() {
    let env = Env::new().await;
    env.bucket("ttr").await;
    env.put("ttr", "k", "v1").await;
    let key = user_key(
        &env,
        "bob",
        json!({"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"s3:*","Resource":"*"},
            {"Effect":"Deny","Action":"tidemark:TimeTravel","Resource":"*"}]}),
    )
    .await;
    let at = instant().await;
    let url = env.url("/ttr/k?attributes");
    let send = |hs: Vec<(String, String)>| {
        let mut rb = reqwest::Client::new().get(&url);
        for (k, v) in hs.iter().skip(1) {
            rb = rb.header(k.as_str(), v.as_str());
        }
        rb.send()
    };
    let plain = signed(
        &env,
        &key,
        "GET",
        "/ttr/k",
        "attributes",
        &[("x-amz-object-attributes", "ETag")],
    );
    assert_eq!(send(plain).await.unwrap().status().as_u16(), 200);
    let past = signed(
        &env,
        &key,
        "GET",
        "/ttr/k",
        "attributes",
        &[
            ("x-amz-object-attributes", "ETag"),
            ("x-tidemark-as-of", &at),
        ],
    );
    assert_eq!(send(past).await.unwrap().status().as_u16(), 403);
    env.stop().await;
}

fn presigned(env: &Env, method: &str, path: &str, now: tidemark_auth::Ts) -> String {
    let url = url::Url::parse(&env.url(path)).unwrap();
    tidemark_auth::sigv4::presign_raw(
        &env.creds.access_key,
        &SecretString::new(&env.creds.secret_key),
        None,
        method,
        &url,
        &[],
        Duration::from_secs(300),
        now,
        "us-east-1",
        "s3",
    )
    .unwrap()
    .url
    .to_string()
}

#[tokio::test]
async fn presigned_urls_bind_method_and_reject_future_dates() {
    let env = Env::new().await;
    env.bucket("psu").await;
    env.put("psu", "k", "v").await;
    let c = reqwest::Client::new();
    let now = tidemark_auth::Ts::now();
    let get = presigned(&env, "GET", "/psu/k", now);
    assert_eq!(c.get(&get).send().await.unwrap().status().as_u16(), 200);
    assert_eq!(c.delete(&get).send().await.unwrap().status().as_u16(), 403);
    assert_eq!(
        c.put(&get)
            .body("x")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    let later = presigned(
        &env,
        "GET",
        "/psu/k",
        now.plus(Duration::from_secs(24 * 3600)),
    );
    assert_eq!(c.get(&later).send().await.unwrap().status().as_u16(), 403);
    env.stop().await;
}

#[tokio::test]
async fn sec5_admin_api_refuses_presigned_urls() {
    let env = Env::new().await;
    let c = reqwest::Client::new();
    let url = presigned(
        &env,
        "GET",
        "/_tidemark/v1/whoami",
        tidemark_auth::Ts::now(),
    );
    let r = c.get(&url).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    assert!(
        r.text()
            .await
            .unwrap()
            .contains("MissingAuthenticationToken")
    );
    let url = presigned(
        &env,
        "GET",
        "/_tidemark/v1/access-keys",
        tidemark_auth::Ts::now(),
    );
    assert_eq!(c.get(&url).send().await.unwrap().status().as_u16(), 401);
    env.stop().await;
}
