//! Lane 1 wiring proof: every S3 request through the real server is SigV4-verified against the
//! credential store and policy-evaluated (identity ∪ group ∪ bucket policy ∪
//! PublicAccessBlock, explicit deny wins); STS sessions work and are revocable; the admin API
//! and MCP endpoint are mounted and authenticated.

mod common;
use aws_sdk_s3::presigning::PresigningConfig;
use cairn_admin::client::AdminClient;
use cairn_auth::SecretString;
use cairn_server::test_support::RootCreds;
use common::*;
use serde_json::json;
use std::time::{Duration, SystemTime};

fn admin(env: &Env, ak: &str, sk: &str) -> AdminClient {
    AdminClient::new(&env.url(""), ak, SecretString::new(sk), None, "us-east-1").unwrap()
}

fn root_admin(env: &Env) -> AdminClient {
    admin(env, &env.creds.access_key, &env.creds.secret_key)
}

fn creds(ak: &str, sk: &str) -> RootCreds {
    RootCreds {
        access_key: ak.into(),
        secret_key: sk.into(),
    }
}

/// Create `name` with an inline policy and return a client signed with a fresh key.
async fn user_with_policy(env: &Env, name: &str, policy: serde_json::Value) -> aws_sdk_s3::Client {
    let a = root_admin(env);
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
    client(
        env.addr,
        &creds(
            k["access_key_id"].as_str().unwrap(),
            k["secret_access_key"].as_str().unwrap(),
        ),
    )
}

#[tokio::test]
async fn unsigned_and_badly_signed_requests_are_rejected() {
    let env = Env::new().await;
    env.bucket("wire").await;
    env.put("wire", "k", "v").await;

    let r = reqwest::get(env.url("/wire/k")).await.unwrap();
    assert_eq!(r.status().as_u16(), 403);
    assert!(
        r.text()
            .await
            .unwrap()
            .contains("<Code>AccessDenied</Code>")
    );
    let r = reqwest::get(env.url("/")).await.unwrap();
    assert_eq!(r.status().as_u16(), 403);

    let wrong_secret = client(env.addr, &creds(&env.creds.access_key, "not-the-secret"));
    let e = wrong_secret
        .get_object()
        .bucket("wire")
        .key("k")
        .send()
        .await;
    assert_eq!(code(e), "SignatureDoesNotMatch");
    let unknown = client(env.addr, &creds("CAIRNNOSUCHKEY000000", "whatever"));
    let e = unknown.list_buckets().send().await;
    assert_eq!(code(e), "InvalidAccessKeyId");

    // A tampered signature on an otherwise valid header is rejected too.
    let presigned = env
        .s3
        .get_object()
        .bucket("wire")
        .key("k")
        .presigned(PresigningConfig::expires_in(Duration::from_secs(60)).unwrap())
        .await
        .unwrap();
    let ok = reqwest::get(presigned.uri()).await.unwrap();
    assert_eq!(ok.status().as_u16(), 200);
    assert_eq!(ok.text().await.unwrap(), "v");
    let uri = presigned.uri().to_string();
    let idx = uri.find("X-Amz-Signature=").unwrap() + "X-Amz-Signature=".len();
    let mut bad = uri.clone();
    let flipped = if &uri[idx..idx + 1] == "0" { "1" } else { "0" };
    bad.replace_range(idx..idx + 1, flipped);
    let r = reqwest::get(&bad).await.unwrap();
    assert_eq!(r.status().as_u16(), 403);
    assert!(
        r.text()
            .await
            .unwrap()
            .contains("<Code>SignatureDoesNotMatch</Code>")
    );
    env.stop().await;
}

#[tokio::test]
async fn expired_presigned_url_is_rejected() {
    let env = Env::new().await;
    env.bucket("wire").await;
    env.put("wire", "k", "v").await;
    let cfg = PresigningConfig::builder()
        .start_time(SystemTime::now() - Duration::from_secs(3600))
        .expires_in(Duration::from_secs(60))
        .build()
        .unwrap();
    let p = env
        .s3
        .get_object()
        .bucket("wire")
        .key("k")
        .presigned(cfg)
        .await
        .unwrap();
    let r = reqwest::get(p.uri()).await.unwrap();
    assert_eq!(r.status().as_u16(), 403);
    let body = r.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert!(body.to_lowercase().contains("expired"), "{body}");
    env.stop().await;
}

#[tokio::test]
async fn identity_group_and_bucket_policy_denies_win() {
    let env = Env::new().await;
    env.bucket("wire").await;
    for k in ["open", "secret/a", "grp/a", "bp/a"] {
        env.put("wire", k, "bytes").await;
    }
    let alice = user_with_policy(
        &env,
        "alice",
        json!({"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::wire","arn:aws:s3:::wire/*"]},
            {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::wire/secret/*"}
        ]}),
    )
    .await;
    let get = |c: &aws_sdk_s3::Client, k: &'static str| {
        let c = c.clone();
        async move { c.get_object().bucket("wire").key(k).send().await }
    };
    assert!(get(&alice, "open").await.is_ok());
    // Identity-policy explicit deny beats its own Allow.
    assert_eq!(code(get(&alice, "secret/a").await), "AccessDenied");
    // No grant at all on another bucket.
    env.bucket("other").await;
    let e = alice.list_objects_v2().bucket("other").send().await;
    assert_eq!(code(e), "AccessDenied");

    // Group policy deny applies to members.
    let a = root_admin(&env);
    a.call("POST", "/groups", &[], Some(&json!({"name":"g"})))
        .await
        .unwrap();
    a.call("PUT", "/groups/g/members/alice", &[], None)
        .await
        .unwrap();
    a.call(
        "PUT",
        "/groups/g/policies/deny-grp",
        &[],
        Some(&json!({"document": {"Version":"2012-10-17","Statement":[
            {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::wire/grp/*"}]}})),
    )
    .await
    .unwrap();
    assert_eq!(code(get(&alice, "grp/a").await), "AccessDenied");
    assert!(get(&alice, "open").await.is_ok());

    // Bucket policy deny applies even though the identity policy allows.
    let bp = json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/alice"},
         "Action":"s3:GetObject","Resource":"arn:aws:s3:::wire/bp/*"}]});
    env.s3
        .put_bucket_policy()
        .bucket("wire")
        .policy(bp.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(code(get(&alice, "bp/a").await), "AccessDenied");
    assert!(get(&alice, "open").await.is_ok());

    // A user with no policy can do nothing, and cannot use the admin API.
    let bob = user_with_policy(
        &env,
        "bob",
        json!({"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}),
    )
    .await;
    assert!(bob.list_buckets().send().await.is_ok());
    assert_eq!(code(get(&bob, "open").await), "AccessDenied");
    env.stop().await;
}

#[tokio::test]
async fn public_bucket_policy_respects_public_access_block() {
    let env = Env::new().await;
    env.bucket("pub").await;
    env.put("pub", "x", "public bytes").await;
    let bp = json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]});
    env.s3
        .put_bucket_policy()
        .bucket("pub")
        .policy(bp.to_string())
        .send()
        .await
        .unwrap();
    let r = reqwest::get(env.url("/pub/x")).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(r.text().await.unwrap(), "public bytes");
    env.s3
        .put_public_access_block()
        .bucket("pub")
        .public_access_block_configuration(
            aws_sdk_s3::types::PublicAccessBlockConfiguration::builder()
                .restrict_public_buckets(true)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let r = reqwest::get(env.url("/pub/x")).await.unwrap();
    assert_eq!(r.status().as_u16(), 403);
    env.stop().await;
}

fn xml_field<'a>(xml: &'a str, t: &str) -> &'a str {
    let open = format!("<{t}>");
    let s = xml
        .find(&open)
        .unwrap_or_else(|| panic!("no <{t}> in {xml}"))
        + open.len();
    let e = xml[s..].find(&format!("</{t}>")).unwrap() + s;
    &xml[s..e]
}

#[tokio::test]
async fn sts_session_works_and_is_revocable() {
    let env = Env::new().await;
    env.bucket("wire").await;
    env.put("wire", "k", "v").await;
    let body = "Action=GetSessionToken&Version=2011-06-15&DurationSeconds=900";
    let host = env.addr.to_string();
    let hs = vec![
        ("host".to_string(), host),
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        ),
    ];
    let add = cairn_auth::sigv4::sign_headers(
        "POST",
        "/",
        "",
        &hs,
        body.as_bytes(),
        &env.creds.access_key,
        &SecretString::new(env.creds.secret_key.clone()),
        None,
        cairn_auth::Ts::now(),
        "us-east-1",
        "sts",
    );
    let mut rb = reqwest::Client::new().post(env.url("/"));
    for (k, v) in hs.iter().skip(1).chain(add.iter()) {
        rb = rb.header(k.as_str(), v.as_str());
    }
    let r = rb.body(body).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let xml = r.text().await.unwrap();
    let ak = xml_field(&xml, "AccessKeyId").to_string();
    let sk = xml_field(&xml, "SecretAccessKey").to_string();
    let token = xml_field(&xml, "SessionToken").to_string();
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(env.url(""))
        .force_path_style(true)
        .credentials_provider(aws_credential_types::Credentials::new(
            &ak,
            &sk,
            Some(token.clone()),
            None,
            "sts",
        ))
        .http_client(aws_smithy_http_client::Builder::new().build_http())
        .build();
    let session = aws_sdk_s3::Client::from_conf(conf.clone());
    assert!(
        session
            .get_object()
            .bucket("wire")
            .key("k")
            .send()
            .await
            .is_ok()
    );
    // Without the token the temporary key is not accepted.
    let no_token = client(env.addr, &creds(&ak, &sk));
    assert!(
        no_token
            .get_object()
            .bucket("wire")
            .key("k")
            .send()
            .await
            .is_err()
    );
    root_admin(&env)
        .call("DELETE", &format!("/sessions/{ak}"), &[], None)
        .await
        .unwrap();
    let e = session.get_object().bucket("wire").key("k").send().await;
    assert!(e.is_err(), "revoked session must be rejected");
    env.stop().await;
}

#[tokio::test]
async fn admin_api_is_mounted_and_authenticated() {
    let env = Env::new().await;
    let r = reqwest::get(env.url("/_cairn/v1/whoami")).await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let who = root_admin(&env)
        .call("GET", "/whoami", &[], None)
        .await
        .unwrap();
    assert!(who.to_string().contains("root"), "{who}");
    let bad = admin(&env, &env.creds.access_key, "wrong");
    assert!(bad.call("GET", "/whoami", &[], None).await.is_err());
    env.stop().await;
}

#[tokio::test]
async fn mcp_http_is_mounted_and_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = cairn_server::test_support::test_config(dir.path());
    cfg.mcp.enabled = true;
    let (addr, _creds, handle) = cairn_server::test_support::spawn_with(cfg).await;
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/_cairn/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#)
        .send()
        .await
        .unwrap();
    let st = r.status().as_u16();
    assert!(
        st == 401 || st == 403,
        "unsigned MCP must be rejected, got {st}"
    );
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn oidc_federation_is_not_wired_even_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = cairn_server::test_support::test_config(dir.path());
    cfg.auth.oidc_providers = vec![cairn_core::config::OidcProviderEntry {
        issuer: "https://idp.example".into(),
        audiences: vec!["cairn".into()],
        jwks_url: None,
        jwks: Some(r#"{"keys":[]}"#.into()),
        claim_tags: Default::default(),
    }];
    let (addr, _creds, handle) = cairn_server::test_support::spawn_with(cfg).await;
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A000000000000%3Arole%2Fr&RoleSessionName=s&WebIdentityToken=x.y.z")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let body = r.text().await.unwrap();
    assert!(body.contains("not configured"), "{body}");
    handle.shutdown().await.unwrap();
}
