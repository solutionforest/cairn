use super::*;
use crate::store::MemoryBackend;
use crate::types::ManualClock;
use crate::{MasterKey, SecretString, Ts};
use http_body_util::BodyExt;
use tower::ServiceExt;

const NOW: i64 = 1_790_000_000;

struct Fx {
    store: Arc<CredentialStore>,
    clock: Arc<ManualClock>,
    alice_ak: String,
    alice_sk: SecretString,
}

async fn fx() -> Fx {
    let clock = Arc::new(ManualClock::new(NOW));
    let store = Arc::new(
        CredentialStore::new(Arc::new(MemoryBackend::new()), MasterKey::new([5; 32]))
            .with_clock(clock.clone()),
    );
    store
        .ensure_root("ROOTAK", &SecretString::new("rootsecret"))
        .await
        .unwrap();
    store.create_user("alice").await.unwrap();
    store
        .put_user_policy(
            "alice",
            "sts",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}"#,
        )
        .await
        .unwrap();
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/alice"},"Action":"sts:AssumeRole"}]}"#;
    store.create_role("reader", trust, None).await.unwrap();
    let k = store
        .create_access_key("alice", Default::default())
        .await
        .unwrap();
    Fx {
        store,
        clock,
        alice_ak: k.access_key_id,
        alice_sk: k.secret_key,
    }
}

struct Req<'a> {
    method: &'a str,
    path_query: &'a str,
    body: &'a str,
    ak: &'a str,
    sk: &'a SecretString,
    token: Option<&'a str>,
    at: Ts,
}

fn signed(r: Req<'_>) -> http::Request<axum::body::Body> {
    let (path, query) = r.path_query.split_once('?').unwrap_or((r.path_query, ""));
    let mut hs = vec![("host".to_string(), "localhost:9000".to_string())];
    if !r.body.is_empty() {
        hs.push((
            "content-type".into(),
            "application/x-www-form-urlencoded; charset=utf-8".into(),
        ));
    }
    let add = sigv4::sign_headers(
        r.method,
        path,
        query,
        &hs,
        r.body.as_bytes(),
        r.ak,
        r.sk,
        r.token,
        r.at,
        "us-east-1",
        "sts",
    );
    let mut b = http::Request::builder().method(r.method).uri(r.path_query);
    for (k, v) in hs.iter().chain(add.iter()) {
        b = b.header(k, v);
    }
    b.body(axum::body::Body::from(r.body.to_string())).unwrap()
}

async fn send(st: &Fx, req: http::Request<axum::body::Body>) -> (StatusCode, String) {
    let resp = router(StsState::new(st.store.clone()))
        .oneshot(req)
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn tag<'a>(xml: &'a str, t: &str) -> &'a str {
    let open = format!("<{t}>");
    let s = xml
        .find(&open)
        .unwrap_or_else(|| panic!("no <{t}> in {xml}"))
        + open.len();
    let e = xml[s..].find(&format!("</{t}>")).unwrap() + s;
    &xml[s..e]
}

#[tokio::test]
async fn assume_role_via_post_form() {
    let f = fx().await;
    let body = "Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A000000000000%3Arole%2Freader&RoleSessionName=job-1&DurationSeconds=900";
    let (st, xml) = send(
        &f,
        signed(Req {
            method: "POST",
            path_query: "/",
            body,
            ak: &f.alice_ak,
            sk: &f.alice_sk,
            token: None,
            at: f.store.now(),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{xml}");
    assert!(
        xml.starts_with("<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">")
    );
    assert_eq!(
        tag(&xml, "Arn"),
        "arn:aws:sts::000000000000:assumed-role/reader/job-1"
    );
    let ak = tag(&xml, "AccessKeyId").to_string();
    let tok = tag(&xml, "SessionToken").to_string();
    let exp = tag(&xml, "Expiration");
    assert_eq!(exp, Ts::from_secs(NOW + 900).to_rfc3339());
    let cred = f.store.lookup(&ak).await.unwrap().unwrap();
    assert!(cred.verify_session_token(Some(&tok)));
    assert_eq!(cred.secret_key.expose(), tag(&xml, "SecretAccessKey"));
    assert_eq!(cred.principal.id.as_str(), "role:reader/job-1");
}

#[tokio::test]
async fn get_session_token_via_get_and_caller_identity_with_session() {
    let f = fx().await;
    let (st, xml) = send(
        &f,
        signed(Req {
            method: "GET",
            path_query: "/?Action=GetSessionToken&Version=2011-06-15&DurationSeconds=3600",
            body: "",
            ak: &f.alice_ak,
            sk: &f.alice_sk,
            token: None,
            at: f.store.now(),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{xml}");
    assert!(xml.contains("<GetSessionTokenResult>"));
    let ak = tag(&xml, "AccessKeyId").to_string();
    let sk = SecretString::new(tag(&xml, "SecretAccessKey"));
    let tok = tag(&xml, "SessionToken").to_string();

    let call = |token: Option<&str>| {
        signed(Req {
            method: "GET",
            path_query: "/?Action=GetCallerIdentity&Version=2011-06-15",
            body: "",
            ak: &ak,
            sk: &sk,
            token,
            at: f.store.now(),
        })
    };
    let (st, xml) = send(&f, call(Some(&tok))).await;
    assert_eq!(st, StatusCode::OK, "{xml}");
    assert_eq!(tag(&xml, "Arn"), "arn:aws:iam::000000000000:user/alice");
    let (st, xml) = send(&f, call(None)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(tag(&xml, "Code"), "InvalidClientTokenId");
    // session creds cannot be used after expiry
    f.clock.advance(Duration::from_secs(3601));
    let (st, xml) = send(&f, call(Some(&tok))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(tag(&xml, "Code"), "InvalidClientTokenId");
}

#[tokio::test]
async fn auth_failures_return_aws_error_xml() {
    let f = fx().await;
    let ok_req = |sk: &SecretString, at: Ts| {
        signed(Req {
            method: "GET",
            path_query: "/?Action=GetCallerIdentity&Version=2011-06-15",
            body: "",
            ak: &f.alice_ak,
            sk,
            token: None,
            at,
        })
    };
    let (st, _) = send(&f, ok_req(&f.alice_sk, f.store.now())).await;
    assert_eq!(st, StatusCode::OK);
    let (st, xml) = send(&f, ok_req(&SecretString::new("wrong"), f.store.now())).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(tag(&xml, "Code"), "SignatureDoesNotMatch");
    assert!(xml.contains("<Type>Sender</Type>") && xml.contains("<RequestId>"));
    let (st, xml) = send(&f, ok_req(&f.alice_sk, Ts::from_secs(NOW - 16 * 60))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(tag(&xml, "Code"), "RequestExpired");

    let unsigned = http::Request::get("/?Action=GetCallerIdentity")
        .header("host", "x")
        .body(axum::body::Body::empty())
        .unwrap();
    let (st, xml) = send(&f, unsigned).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(tag(&xml, "Code"), "MissingAuthenticationToken");

    // tampered body after signing
    let mut r = signed(Req {
        method: "POST",
        path_query: "/",
        body: "Action=GetSessionToken&Version=2011-06-15",
        ak: &f.alice_ak,
        sk: &f.alice_sk,
        token: None,
        at: f.store.now(),
    });
    *r.body_mut() =
        axum::body::Body::from("Action=GetSessionToken&Version=2011-06-15&DurationSeconds=999");
    let (st, xml) = send(&f, r).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{xml}");
    assert_eq!(tag(&xml, "Code"), "SignatureDoesNotMatch");
}

#[tokio::test]
async fn assume_role_denied_and_validation_errors() {
    let f = fx().await;
    f.store.create_user("bob").await.unwrap();
    let bob = f
        .store
        .create_access_key("bob", Default::default())
        .await
        .unwrap();
    let call = |ak: &str, sk: &SecretString, body: &str| {
        signed(Req {
            method: "POST",
            path_query: "/",
            body,
            ak,
            sk,
            token: None,
            at: f.store.now(),
        })
    };
    let body = "Action=AssumeRole&Version=2011-06-15&RoleArn=reader&RoleSessionName=s";
    let (st, xml) = send(
        &f,
        call(&bob.access_key_id, &bob.secret_key, &format!("{body}x")),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{xml}");
    assert_eq!(tag(&xml, "Code"), "AccessDenied");
    let (st, xml) = send(
        &f,
        call(
            &f.alice_ak,
            &f.alice_sk,
            "Action=AssumeRole&RoleArn=nosuch&RoleSessionName=s1",
        ),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(tag(&xml, "Code"), "AccessDenied");
    let (st, xml) = send(
        &f,
        call(
            &f.alice_ak,
            &f.alice_sk,
            &format!("{body}x&DurationSeconds=60"),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&xml, "Code"), "ValidationError");
    let (st, xml) = send(
        &f,
        call(&f.alice_ak, &f.alice_sk, "Action=AssumeRole&RoleArn=reader"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&xml, "Code"), "MissingParameter");
    let (st, xml) = send(&f, call(&f.alice_ak, &f.alice_sk, "Action=Frobnicate")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&xml, "Code"), "InvalidAction");
    let (st, xml) = send(
        &f,
        call(
            &f.alice_ak,
            &f.alice_sk,
            "Action=GetSessionToken&Version=2010-01-01",
        ),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&xml, "Code"), "InvalidParameterValue");
    let (st, xml) = send(
        &f,
        call(&f.alice_ak, &f.alice_sk, &format!("{body}x&Policy=%7Bbad")),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&xml, "Code"), "MalformedPolicyDocument");
}

#[test]
fn sts_request_detection() {
    let h = HeaderMap::new();
    let mut form = HeaderMap::new();
    form.insert(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    let u = |s: &str| s.parse::<Uri>().unwrap();
    assert!(is_sts_request(&Method::GET, &u("/?Action=AssumeRole"), &h));
    assert!(is_sts_request(&Method::POST, &u("/"), &form));
    assert!(!is_sts_request(&Method::GET, &u("/"), &h));
    assert!(!is_sts_request(&Method::POST, &u("/bucket"), &form));
    assert!(!is_sts_request(&Method::PUT, &u("/?Action=x"), &h));
}
