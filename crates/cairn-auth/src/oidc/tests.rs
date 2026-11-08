//! OIDC federation tests: local JWKS on 127.0.0.1:0, locally generated RS256 / ES256 keys.

use super::*;
use crate::MasterKey;
use crate::store::{CredentialStore, MemoryBackend};
use crate::sts::{StsState, router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

const ISS: &str = "https://idp.test";
const AUD: &str = "cairn";

struct RsaKey {
    kid: String,
    enc: EncodingKey,
    jwk: Value,
}

fn rsa_key(kid: &str) -> RsaKey {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    let k = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let der = k.to_pkcs1_der().unwrap();
    RsaKey {
        kid: kid.into(),
        enc: EncodingKey::from_rsa_der(der.as_bytes()),
        jwk: json!({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": URL_SAFE_NO_PAD.encode(k.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(k.e().to_bytes_be()),
        }),
    }
}

fn ec_key(kid: &str) -> RsaKey {
    use p256::pkcs8::EncodePrivateKey;
    let sk = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let pt = sk.verifying_key().to_encoded_point(false);
    RsaKey {
        kid: kid.into(),
        enc: EncodingKey::from_ec_der(sk.to_pkcs8_der().unwrap().as_bytes()),
        jwk: json!({
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(pt.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(pt.y().unwrap()),
        }),
    }
}

fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

fn claims(sub: &str) -> Value {
    json!({"iss": ISS, "aud": AUD, "sub": sub, "exp": now() + 600, "iat": now(),
           "email": "dev@example.com", "team": "storage"})
}

fn sign(k: &RsaKey, alg: Algorithm, c: &Value) -> String {
    let mut h = Header::new(alg);
    h.kid = Some(k.kid.clone());
    encode(&h, c, &k.enc).unwrap()
}

/// A JWKS endpoint on 127.0.0.1:0 whose document can be swapped; counts fetches.
struct Jwks {
    url: String,
    doc: Arc<Mutex<Value>>,
    hits: Arc<AtomicUsize>,
}

async fn jwks_server(keys: Vec<Value>) -> Jwks {
    let doc = Arc::new(Mutex::new(json!({ "keys": keys })));
    let hits = Arc::new(AtomicUsize::new(0));
    let (d, h) = (doc.clone(), hits.clone());
    let app = axum::Router::new().route(
        "/jwks",
        axum::routing::get(move || {
            let (d, h) = (d.clone(), h.clone());
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                axum::Json(d.lock().unwrap().clone())
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    Jwks {
        url: format!("http://{addr}/jwks"),
        doc,
        hits,
    }
}

fn provider(jwks_url: Option<&str>, inline: Option<Value>) -> OidcProviderConfig {
    OidcProviderConfig {
        issuer: ISS.into(),
        audiences: vec![AUD.into()],
        jwks_url: jwks_url.map(str::to_string),
        jwks: inline,
        claim_tags: [("team".to_string(), "team".to_string())].into(),
    }
}

async fn store_with_role(trust: &str) -> Arc<CredentialStore> {
    let store = Arc::new(CredentialStore::new(
        Arc::new(MemoryBackend::new()),
        MasterKey::new([9; 32]),
    ));
    store.create_role("ci", trust, None).await.unwrap();
    store
        .put_role_policy(
            "ci",
            "read",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::builds/${aws:PrincipalTag/team}/*"}]}"#,
        )
        .await
        .unwrap();
    store
}

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"idp.test"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"idp.test:aud":"cairn"},"StringLike":{"idp.test:sub":"repo:acme/*"}}}]}"#;

async fn call(app: &axum::Router, token: &str, role: &str) -> (http::StatusCode, String) {
    let body = format!(
        "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn={role}&RoleSessionName=gha-1&WebIdentityToken={token}"
    );
    let req = http::Request::post("/")
        .header("host", "localhost:9000")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let r = app.clone().oneshot(req).await.unwrap();
    let st = r.status();
    let b = r.into_body().collect().await.unwrap().to_bytes();
    (st, String::from_utf8(b.to_vec()).unwrap())
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> &'a str {
    let i = s.find(a).unwrap() + a.len();
    &s[i..i + s[i..].find(b).unwrap()]
}

#[tokio::test]
async fn rs256_via_jwks_url_issues_tagged_session() {
    let k = rsa_key("k1");
    let srv = jwks_server(vec![k.jwk.clone()]).await;
    let v = Arc::new(OidcVerifier::new(vec![provider(Some(&srv.url), None)]).unwrap());
    let store = store_with_role(TRUST).await;
    let app = router(StsState::new(store.clone()).with_oidc(v));
    let tok = sign(&k, Algorithm::RS256, &claims("repo:acme/app:ref:main"));
    let (st, body) = call(&app, &tok, "arn:aws:iam::000000000000:role/ci").await;
    assert_eq!(st, http::StatusCode::OK, "{body}");
    assert!(body.contains("<SubjectFromWebIdentityToken>repo:acme/app:ref:main<"));
    assert!(body.contains("<Provider>idp.test</Provider>"));
    assert!(body.contains("<Audience>cairn</Audience>"));
    assert!(!body.contains(&tok), "token must not be echoed");
    let ak = between(&body, "<AccessKeyId>", "<");
    let token = between(&body, "<SessionToken>", "<");
    let cred = store.lookup(ak).await.unwrap().unwrap();
    assert!(cred.verify_session_token(Some(token)));
    let p = cred.principal;
    assert_eq!(p.arn, "arn:aws:sts::000000000000:assumed-role/ci/gha-1");
    assert_eq!(p.tags.get("team").map(String::as_str), Some("storage"));
    // The session tag drives `${aws:PrincipalTag/team}` in the role policy.
    let eng = crate::AuthzEngine::new();
    let ctx = crate::ConditionContext::new();
    let get = |r: &str| eng.authorize(Some(&p), "s3:GetObject", r, &ctx, None);
    assert!(get("arn:aws:s3:::builds/storage/x").is_allowed());
    assert!(!get("arn:aws:s3:::builds/other/x").is_allowed());
    // Sessions list the federated source; revocation by role works.
    let s = store.list_sessions().await.unwrap();
    assert_eq!(
        s[0].source.as_deref(),
        Some("oidc:idp.test/repo:acme/app:ref:main")
    );
    assert_eq!(store.revoke_sessions_for("role:ci/").await.unwrap(), 1);
    assert!(store.lookup(ak).await.unwrap().is_none());
    // A second token is verified from the cache: one JWKS fetch in total.
    let (st, _) = call(&app, &tok, "ci").await;
    assert_eq!(st, http::StatusCode::OK);
    assert_eq!(srv.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn es256_with_inline_jwks() {
    let k = ec_key("ec1");
    let v =
        OidcVerifier::new(vec![provider(None, Some(json!({"keys": [k.jwk.clone()]})))]).unwrap();
    let as_string = OidcVerifier::new(vec![provider(
        None,
        Some(Value::String(json!({"keys": [k.jwk.clone()]}).to_string())),
    )])
    .unwrap();
    as_string
        .verify(&sign(&k, Algorithm::ES256, &claims("s")))
        .await
        .unwrap();
    let id = v
        .verify(&sign(&k, Algorithm::ES256, &claims("repo:acme/x")))
        .await
        .unwrap();
    assert_eq!(id.provider, "idp.test");
    assert_eq!(id.subject, "repo:acme/x");
    assert_eq!(id.audience, vec!["cairn".to_string()]);
    // An RS256 header against an EC-only JWKS finds no usable key.
    let rk = rsa_key("ec1");
    assert_eq!(
        v.verify(&sign(&rk, Algorithm::RS256, &claims("s"))).await,
        Err(OidcError::UnknownKey)
    );
}

#[tokio::test]
async fn rejects_expired_wrong_aud_wrong_issuer_and_bad_signature() {
    let k = ec_key("ec1");
    let v = OidcVerifier::new(vec![provider(None, Some(json!({"keys": [k.jwk]})))]).unwrap();
    let mut c = claims("s");
    c["exp"] = json!(now() - 3600);
    assert_eq!(
        v.verify(&sign(&k, Algorithm::ES256, &c)).await,
        Err(OidcError::Expired)
    );
    let mut c = claims("s");
    c["aud"] = json!("someone-else");
    assert_eq!(
        v.verify(&sign(&k, Algorithm::ES256, &c)).await,
        Err(OidcError::InvalidAudience)
    );
    let mut c = claims("s");
    c["iss"] = json!("https://evil.test");
    assert_eq!(
        v.verify(&sign(&k, Algorithm::ES256, &c)).await,
        Err(OidcError::UnknownIssuer)
    );
    let mut c = claims("s");
    c["nbf"] = json!(now() + 3600);
    assert!(matches!(
        v.verify(&sign(&k, Algorithm::ES256, &c)).await,
        Err(OidcError::InvalidClaims(_))
    ));
    let mut c = claims("s");
    c.as_object_mut().unwrap().remove("sub");
    assert!(matches!(
        v.verify(&sign(&k, Algorithm::ES256, &c)).await,
        Err(OidcError::InvalidClaims(_))
    ));
    // Same kid, different key: signature fails.
    let other = ec_key("ec1");
    assert_eq!(
        v.verify(&sign(&other, Algorithm::ES256, &claims("s")))
            .await,
        Err(OidcError::InvalidSignature)
    );
    assert_eq!(v.verify("a.b").await, Err(OidcError::Malformed));
    assert_eq!(v.verify("not.a.jwt").await, Err(OidcError::Malformed));
}

#[tokio::test]
async fn rejects_symmetric_and_none_algorithms() {
    let k = ec_key("ec1");
    let v = OidcVerifier::new(vec![provider(None, Some(json!({"keys": [k.jwk]})))]).unwrap();
    let mut h = Header::new(Algorithm::HS256);
    h.kid = Some("ec1".into());
    let hs = encode(&h, &claims("s"), &EncodingKey::from_secret(b"k")).unwrap();
    assert_eq!(v.verify(&hs).await, Err(OidcError::UnsupportedAlgorithm));
    let none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims("s").to_string())
    );
    assert!(v.verify(&none).await.is_err());
}

#[tokio::test]
async fn unknown_kid_rejected_then_rotation_refetches() {
    let k1 = rsa_key("k1");
    let k2 = rsa_key("k2");
    let srv = jwks_server(vec![k1.jwk.clone()]).await;
    let v = OidcVerifier::new(vec![provider(Some(&srv.url), None)])
        .unwrap()
        .with_cache_policy(Duration::from_secs(3600), Duration::from_secs(3600));
    v.verify(&sign(&k1, Algorithm::RS256, &claims("s")))
        .await
        .unwrap();
    // k2 is unknown and the refetch interval has not elapsed: rejected without a fetch.
    let t2 = sign(&k2, Algorithm::RS256, &claims("s"));
    assert_eq!(v.verify(&t2).await, Err(OidcError::UnknownKey));
    assert_eq!(srv.hits.load(Ordering::SeqCst), 1);
    // The provider rotates to k2; once refetching is allowed the new kid resolves.
    *srv.doc.lock().unwrap() = json!({"keys": [k2.jwk.clone()]});
    let v = v.with_cache_policy(Duration::from_secs(3600), Duration::ZERO);
    v.verify(&t2).await.unwrap();
    assert_eq!(srv.hits.load(Ordering::SeqCst), 2);
    // A kid absent even after a refetch stays rejected.
    let k3 = rsa_key("k3");
    assert_eq!(
        v.verify(&sign(&k3, Algorithm::RS256, &claims("s"))).await,
        Err(OidcError::UnknownKey)
    );
}

#[tokio::test]
async fn sts_maps_errors_and_enforces_trust_conditions() {
    let k = ec_key("ec1");
    let v = Arc::new(
        OidcVerifier::new(vec![provider(None, Some(json!({"keys": [k.jwk.clone()]})))]).unwrap(),
    );
    let store = store_with_role(TRUST).await;
    let app = router(StsState::new(store.clone()).with_oidc(v));
    // sub outside the trust condition.
    let (st, body) = call(
        &app,
        &sign(&k, Algorithm::ES256, &claims("repo:evil/x")),
        "ci",
    )
    .await;
    assert_eq!(st, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"));
    let mut c = claims("repo:acme/x");
    c["exp"] = json!(now() - 3600);
    let (st, body) = call(&app, &sign(&k, Algorithm::ES256, &c), "ci").await;
    assert_eq!(st, http::StatusCode::BAD_REQUEST);
    assert!(body.contains("<Code>ExpiredTokenException</Code>"));
    let mut c = claims("repo:acme/x");
    c["aud"] = json!("other");
    let (st, body) = call(&app, &sign(&k, Algorithm::ES256, &c), "ci").await;
    assert_eq!(st, http::StatusCode::BAD_REQUEST);
    assert!(body.contains("<Code>InvalidIdentityToken</Code>"));
    // Unknown role: AccessDenied, no existence leak.
    let (st, _) = call(
        &app,
        &sign(&k, Algorithm::ES256, &claims("repo:acme/x")),
        "nope",
    )
    .await;
    assert_eq!(st, http::StatusCode::FORBIDDEN);
    // A trust policy that only names an AWS principal or `*` never admits web identities.
    let star = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity"}]}"#;
    store.update_assume_role_policy("ci", star).await.unwrap();
    let (st, _) = call(
        &app,
        &sign(&k, Algorithm::ES256, &claims("repo:acme/x")),
        "ci",
    )
    .await;
    assert_eq!(st, http::StatusCode::FORBIDDEN);
    // Explicit Deny beats Allow.
    let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"https://idp.test"},"Action":"sts:AssumeRoleWithWebIdentity"},{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"aws:RequestTag/team":"storage"}}}]}"#;
    store.update_assume_role_policy("ci", deny).await.unwrap();
    let (st, _) = call(
        &app,
        &sign(&k, Algorithm::ES256, &claims("repo:acme/x")),
        "ci",
    )
    .await;
    assert_eq!(st, http::StatusCode::FORBIDDEN);
    // Issuer-URL and ARN forms of the Federated principal are accepted.
    let arn = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/idp.test"},"Action":"sts:AssumeRoleWithWebIdentity"}]}"#;
    store.update_assume_role_policy("ci", arn).await.unwrap();
    let (st, body) = call(&app, &sign(&k, Algorithm::ES256, &claims("anyone")), "ci").await;
    assert_eq!(st, http::StatusCode::OK, "{body}");
}

#[tokio::test]
async fn not_configured_and_missing_params() {
    let store = store_with_role(TRUST).await;
    let app = router(StsState::new(store));
    let (st, body) = call(&app, "a.b.c", "ci").await;
    assert_eq!(st, http::StatusCode::BAD_REQUEST);
    assert!(body.contains("<Code>InvalidIdentityToken</Code>"));
    let req =
        http::Request::get("/?Action=AssumeRoleWithWebIdentity&RoleArn=ci&RoleSessionName=xx")
            .header("host", "localhost:9000")
            .body(axum::body::Body::empty())
            .unwrap();
    let r = app.clone().oneshot(req).await.unwrap();
    assert_eq!(r.status(), http::StatusCode::BAD_REQUEST);
    let b = r.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&b).contains("MissingParameter"));
}

#[test]
fn provider_config_validation() {
    let ok = provider(Some("https://idp.test/jwks"), None);
    assert!(OidcVerifier::new(vec![ok.clone()]).is_ok());
    let mut c = ok.clone();
    c.jwks_url = Some("http://idp.test/jwks".into());
    assert!(matches!(
        OidcVerifier::new(vec![c]),
        Err(OidcError::Config(_))
    ));
    let mut c = ok.clone();
    c.audiences.clear();
    assert!(OidcVerifier::new(vec![c]).is_err());
    let mut c = ok.clone();
    c.jwks_url = None;
    assert!(OidcVerifier::new(vec![c]).is_err());
    let mut c = ok.clone();
    c.issuer = "http://idp.test".into();
    assert!(OidcVerifier::new(vec![c]).is_err());
    assert!(OidcVerifier::new(vec![ok.clone(), ok]).is_err());
    let parsed: OidcProviderConfig = serde_json::from_value(json!({
        "issuer": "https://token.actions.githubusercontent.com",
        "audiences": ["cairn"],
        "jwks_url": "https://token.actions.githubusercontent.com/.well-known/jwks",
    }))
    .unwrap();
    assert_eq!(parsed.provider_id(), "token.actions.githubusercontent.com");
}
