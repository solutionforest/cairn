use crate::engine::{BucketSummary, MockAdminEngine, TrashEntry};
use crate::*;
use axum::body::Body;
use cairn_auth::{CredentialStore, MasterKey, MemoryBackend, SecretString, Ts, sigv4};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

struct Fx {
    store: Arc<CredentialStore>,
    engine: Arc<MockAdminEngine>,
}

const ROOT_AK: &str = "ROOTADMINKEY";
const ROOT_SK: &str = "root-secret-value";

async fn fx() -> Fx {
    let store = Arc::new(CredentialStore::new(
        Arc::new(MemoryBackend::new()),
        MasterKey::new([1; 32]),
    ));
    store
        .ensure_root(ROOT_AK, &SecretString::new(ROOT_SK))
        .await
        .unwrap();
    let engine = Arc::new(MockAdminEngine::new(
        vec![
            BucketSummary {
                name: "photos".into(),
                id: "b1".into(),
                versioning: "Enabled".into(),
                object_count: 3,
                total_bytes: 300,
                ..Default::default()
            },
            BucketSummary {
                name: "old".into(),
                id: "b2".into(),
                trashed: true,
                ..Default::default()
            },
        ],
        vec![
            TrashEntry {
                bucket: "photos".into(),
                key: "a.jpg".into(),
                version_id: "v1".into(),
                size: 10,
                ..Default::default()
            },
            TrashEntry {
                bucket: "photos".into(),
                key: "b.jpg".into(),
                version_id: "v2".into(),
                size: 20,
                ..Default::default()
            },
        ],
    ));
    Fx { store, engine }
}

impl Fx {
    fn app(&self) -> axum::Router {
        router(AdminState::new(self.store.clone(), self.engine.clone()))
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, http::HeaderMap, Value) {
        let resp = self.app().oneshot(req).await.unwrap();
        let st = resp.status();
        let h = resp.headers().clone();
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice(&b).unwrap_or(Value::Null);
        (st, h, v)
    }

    async fn call(
        &self,
        ak: &str,
        sk: &str,
        method: &str,
        path_query: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (st, _, v) = self.send(signed(ak, sk, method, path_query, body)).await;
        (st, v)
    }

    async fn root(&self, method: &str, pq: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call(ROOT_AK, ROOT_SK, method, pq, body).await
    }

    /// New user with an inline policy and a key; returns (ak, sk).
    async fn user(&self, name: &str, policy: Option<Value>) -> (String, String) {
        self.store.create_user(name).await.unwrap();
        if let Some(p) = policy {
            self.store
                .put_user_policy(name, "p", &p.to_string())
                .await
                .unwrap();
        }
        let k = self
            .store
            .create_access_key(name, Default::default())
            .await
            .unwrap();
        (k.access_key_id, k.secret_key.expose().to_string())
    }
}

fn signed(ak: &str, sk: &str, method: &str, pq: &str, body: Option<Value>) -> Request<Body> {
    let full = format!("{}{pq}", PREFIX);
    let (path, query) = full.split_once('?').unwrap_or((&full, ""));
    let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    let mut hs = vec![("host".to_string(), "127.0.0.1:9000".to_string())];
    if !bytes.is_empty() {
        hs.push(("content-type".into(), "application/json".into()));
    }
    let add = sigv4::sign_headers(
        method,
        path,
        query,
        &hs,
        &bytes,
        ak,
        &SecretString::new(sk),
        None,
        Ts::now(),
        "us-east-1",
        "s3",
    );
    let mut b = Request::builder().method(method).uri(&full);
    for (k, v) in hs.iter().chain(add.iter()) {
        b = b.header(k, v);
    }
    b.body(Body::from(bytes)).unwrap()
}

fn allow(action: &str, resource: &str) -> Value {
    json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":action,"Resource":resource}]})
}

#[tokio::test]
async fn unauthenticated_and_bad_signature_get_error_envelope() {
    let f = fx().await;
    let req = Request::get(format!("{PREFIX}/users"))
        .header("host", "x")
        .body(Body::empty())
        .unwrap();
    let (st, h, v) = f.send(req).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "MissingAuthenticationToken");
    let rid = h.get(REQUEST_ID_HEADER).unwrap().to_str().unwrap();
    assert_eq!(v["error"]["request_id"], rid);
    assert_eq!(rid.len(), 32);

    let (st, v) = f.call(ROOT_AK, "wrong", "GET", "/users", None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "SignatureDoesNotMatch");
    let (st, v) = f.call("NOSUCHKEY", ROOT_SK, "GET", "/users", None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "InvalidClientTokenId");
}

#[tokio::test]
async fn cors_default_deny_and_unknown_routes() {
    let f = fx().await;
    let pre = Request::builder()
        .method("OPTIONS")
        .uri(format!("{PREFIX}/users"))
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let (st, h, _) = f.send(pre).await;
    assert!(st.is_client_error());
    assert!(h.get("access-control-allow-origin").is_none());
    let (st, v) = f.root("GET", "/debug/pprof", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(v["error"]["code"], "NotFound");
    let (st, v) = f.root("PATCH", "/users", None).await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(v["error"]["code"], "MethodNotAllowed");
}

#[tokio::test]
async fn users_and_keys_secret_only_at_creation() {
    let f = fx().await;
    let (st, v) = f
        .root("POST", "/users", Some(json!({"name":"alice"})))
        .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert_eq!(v["arn"], "arn:aws:iam::000000000000:user/alice");
    let (st, v) = f
        .root("POST", "/users", Some(json!({"name":"alice"})))
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(v["error"]["code"], "AlreadyExists");
    let (st, v) = f
        .root("POST", "/users", Some(json!({"name":"bad name!"})))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["code"], "InvalidArgument");
    let (st, v) = f.root("POST", "/users", Some(json!({"nom":"x"}))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");

    let (st, k) = f
        .root(
            "POST",
            "/users/alice/access-keys",
            Some(json!({"allowed_source_cidrs":["10.0.0.0/8"]})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{k}");
    let secret = k["secret_access_key"].as_str().unwrap().to_string();
    assert_eq!(secret.len(), 40);
    let akid = k["access_key_id"].as_str().unwrap().to_string();

    for path in [
        "/users/alice/access-keys",
        "/access-keys",
        "/access-keys?user=alice",
        "/users/alice",
    ] {
        let (st, v) = f.root("GET", path, None).await;
        assert_eq!(st, StatusCode::OK, "{path}");
        assert!(!v.to_string().contains(&secret), "{path} leaked the secret");
        assert!(!v.to_string().contains("secret_access_key"));
    }
    let (_, v) = f.root("GET", "/access-keys?user=alice", None).await;
    assert_eq!(v["items"][0]["access_key_id"], akid.as_str());
    assert_eq!(v["items"][0]["allowed_source_cidrs"][0], "10.0.0.0/8");

    let (st, _) = f
        .root("POST", &format!("/access-keys/{akid}/deactivate"), None)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert!(f.store.lookup(&akid).await.unwrap().is_none());
    f.root("POST", &format!("/access-keys/{akid}/activate"), None)
        .await;
    assert!(f.store.lookup(&akid).await.unwrap().is_some());
    let (st, _) = f.root("POST", "/users/alice/disable", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(f.store.get_user("alice").await.unwrap().disabled);
    f.root("POST", "/users/alice/enable", None).await;
    let (st, _) = f
        .root("DELETE", &format!("/access-keys/{akid}"), None)
        .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = f.root("DELETE", "/users/alice", None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, v) = f.root("GET", "/users/alice", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(v["error"]["code"], "NotFound");
}

#[tokio::test]
async fn policy_controls_admin_access() {
    let f = fx().await;
    let (ak, sk) = f.user("nobody", None).await;
    let (st, v) = f.call(&ak, &sk, "GET", "/users", None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(v["error"]["code"], "AccessDenied");
    let (st, v) = f.call(&ak, &sk, "GET", "/whoami", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["id"], "user:nobody");

    let (ak, sk) = f.user("reader", Some(allow("cairn:List*", "*"))).await;
    assert_eq!(
        f.call(&ak, &sk, "GET", "/users", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.call(&ak, &sk, "GET", "/roles", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.call(&ak, &sk, "POST", "/users", Some(json!({"name":"x"})))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.call(&ak, &sk, "POST", "/root/rotate", None).await.0,
        StatusCode::FORBIDDEN
    );

    let (ak, sk) = f.user("admin", Some(allow("cairn:*", "*"))).await;
    assert_eq!(
        f.call(&ak, &sk, "POST", "/users", Some(json!({"name":"x"})))
            .await
            .0,
        StatusCode::CREATED
    );
    // s3:* does not grant admin actions
    let (ak, sk) = f.user("s3only", Some(allow("s3:*", "*"))).await;
    assert_eq!(
        f.call(&ak, &sk, "GET", "/users", None).await.0,
        StatusCode::FORBIDDEN
    );

    // bucket-scoped admin grants
    let (ak, sk) = f
        .user(
            "trashop",
            Some(allow("cairn:ListTrash", "arn:aws:s3:::photos")),
        )
        .await;
    assert_eq!(
        f.call(&ak, &sk, "GET", "/trash?bucket=photos", None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.call(&ak, &sk, "GET", "/trash?bucket=other", None).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.call(&ak, &sk, "GET", "/trash", None).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn groups_policies_roles_sessions() {
    let f = fx().await;
    f.root("POST", "/users", Some(json!({"name":"bob"}))).await;
    assert_eq!(
        f.root("POST", "/groups", Some(json!({"name":"devs"})))
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        f.root("PUT", "/groups/devs/members/bob", None).await.0,
        StatusCode::OK
    );
    let (_, g) = f.root("GET", "/groups/devs", None).await;
    assert_eq!(g["members"][0], "bob");

    let doc = allow("s3:GetObject", "arn:aws:s3:::photos/*");
    let (st, p) = f
        .root(
            "POST",
            "/policies",
            Some(json!({"name":"read-photos","document":doc})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{p}");
    assert_eq!(p["arn"], "arn:aws:iam::000000000000:policy/read-photos");
    let (st, v) = f
        .root("POST", "/policies", Some(json!({"name":"bad","document":{"Statement":[{"Effect":"Allow","Action":"s3:Nope","Resource":"*"}]}})))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["code"], "MalformedPolicy");
    assert_eq!(
        f.root("PUT", "/groups/devs/attached-policies/read-photos", None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.root("PUT", "/users/bob/attached-policies/read-photos", None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.root(
            "PUT",
            "/users/bob/policies/inline1",
            Some(json!({"document": doc.to_string()}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.root(
            "PUT",
            "/groups/devs/policies/inline2",
            Some(json!({"document": doc}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, u) = f.root("GET", "/users/bob", None).await;
    assert_eq!(u["attached_policies"][0], "read-photos");
    assert_eq!(u["inline_policies"][0], "inline1");
    let v2 = allow("s3:*", "arn:aws:s3:::photos/*");
    let (st, p) = f
        .root(
            "PUT",
            "/policies/read-photos",
            Some(json!({"document": v2})),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(p["version"], 2);
    assert_eq!(
        f.root("DELETE", "/users/bob/attached-policies/read-photos", None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.root("DELETE", "/groups/devs/attached-policies/read-photos", None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.root("DELETE", "/users/bob/policies/inline1", None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.root("DELETE", "/groups/devs/policies/inline2", None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.root("DELETE", "/groups/devs/members/bob", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.root("DELETE", "/policies/read-photos", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.root("DELETE", "/groups/devs", None).await.0,
        StatusCode::OK
    );

    let trust = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/bob"},"Action":"sts:AssumeRole"}]});
    let (st, r) = f
        .root(
            "POST",
            "/roles",
            Some(json!({"name":"ci","trust_policy":trust,"max_session_secs":3600})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{r}");
    assert_eq!(r["max_session_secs"], 3600);
    assert_eq!(
        f.root(
            "PUT",
            "/roles/ci/trust-policy",
            Some(json!({"document": trust}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.root(
            "PUT",
            "/roles/ci/policies/p",
            Some(json!({"document": doc}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, roles) = f.root("GET", "/roles", None).await;
    assert_eq!(roles["items"][0]["name"], "ci");

    let bob = f.store.principal_for_user("bob").await.unwrap().unwrap();
    let s = f
        .store
        .get_session_token(&bob, std::time::Duration::from_secs(900))
        .await
        .unwrap();
    let (_, l) = f.root("GET", "/sessions", None).await;
    assert_eq!(l["items"][0]["principal"], "user:bob");
    assert!(!l.to_string().contains(s.session_token.expose()));
    assert!(!l.to_string().contains(s.secret_access_key.expose()));
    assert_eq!(
        f.root("DELETE", &format!("/sessions/{}", s.access_key_id), None)
            .await
            .0,
        StatusCode::OK
    );
    assert!(f.store.lookup(&s.access_key_id).await.unwrap().is_none());
    assert_eq!(
        f.root("DELETE", "/sessions/NOPE", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.root("POST", "/sessions/purge-expired", None).await.1["purged"],
        0
    );
    assert_eq!(
        f.root("DELETE", "/roles/ci/policies/p", None).await.0,
        StatusCode::OK
    );
    assert_eq!(f.root("DELETE", "/roles/ci", None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn service_account_and_root_rotation() {
    let f = fx().await;
    let (st, v) = f
        .root(
            "POST",
            "/service-accounts",
            Some(json!({"name":"backup","bucket":"photos","read_only":true})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let ak = v["access_key_id"].as_str().unwrap();
    let cred = f.store.lookup(ak).await.unwrap().unwrap();
    let ctx = cairn_auth::ConditionContext::new();
    let engine = cairn_auth::AuthzEngine::new();
    assert!(
        engine
            .authorize(
                Some(&cred.principal),
                "s3:GetObject",
                "arn:aws:s3:::photos/x",
                &ctx,
                None
            )
            .is_allowed()
    );
    assert!(
        !engine
            .authorize(
                Some(&cred.principal),
                "s3:PutObject",
                "arn:aws:s3:::photos/x",
                &ctx,
                None
            )
            .is_allowed()
    );
    assert!(
        !engine
            .authorize(
                Some(&cred.principal),
                "s3:GetObject",
                "arn:aws:s3:::other/x",
                &ctx,
                None
            )
            .is_allowed()
    );

    let (st, v) = f.root("POST", "/root/rotate", None).await;
    assert_eq!(st, StatusCode::CREATED);
    let (nak, nsk) = (
        v["access_key_id"].as_str().unwrap(),
        v["secret_access_key"].as_str().unwrap(),
    );
    assert_eq!(
        f.root("GET", "/users", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.call(nak, nsk, "GET", "/users", None).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn buckets_trash_pitr_passthrough() {
    let f = fx().await;
    let (st, v) = f.root("GET", "/buckets", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    let (_, v) = f.root("GET", "/buckets/photos", None).await;
    assert_eq!(v["versioning"], "Enabled");
    assert_eq!(v["object_lock"]["enabled"], false);
    assert_eq!(
        f.root("GET", "/buckets/nope", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.root(
            "PUT",
            "/buckets/photos/quota",
            Some(json!({"quota_bytes": 1024}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.engine.get_bucket("photos").await.unwrap().quota_bytes,
        Some(1024)
    );
    assert_eq!(
        f.root(
            "PUT",
            "/buckets/photos/retention",
            Some(json!({"trash_days": 7}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.root("GET", "/buckets/photos/retention", None).await.1["trash_days"],
        7
    );

    let (_, v) = f.root("GET", "/trash?bucket=photos&prefix=a", None).await;
    assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        f.root("GET", "/trash?deleted_after=yesterday", None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (st, v) = f
        .root(
            "POST",
            "/trash/restore",
            Some(json!({"bucket":"photos","key":"a.jpg"})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["version_id"], "v1");
    let (st, v) = f
        .root("POST", "/trash/purge", Some(json!({"bucket":"photos"})))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(v["error"]["message"].as_str().unwrap().contains("confirm"));
    let (st, v) = f
        .root(
            "POST",
            "/trash/purge",
            Some(json!({"bucket":"photos","confirm":true})),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v, json!({"purged": 1, "bytes": 20}));
    let (st, v) = f
        .root(
            "POST",
            "/trash/restore-bucket",
            Some(json!({"bucket_id":"b2","as_name":"old2"})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["name"], "old2");

    let (st, v) = f
        .root(
            "POST",
            "/pitr/restore",
            Some(json!({"bucket":"photos","as_of":"2026-11-01T00:00:00Z","dry_run":true})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["dry_run"], true);
    assert_eq!(
        f.root(
            "POST",
            "/pitr/restore",
            Some(json!({"bucket":"photos","as_of":"nope"}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (st, _) = f
        .root(
            "GET",
            "/pitr/diff?bucket=photos&from=2026-11-01T00:00:00Z",
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let (_, v) = f.root("GET", "/info", None).await;
    assert_eq!(v["buckets"], 2);
}

#[tokio::test]
async fn oversized_body_rejected() {
    let f = fx().await;
    let big = json!({"name": "x".repeat(MAX_BODY_TEST)});
    let (st, v) = f.root("POST", "/users", Some(big)).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(v["error"]["code"], "PayloadTooLarge");
}

const MAX_BODY_TEST: usize = crate::api::MAX_BODY + 10;

#[tokio::test]
async fn cli_end_to_end_over_loopback() {
    let f = fx().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = f.app();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let endpoint = format!("http://{addr}");
    let run = |args: &[&str]| {
        let mut full = vec![
            "admin",
            "--endpoint",
            &endpoint,
            "--access-key",
            ROOT_AK,
            "--secret-key",
            ROOT_SK,
        ];
        full.extend_from_slice(args);
        let m = cli::cli().try_get_matches_from(full).unwrap();
        async move {
            let c = cli::client_from_matches(&m)?;
            let mut out = String::new();
            cli::run_to(&m, &c, &mut out).await.map(|_| out)
        }
    };
    let out = run(&["user", "add", "carol"]).await.unwrap();
    assert!(
        out.contains("arn:aws:iam::000000000000:user/carol"),
        "{out}"
    );
    let out = run(&["--json", "key", "create", "carol"]).await.unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["secret_access_key"].as_str().unwrap().len(), 40);
    let out = run(&["key", "ls", "--user", "carol"]).await.unwrap();
    assert!(out.starts_with("ACCESS_KEY_ID"), "{out}");
    assert!(!out.contains(v["secret_access_key"].as_str().unwrap()));
    let out = run(&["user", "ls"]).await.unwrap();
    assert!(out.lines().nth(1).unwrap().starts_with("carol"), "{out}");
    let dir = tempfile_dir();
    let pf = dir.join("p.json");
    std::fs::write(&pf, allow("s3:GetObject", "*").to_string()).unwrap();
    assert_eq!(
        run(&["policy", "create", "ro", pf.to_str().unwrap()])
            .await
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .next(),
        Some("arn")
    );
    assert_eq!(
        run(&["user", "attach", "carol", "ro"]).await.unwrap(),
        "ok\n"
    );
    assert_eq!(
        run(&[
            "user",
            "policy",
            "put",
            "carol",
            "inl",
            pf.to_str().unwrap()
        ])
        .await
        .unwrap(),
        "ok\n"
    );
    assert_eq!(
        run(&["group", "add", "g1"]).await.unwrap().lines().count(),
        5
    );
    assert_eq!(
        run(&["group", "add-user", "g1", "carol"]).await.unwrap(),
        "ok\n"
    );
    let out = run(&["bucket", "ls"]).await.unwrap();
    assert!(
        out.contains("photos") && out.contains("QUOTA_BYTES"),
        "{out}"
    );
    assert_eq!(
        run(&["bucket", "quota", "photos", "10GiB"]).await.unwrap(),
        "ok\n"
    );
    assert_eq!(
        f.engine.get_bucket("photos").await.unwrap().quota_bytes,
        Some(10 << 30)
    );
    let out = run(&["--json", "bucket", "lock", "photos"]).await.unwrap();
    assert!(out.contains("\"enabled\": false"));
    let out = run(&["trash", "ls", "--bucket", "photos"]).await.unwrap();
    assert!(out.contains("a.jpg") && out.contains("b.jpg"), "{out}");
    let err = run(&["trash", "purge", "--bucket", "photos"])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("--yes"));
    let out = run(&[
        "--json", "trash", "purge", "--bucket", "photos", "--key", "a.jpg", "--yes",
    ])
    .await
    .unwrap();
    assert!(out.contains("\"purged\": 1"));
    let out = run(&[
        "pitr",
        "restore",
        "--bucket",
        "photos",
        "--as-of",
        "2026-11-01T00:00:00Z",
        "--dry-run",
    ])
    .await
    .unwrap();
    assert!(out.contains("dry_run") && out.contains("true"), "{out}");
    let err = run(&["user", "info", "nobody"]).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("NotFound") && msg.contains("HTTP 404"),
        "{msg}"
    );
    // bad secret
    let m = cli::cli()
        .try_get_matches_from([
            "admin",
            "--endpoint",
            &endpoint,
            "--access-key",
            ROOT_AK,
            "--secret-key",
            "nope",
            "whoami",
        ])
        .unwrap();
    let c = cli::client_from_matches(&m).unwrap();
    let e = cli::run_to(&m, &c, &mut String::new()).await.unwrap_err();
    assert!(e.to_string().contains("SignatureDoesNotMatch"), "{e}");
    let _ = std::fs::remove_dir_all(dir);
}

fn tempfile_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "cairn-admin-test-{}",
        uuid::Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn size_parsing_and_cli_tree() {
    assert_eq!(cli::parse_size("10").unwrap(), 10);
    assert_eq!(cli::parse_size("5MiB").unwrap(), 5 << 20);
    assert_eq!(cli::parse_size("2g").unwrap(), 2 << 30);
    assert!(cli::parse_size("5X").is_err());
    let cmd = cli::cli();
    let names: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
    for want in [
        "user", "key", "sa", "group", "policy", "role", "session", "bucket", "trash", "pitr",
    ] {
        assert!(names.contains(&want), "missing {want}");
    }
    cmd.debug_assert();
}

#[derive(Clone, Default)]
struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

/// Process-wide subscriber that records nothing but answers `sometimes` for every callsite, so a
/// callsite first hit by a concurrent test is never cached as disabled for a thread-local capture.
struct Quiet;

impl tracing::Subscriber for Quiet {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// B4: secrets, session tokens and Authorization signatures never reach the logs, even at
/// TRACE, across key creation, root rotation, STS issuance and S3 access checks.
#[tokio::test(flavor = "current_thread")]
async fn secrets_never_logged() {
    let _ = tracing::subscriber::set_global_default(Quiet);
    let cap = Capture::default();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(cap.clone())
        .with_ansi(false)
        .finish();
    let _g = tracing::subscriber::set_default(sub);

    let f = fx().await;
    tracing::callsite::rebuild_interest_cache();
    let mut secrets: Vec<String> = vec![ROOT_SK.to_string()];
    let req = signed(
        ROOT_AK,
        ROOT_SK,
        "POST",
        "/users",
        Some(json!({"name":"dana"})),
    );
    let sig = req.headers()["authorization"]
        .to_str()
        .unwrap()
        .rsplit('=')
        .next()
        .unwrap()
        .to_string();
    secrets.push(sig);
    f.send(req).await;
    let (_, k) = f.root("POST", "/users/dana/access-keys", None).await;
    secrets.push(k["secret_access_key"].as_str().unwrap().to_string());
    f.root(
        "PUT",
        "/users/dana/policies/sts",
        Some(json!({"document": allow("*", "*")})),
    )
    .await;
    let trust = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/dana"},"Action":"sts:AssumeRole"}]});
    f.root(
        "POST",
        "/roles",
        Some(json!({"name":"r","trust_policy":trust})),
    )
    .await;

    // STS AssumeRole over HTTP
    let body = "Action=AssumeRole&RoleArn=r&RoleSessionName=s1";
    let hs = vec![
        ("host".to_string(), "h".to_string()),
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
    ];
    let ak = k["access_key_id"].as_str().unwrap();
    let sk = SecretString::new(k["secret_access_key"].as_str().unwrap());
    let add = sigv4::sign_headers(
        "POST",
        "/",
        "",
        &hs,
        body.as_bytes(),
        ak,
        &sk,
        None,
        Ts::now(),
        "us-east-1",
        "sts",
    );
    let mut b = Request::post("/");
    for (k, v) in hs.iter().chain(add.iter()) {
        b = b.header(k, v);
    }
    let resp = cairn_auth::sts::router(cairn_auth::sts::StsState::new(f.store.clone()))
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let xml = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let grab = |t: &str| {
        xml.split(&format!("<{t}>"))
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_string()
    };
    let (sts_ak, sts_sk, tok) = (
        grab("AccessKeyId"),
        grab("SecretAccessKey"),
        grab("SessionToken"),
    );
    secrets.push(sts_sk);
    secrets.push(tok.clone());

    // S3 access checks, allowed and denied, with and without the token
    let access = cairn_auth::CairnS3Access::new(
        f.store.clone(),
        Arc::new(cairn_auth::MemoryBucketAuthz::new()),
    );
    let uri: http::Uri = "/b/k".parse().unwrap();
    let mut h = http::HeaderMap::new();
    h.insert("x-amz-security-token", tok.parse().unwrap());
    for (headers, op) in [
        (&h, "GetObject"),
        (&http::HeaderMap::new(), "GetObject"),
        (&h, "SelectObjectContent"),
    ] {
        let _ = access
            .authorize(&cairn_auth::s3s_bridge::S3RequestView {
                op,
                access_key: Some(&sts_ak),
                bucket: Some("b"),
                key: Some("k"),
                uri: &uri,
                headers,
                meta: None,
            })
            .await;
    }
    let (_, rot) = f.root("POST", "/root/rotate", None).await;
    secrets.push(rot["secret_access_key"].as_str().unwrap().to_string());

    let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("access key created"),
        "capture is working: {logs}"
    );
    assert!(logs.contains("root credentials rotated"));
    for s in &secrets {
        assert!(!logs.contains(s.as_str()), "secret leaked into logs");
    }
}
