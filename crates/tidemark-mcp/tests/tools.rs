//! tidemark-mcp end to end: an in-process rmcp client against a real `TidemarkEngine` in a temp dir,
//! restricted IAM policies, allow / deny cases and `tidemark:McpTool` conditions; plus the
//! streamable-HTTP transport with bearer and SigV4 authentication.

use http_body_util::BodyExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};
use std::sync::Arc;
use tidemark_auth::{
    BucketAuthz, CredentialStore, MasterKey, MemoryBackend, MemoryBucketAuthz, SecretString,
};
use tidemark_core::PrincipalId;
use tidemark_engine::types::{ObjectMeta, PutObjectReq, body_from_bytes};
use tidemark_engine::{EngineConfig, TidemarkEngine};
use tidemark_mcp::{
    McpConfig, McpState, StaticCredentials, TidemarkMcp, http_router, serve_transport,
};
use tower::ServiceExt as _;

const AGENT: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"},
 {"Effect":"Allow","Action":["s3:ListBucket","s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::docs","arn:aws:s3:::docs/*"]},
 {"Effect":"Allow","Action":["s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::docs/inbox/*"},
 {"Effect":"Allow","Action":["tidemark:ListTrash","tidemark:PitrDiff","tidemark:Pitr"],"Resource":"arn:aws:s3:::docs"},
 {"Effect":"Allow","Action":"tidemark:TimeTravel","Resource":["arn:aws:s3:::docs","arn:aws:s3:::docs/inbox/*"]},
 {"Effect":"Allow","Action":"tidemark:Restore","Resource":"arn:aws:s3:::docs/inbox/*"},
 {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::docs/private/*"},
 {"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"tidemark:McpTool":"pitr_restore"}}}
]}"#;

/// Reads only through `head_object` / `list_objects`: `get_object` is denied by tool name.
const HEAD_ONLY: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::docs","arn:aws:s3:::docs/*"],
  "Condition":{"StringEquals":{"tidemark:McpTool":["head_object","list_objects"]}}}
]}"#;

struct Fx {
    _dir: tempfile::TempDir,
    engine: TidemarkEngine,
    store: Arc<CredentialStore>,
    buckets: Arc<MemoryBucketAuthz>,
    root: StaticCredentials,
    agent: StaticCredentials,
    head_only: StaticCredentials,
}

impl Fx {
    fn state(&self) -> McpState {
        McpState::new(
            self.engine.clone(),
            self.store.clone(),
            self.buckets.clone(),
        )
    }
}

async fn put(e: &TidemarkEngine, b: &str, k: &str, data: &[u8], ct: &str) {
    e.put_object(PutObjectReq {
        bucket: b.into(),
        key: k.into(),
        body: body_from_bytes(data.to_vec()),
        content_length: Some(data.len() as u64),
        content_md5: None,
        checksum: Default::default(),
        meta: ObjectMeta {
            content_type: Some(ct.into()),
            ..Default::default()
        },
        tags: Default::default(),
        conditions: Default::default(),
        owner: PrincipalId::root(),
    })
    .await
    .unwrap();
}

async fn user(store: &CredentialStore, name: &str, policy: &str) -> StaticCredentials {
    store.create_user(name).await.unwrap();
    store.put_user_policy(name, "p", policy).await.unwrap();
    let k = store
        .create_access_key(name, Default::default())
        .await
        .unwrap();
    StaticCredentials::new(&k.access_key_id, k.secret_key.expose(), None)
}

async fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let engine = TidemarkEngine::open(dir.path(), EngineConfig::default()).unwrap();
    for b in ["docs", "secret"] {
        engine
            .create_bucket(b, &PrincipalId::root(), false, None)
            .await
            .unwrap();
    }
    put(&engine, "docs", "readme.md", b"hello", "text/markdown").await;
    put(&engine, "docs", "private/key.txt", b"nope", "text/plain").await;
    put(
        &engine,
        "docs",
        "bin.dat",
        &[0, 159, 146, 150],
        "application/octet-stream",
    )
    .await;
    put(&engine, "secret", "s.txt", b"classified", "text/plain").await;
    let store = Arc::new(CredentialStore::new(
        Arc::new(MemoryBackend::new()),
        MasterKey::new([3; 32]),
    ));
    store
        .ensure_root("ROOTAKID", &SecretString::new("rootsecret"))
        .await
        .unwrap();
    let agent = user(&store, "agent", AGENT).await;
    let head_only = user(&store, "headonly", HEAD_ONLY).await;
    Fx {
        _dir: dir,
        engine,
        store,
        buckets: Arc::new(MemoryBucketAuthz::new()),
        root: StaticCredentials::new("ROOTAKID", "rootsecret", None),
        agent,
        head_only,
    }
}

type Client = RunningService<RoleClient, ()>;

async fn connect(state: McpState, creds: StaticCredentials) -> Client {
    let (s, c) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = serve_transport(state, creds, s).await;
    });
    ().serve(c).await.unwrap()
}

async fn call(c: &Client, tool: &'static str, args: Value) -> CallToolResult {
    c.call_tool(CallToolRequestParams::new(tool).with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap()
}

/// Structured result of a successful call.
async fn ok(c: &Client, tool: &'static str, args: Value) -> Value {
    let r = call(c, tool, args).await;
    assert_eq!(
        r.is_error,
        Some(false),
        "{tool} failed: {:?}",
        r.structured_content
    );
    r.structured_content.unwrap()
}

/// Error code of a failed call.
async fn err(c: &Client, tool: &'static str, args: Value) -> String {
    let r = call(c, tool, args).await;
    assert_eq!(
        r.is_error,
        Some(true),
        "{tool} unexpectedly succeeded: {:?}",
        r.structured_content
    );
    r.structured_content.unwrap()["error"]
        .as_str()
        .unwrap()
        .to_string()
}

fn keys(v: &Value, field: &str) -> Vec<String> {
    v[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["key"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn tools_are_listed_with_json_schemas() {
    let f = fx().await;
    let c = connect(f.state(), f.agent.clone()).await;
    let tools = c.list_all_tools().await.unwrap();
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    let mut expected = vec![
        "bucket_info",
        "copy_object",
        "delete_object",
        "get_object",
        "head_object",
        "list_buckets",
        "list_objects",
        "pitr_diff",
        "pitr_head_at",
        "pitr_restore",
        "put_object",
        "search",
        "trash_list",
        "trash_restore",
    ];
    expected.sort();
    assert_eq!(names, expected);
    assert_eq!(TidemarkMcp::tool_names().len(), expected.len());
    let get = tools.iter().find(|t| t.name == "get_object").unwrap();
    let schema = serde_json::to_value(&*get.input_schema).unwrap();
    assert_eq!(schema["type"], "object");
    assert!(schema["properties"]["bucket"].is_object());
    let req: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(req.contains(&"bucket") && req.contains(&"key"));
    for t in &tools {
        assert!(
            t.description.as_ref().is_some_and(|d| !d.is_empty()),
            "{}",
            t.name
        );
    }
}

#[tokio::test]
async fn restricted_agent_reads_and_lists_only_what_policy_allows() {
    let f = fx().await;
    let c = connect(f.state(), f.agent.clone()).await;
    // list_buckets never leaks buckets the caller cannot browse.
    let b = ok(&c, "list_buckets", json!({})).await;
    let names: Vec<&str> = b["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["docs"]);
    let l = ok(&c, "list_objects", json!({"bucket": "docs"})).await;
    assert_eq!(
        keys(&l, "objects"),
        vec!["bin.dat", "private/key.txt", "readme.md"]
    );
    let l = ok(
        &c,
        "list_objects",
        json!({"bucket": "docs", "delimiter": "/", "max_keys": 1}),
    )
    .await;
    assert_eq!(l["truncated"], true);
    assert_eq!(l["next_start_after"], "bin.dat");
    assert_eq!(
        err(&c, "list_objects", json!({"bucket": "secret"})).await,
        "AccessDenied"
    );
    // Denied before existence is checked: no NoSuchBucket oracle.
    assert_eq!(
        err(&c, "list_objects", json!({"bucket": "nope"})).await,
        "AccessDenied"
    );
    let g = ok(
        &c,
        "get_object",
        json!({"bucket": "docs", "key": "readme.md"}),
    )
    .await;
    assert_eq!(g["content"], "hello");
    assert_eq!(g["encoding"], "text");
    assert_eq!(g["content_type"], "text/markdown");
    assert_eq!(g["truncated"], false);
    let g = ok(
        &c,
        "get_object",
        json!({"bucket": "docs", "key": "readme.md", "range": "1-3"}),
    )
    .await;
    assert_eq!(g["content"], "ell");
    let g = ok(
        &c,
        "get_object",
        json!({"bucket": "docs", "key": "bin.dat"}),
    )
    .await;
    assert_eq!(g["encoding"], "base64");
    assert_eq!(g["content_base64"], "AJ+Slg==");
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "docs", "key": "bin.dat", "mode": "text"})
        )
        .await,
        "InvalidArgument"
    );
    let g = ok(
        &c,
        "get_object",
        json!({"bucket": "docs", "key": "readme.md", "mode": "base64"}),
    )
    .await;
    assert_eq!(g["content_base64"], "aGVsbG8=");
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "docs", "key": "private/key.txt"})
        )
        .await,
        "AccessDenied"
    );
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "secret", "key": "s.txt"})
        )
        .await,
        "AccessDenied"
    );
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "docs", "key": "missing"})
        )
        .await,
        "NoSuchKey"
    );
    let h = ok(
        &c,
        "head_object",
        json!({"bucket": "docs", "key": "readme.md"}),
    )
    .await;
    assert_eq!(h["size"], 5);
    assert_eq!(
        err(
            &c,
            "head_object",
            json!({"bucket": "secret", "key": "s.txt"})
        )
        .await,
        "AccessDenied"
    );
    let s = ok(&c, "search", json!({"bucket": "docs", "query": "READ"})).await;
    assert_eq!(keys(&s, "results"), vec!["readme.md"]);
    assert_eq!(s["complete"], true);
    let s = ok(
        &c,
        "search",
        json!({"bucket": "docs", "content_type": "text/", "max_size": 4}),
    )
    .await;
    assert_eq!(keys(&s, "results"), vec!["private/key.txt"]);
    assert_eq!(
        err(&c, "search", json!({"bucket": "secret"})).await,
        "AccessDenied"
    );
    let i = ok(&c, "bucket_info", json!({"bucket": "docs"})).await;
    assert_eq!(i["versioning"], "Off");
    assert!(i.get("tags").is_none(), "tags need s3:GetBucketTagging");
    assert_eq!(
        err(&c, "bucket_info", json!({"bucket": "secret"})).await,
        "AccessDenied"
    );
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "docs", "key": "readme.md", "as_of": "yesterday"})
        )
        .await,
        "InvalidArgument"
    );
}

#[tokio::test]
async fn restricted_agent_writes_deletes_and_recovers() {
    let f = fx().await;
    let c = connect(f.state(), f.agent.clone()).await;
    let before = tidemark_core::Ts::now().to_rfc3339();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let p = ok(
        &c,
        "put_object",
        json!({"bucket": "docs", "key": "inbox/a.txt", "content": "v1",
        "metadata": {"source": "agent"}, "tags": {"kind": "note"}}),
    )
    .await;
    assert_eq!(p["size"], 2);
    let h = ok(
        &c,
        "head_object",
        json!({"bucket": "docs", "key": "inbox/a.txt"}),
    )
    .await;
    assert_eq!(h["metadata"]["source"], "agent");
    assert_eq!(h["tag_count"], 1);
    assert_eq!(h["content_type"], "text/plain; charset=utf-8");
    ok(
        &c,
        "put_object",
        json!({"bucket": "docs", "key": "inbox/b.bin", "content_base64": "AAEC"}),
    )
    .await;
    assert_eq!(
        err(
            &c,
            "put_object",
            json!({"bucket": "docs", "key": "readme.md", "content": "x"})
        )
        .await,
        "AccessDenied"
    );
    assert_eq!(
        err(
            &c,
            "put_object",
            json!({"bucket": "secret", "key": "inbox/x", "content": "x"})
        )
        .await,
        "AccessDenied"
    );
    assert_eq!(
        err(
            &c,
            "put_object",
            json!({"bucket": "docs", "key": "inbox/x", "content": "a", "content_base64": "YQ=="})
        )
        .await,
        "InvalidArgument"
    );
    // Copy needs read on the source and write on the destination.
    ok(
        &c,
        "copy_object",
        json!({"source_bucket": "docs", "source_key": "readme.md",
        "bucket": "docs", "key": "inbox/copy.md"}),
    )
    .await;
    let g = ok(
        &c,
        "get_object",
        json!({"bucket": "docs", "key": "inbox/copy.md"}),
    )
    .await;
    assert_eq!(g["content"], "hello");
    assert_eq!(
        err(
            &c,
            "copy_object",
            json!({"source_bucket": "secret", "source_key": "s.txt",
            "bucket": "docs", "key": "inbox/stolen"})
        )
        .await,
        "AccessDenied"
    );
    assert_eq!(
        err(
            &c,
            "copy_object",
            json!({"source_bucket": "docs", "source_key": "readme.md",
            "bucket": "docs", "key": "elsewhere"})
        )
        .await,
        "AccessDenied"
    );
    // Delete, find it in the trash, restore it.
    ok(
        &c,
        "delete_object",
        json!({"bucket": "docs", "key": "inbox/a.txt"}),
    )
    .await;
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "docs", "key": "inbox/a.txt"})
        )
        .await,
        "NoSuchKey"
    );
    assert_eq!(
        err(
            &c,
            "delete_object",
            json!({"bucket": "docs", "key": "readme.md"})
        )
        .await,
        "AccessDenied"
    );
    let t = ok(
        &c,
        "trash_list",
        json!({"bucket": "docs", "prefix": "inbox/"}),
    )
    .await;
    assert_eq!(keys(&t, "items"), vec!["inbox/a.txt"]);
    let vid = t["items"][0]["version_id"].as_str().unwrap().to_string();
    assert_eq!(
        err(&c, "trash_list", json!({"bucket": "secret"})).await,
        "AccessDenied"
    );
    ok(
        &c,
        "trash_restore",
        json!({"bucket": "docs", "key": "inbox/a.txt", "version_id": vid}),
    )
    .await;
    let g = ok(
        &c,
        "get_object",
        json!({"bucket": "docs", "key": "inbox/a.txt"}),
    )
    .await;
    assert_eq!(g["content"], "v1");
    assert_eq!(
        err(
            &c,
            "trash_restore",
            json!({"bucket": "docs", "key": "readme.md"})
        )
        .await,
        "AccessDenied"
    );
    // Time travel: the key did not exist before the first put.
    let h = ok(
        &c,
        "pitr_head_at",
        json!({"bucket": "docs", "key": "inbox/a.txt", "at": before}),
    )
    .await;
    assert_eq!(h["exists"], false);
    let l = ok(
        &c,
        "list_objects",
        json!({"bucket": "docs", "prefix": "inbox/", "as_of": before}),
    )
    .await;
    assert!(keys(&l, "objects").is_empty());
    let d = ok(&c, "pitr_diff", json!({"bucket": "docs", "at": before})).await;
    let changed: Vec<&str> = d["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["key"].as_str().unwrap())
        .collect();
    assert_eq!(changed, vec!["inbox/a.txt", "inbox/b.bin", "inbox/copy.md"]);
    assert_eq!(
        err(
            &c,
            "pitr_head_at",
            json!({"bucket": "docs", "key": "readme.md", "at": before})
        )
        .await,
        "AccessDenied",
        "tidemark:TimeTravel is only granted on inbox/*"
    );
    // tidemark:Pitr is allowed, but a Deny on tidemark:McpTool = pitr_restore blocks the tool.
    assert_eq!(
        err(&c, "pitr_restore", json!({"bucket": "docs", "at": before})).await,
        "AccessDenied"
    );
}

#[tokio::test]
async fn mcp_tool_condition_selects_tools() {
    let f = fx().await;
    let c = connect(f.state(), f.head_only.clone()).await;
    ok(
        &c,
        "head_object",
        json!({"bucket": "docs", "key": "readme.md"}),
    )
    .await;
    ok(&c, "list_objects", json!({"bucket": "docs"})).await;
    // Time travel additionally needs tidemark:TimeTravel.
    let at = tidemark_core::Ts::now().to_rfc3339();
    assert_eq!(
        err(
            &c,
            "head_object",
            json!({"bucket": "docs", "key": "readme.md", "as_of": at})
        )
        .await,
        "AccessDenied"
    );
    assert_eq!(
        err(&c, "list_objects", json!({"bucket": "docs", "as_of": at})).await,
        "AccessDenied"
    );
    // Same action (s3:GetObject / s3:ListBucket), different tool: denied.
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "docs", "key": "readme.md"})
        )
        .await,
        "AccessDenied"
    );
    assert_eq!(
        err(&c, "search", json!({"bucket": "docs"})).await,
        "AccessDenied"
    );
    assert_eq!(err(&c, "list_buckets", json!({})).await, "AccessDenied");
}

#[tokio::test]
async fn bucket_policy_applies_to_mcp_calls() {
    let f = fx().await;
    let c = connect(f.state(), f.head_only.clone()).await;
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "secret", "key": "s.txt"})
        )
        .await,
        "AccessDenied"
    );
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/headonly"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::secret/*","Condition":{"StringEquals":{"tidemark:McpTool":"get_object"}}}]}"#;
    f.buckets.set(
        "secret",
        BucketAuthz {
            policy: Some(policy.parse().unwrap()),
            ..Default::default()
        },
    );
    let g = ok(
        &c,
        "get_object",
        json!({"bucket": "secret", "key": "s.txt"}),
    )
    .await;
    assert_eq!(g["content"], "classified");
    assert_eq!(
        err(
            &c,
            "head_object",
            json!({"bucket": "secret", "key": "s.txt"})
        )
        .await,
        "AccessDenied"
    );
}

#[tokio::test]
async fn get_object_is_capped_and_put_object_is_limited() {
    let f = fx().await;
    let st = f.state().with_config(McpConfig {
        max_get_bytes: 4,
        max_put_bytes: 3,
        ..Default::default()
    });
    let c = connect(st, f.root.clone()).await;
    let g = ok(
        &c,
        "get_object",
        json!({"bucket": "docs", "key": "readme.md"}),
    )
    .await;
    assert_eq!(g["truncated"], true);
    assert_eq!(g["content"], "hell");
    assert_eq!(g["size"], 5);
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "docs", "key": "readme.md", "range": "0-4"})
        )
        .await,
        "InvalidArgument"
    );
    assert_eq!(
        err(
            &c,
            "put_object",
            json!({"bucket": "docs", "key": "big", "content": "abcd"})
        )
        .await,
        "EntityTooLarge"
    );
}

#[tokio::test]
async fn pitr_restore_dry_run_confirm_and_apply() {
    let f = fx().await;
    let c = connect(f.state(), f.root.clone()).await;
    let pause = || tokio::time::sleep(std::time::Duration::from_millis(5));
    put(&f.engine, "docs", "p/a.txt", b"old-a", "text/plain").await;
    put(&f.engine, "docs", "p/b.txt", b"old-b", "text/plain").await;
    pause().await;
    let at = tidemark_core::Ts::now().to_rfc3339();
    pause().await;
    put(&f.engine, "docs", "p/a.txt", b"new-a", "text/plain").await;
    f.engine
        .delete_object("docs", "p/b.txt", None, &PrincipalId::root())
        .await
        .unwrap();
    put(&f.engine, "docs", "p/c.txt", b"new-c", "text/plain").await;
    let d = ok(
        &c,
        "pitr_restore",
        json!({"bucket": "docs", "at": at, "prefix": "p/"}),
    )
    .await;
    assert_eq!(d["dry_run"], true);
    let acts: Vec<(String, String)> = d["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["key"].as_str().unwrap().into(),
                e["action"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        acts,
        vec![
            ("p/a.txt".into(), "revert".into()),
            ("p/b.txt".into(), "recreate".into()),
            ("p/c.txt".into(), "remove".into())
        ]
    );
    assert_eq!(
        err(
            &c,
            "pitr_restore",
            json!({"bucket": "docs", "at": at, "prefix": "p/", "dry_run": false})
        )
        .await,
        "InvalidArgument"
    );
    let r = ok(
        &c,
        "pitr_restore",
        json!({"bucket": "docs", "at": at, "prefix": "p/",
        "dry_run": false, "confirm": true}),
    )
    .await;
    assert!(
        r["applied"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["ok"] == true),
        "{r}"
    );
    let get = |k: &'static str| ok(&c, "get_object", json!({"bucket": "docs", "key": k}));
    assert_eq!(get("p/a.txt").await["content"], "old-a");
    assert_eq!(get("p/b.txt").await["content"], "old-b");
    assert_eq!(
        err(
            &c,
            "get_object",
            json!({"bucket": "docs", "key": "p/c.txt"})
        )
        .await,
        "NoSuchKey"
    );
    let d = ok(
        &c,
        "pitr_diff",
        json!({"bucket": "docs", "at": at, "prefix": "p/"}),
    )
    .await;
    assert!(d["changes"].as_array().unwrap().is_empty(), "{d}");
}

#[tokio::test]
async fn stdio_binding_reverifies_credentials_per_call() {
    let f = fx().await;
    let bad = StaticCredentials::new(&f.agent.access_key_id, "wrong", None);
    assert!(TidemarkMcp::with_credentials(f.state(), bad).await.is_err());
    let c = connect(f.state(), f.agent.clone()).await;
    ok(&c, "list_objects", json!({"bucket": "docs"})).await;
    f.store
        .revoke_access_key(&f.agent.access_key_id)
        .await
        .unwrap();
    assert_eq!(
        err(&c, "list_objects", json!({"bucket": "docs"})).await,
        "InvalidAccessKeyId"
    );
}

// ------------------------------------------------------------------ HTTP transport

const ACCEPT: &str = "application/json, text/event-stream";

fn rpc(id: u64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

fn init() -> String {
    rpc(
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "test", "version": "0"}}),
    )
}

async fn post(
    app: &axum::Router,
    auth: Option<&str>,
    session: Option<&str>,
    body: String,
    extra: &[(String, String)],
) -> (http::StatusCode, Option<String>, String) {
    let mut b = http::Request::post("/_tidemark/mcp")
        .header("host", "localhost:9000")
        .header("content-type", "application/json")
        .header("accept", ACCEPT);
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    if let Some(s) = session {
        b = b.header("mcp-session-id", s);
        b = b.header("mcp-protocol-version", "2025-06-18");
    }
    for (k, v) in extra {
        b = b.header(k, v);
    }
    let r = app
        .clone()
        .oneshot(b.body(axum::body::Body::from(body)).unwrap())
        .await
        .unwrap();
    let st = r.status();
    let sid = r
        .headers()
        .get("mcp-session-id")
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(10), r.into_body().collect())
        .await
        .expect("body timed out")
        .unwrap()
        .to_bytes();
    (st, sid, String::from_utf8_lossy(&bytes).into_owned())
}

/// The JSON-RPC message in a JSON or SSE response body.
fn message(body: &str) -> Value {
    if let Ok(v) = serde_json::from_str(body) {
        return v;
    }
    body.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .find(|v| v.get("id").is_some())
        .unwrap_or_else(|| panic!("no JSON-RPC message in {body}"))
}

async fn http_session(app: &axum::Router, auth: &str) -> String {
    let (st, sid, body) = post(app, Some(auth), None, init(), &[]).await;
    assert_eq!(st, http::StatusCode::OK, "{body}");
    let sid = sid.expect("session id");
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string();
    let (st, _, _) = post(app, Some(auth), Some(&sid), note, &[]).await;
    assert!(st.is_success());
    sid
}

fn bearer(c: &StaticCredentials) -> String {
    format!("Bearer {}:{}", c.access_key_id, c.secret.expose())
}

#[tokio::test]
async fn http_transport_authenticates_every_request() {
    let f = fx().await;
    let app = http_router(f.state());
    let (st, _, body) = post(&app, None, None, init(), &[]).await;
    assert_eq!(st, http::StatusCode::UNAUTHORIZED, "{body}");
    let (st, _, _) = post(&app, Some("Bearer TIDEMARKX:nope"), None, init(), &[]).await;
    assert_eq!(st, http::StatusCode::UNAUTHORIZED);
    let (st, _, _) = post(&app, Some("Bearer garbage"), None, init(), &[]).await;
    assert_eq!(st, http::StatusCode::UNAUTHORIZED);

    let agent = bearer(&f.agent);
    let sid = http_session(&app, &agent).await;
    let list = rpc(
        2,
        "tools/call",
        json!({"name": "list_buckets", "arguments": {}}),
    );
    let (st, _, body) = post(&app, Some(&agent), Some(&sid), list.clone(), &[]).await;
    assert_eq!(st, http::StatusCode::OK, "{body}");
    let m = message(&body);
    assert_eq!(
        m["result"]["structuredContent"]["buckets"][0]["name"], "docs",
        "{m}"
    );
    let get = rpc(
        3,
        "tools/call",
        json!({"name": "get_object",
        "arguments": {"bucket": "secret", "key": "s.txt"}}),
    );
    let (_, _, body) = post(&app, Some(&agent), Some(&sid), get.clone(), &[]).await;
    let m = message(&body);
    assert_eq!(m["result"]["isError"], true);
    assert_eq!(m["result"]["structuredContent"]["error"], "AccessDenied");
    // The session id is not a credential: a request without credentials is rejected.
    let (st, _, _) = post(&app, None, Some(&sid), list, &[]).await;
    assert_eq!(st, http::StatusCode::UNAUTHORIZED);
    // Each request runs as the credential it carries.
    let (_, _, body) = post(&app, Some(&bearer(&f.root)), Some(&sid), get, &[]).await;
    assert_eq!(
        message(&body)["result"]["structuredContent"]["content"],
        "classified"
    );

    // STS session credentials: Bearer ak:secret:token.
    let p = f.store.principal_for_user("agent").await.unwrap().unwrap();
    let t = f
        .store
        .get_session_token(&p, std::time::Duration::from_secs(900))
        .await
        .unwrap();
    let sts = format!(
        "Bearer {}:{}:{}",
        t.access_key_id,
        t.secret_access_key.expose(),
        t.session_token.expose()
    );
    http_session(&app, &sts).await;
    let no_token = format!(
        "Bearer {}:{}",
        t.access_key_id,
        t.secret_access_key.expose()
    );
    let (st, _, _) = post(&app, Some(&no_token), None, init(), &[]).await;
    assert_eq!(st, http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn http_transport_accepts_sigv4() {
    let f = fx().await;
    let app = http_router(f.state());
    let body = init();
    let hs = vec![
        ("host".to_string(), "localhost:9000".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
    ];
    let sign = |body: &str, secret: &str| {
        tidemark_auth::sigv4::sign_headers(
            "POST",
            "/_tidemark/mcp",
            "",
            &hs,
            body.as_bytes(),
            &f.agent.access_key_id,
            &SecretString::new(secret),
            None,
            tidemark_auth::Ts::now(),
            "us-east-1",
            "s3",
        )
    };
    let (st, sid, b) = post(
        &app,
        None,
        None,
        body.clone(),
        &sign(&body, f.agent.secret.expose()),
    )
    .await;
    assert_eq!(st, http::StatusCode::OK, "{b}");
    assert!(sid.is_some());
    let (st, _, _) = post(&app, None, None, body.clone(), &sign(&body, "wrong")).await;
    assert_eq!(st, http::StatusCode::UNAUTHORIZED);
    // Signature covers the body: tampering is rejected.
    let h = sign(&body, f.agent.secret.expose());
    let (st, _, _) = post(&app, None, None, body.replace("test", "evil"), &h).await;
    assert_eq!(st, http::StatusCode::UNAUTHORIZED);
}
