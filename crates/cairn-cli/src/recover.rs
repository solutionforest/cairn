//! `cairn trash …` and `cairn pitr …`: the one-command undo (DESIGN §0 claims 1 and 2).
//!
//! Without `--endpoint` they open the data directory directly (server stopped) and act as the
//! operator; with `--endpoint` they call the admin API of a running server, signed with the
//! given credentials and subject to its policies.

use anyhow::Context as _;
use cairn_admin::AdminEngine as _;
use cairn_admin::engine::{
    BucketSummary, PitrChange, PitrDiffQuery, PitrRequest, PitrResult, RestoreBucketRequest,
    RestoreRequest, RestoreResult, TrashEntry, TrashPage, TrashQuery,
};
use cairn_core::{Config, Ts};
use cairn_server::admin_engine::EngineAdmin;
use cairn_server::cairn_engine::CairnEngine;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::path::PathBuf;

/// How a recovery command reaches the store.
#[derive(clap::Args, Clone, Debug)]
pub struct Access {
    /// Path to `cairn.toml` (offline mode).
    #[arg(long, short, env = "CAIRN_CONFIG")]
    pub config: Option<PathBuf>,
    /// Data directory (offline mode; overrides the config).
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    /// Talk to a running server's admin API instead of opening the data directory.
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Access key id for `--endpoint`.
    #[arg(long, env = "CAIRN_ACCESS_KEY")]
    pub access_key: Option<String>,
    /// Secret key for `--endpoint`.
    #[arg(long, env = "CAIRN_SECRET_KEY", hide_env_values = true)]
    pub secret_key: Option<String>,
    /// Signing region for `--endpoint`.
    #[arg(long, env = "CAIRN_REGION", default_value = "us-east-1")]
    pub region: String,
    /// Print JSON.
    #[arg(long)]
    pub json: bool,
}

/// `cairn trash` subcommands.
#[derive(clap::Subcommand, Debug)]
pub enum TrashCmd {
    /// List soft-deleted and superseded versions, and trashed buckets.
    #[command(alias = "list")]
    Ls {
        #[command(flatten)]
        access: Access,
        /// Only this bucket.
        #[arg(long)]
        bucket: Option<String>,
        /// Only keys under this prefix.
        #[arg(long)]
        prefix: Option<String>,
    },
    /// Restore deleted objects (and, with `--all`, a deleted bucket) as they were.
    Restore {
        #[command(flatten)]
        access: Access,
        /// Bucket.
        #[arg(long)]
        bucket: String,
        /// Key to restore (newest hidden version unless `--version`).
        #[arg(long, conflicts_with = "all")]
        key: Option<String>,
        /// Version id to restore.
        #[arg(long, requires = "key")]
        version: Option<String>,
        /// Undelete everything: bring the bucket back if it was deleted (replaying every
        /// version of every key), then restore the newest hidden version of every key (under
        /// `--prefix`) that still has no live version.
        #[arg(long)]
        all: bool,
        /// Limit `--all` to keys under this prefix.
        #[arg(long, requires = "all")]
        prefix: Option<String>,
    },
    /// Restore a deleted bucket by id or by name (newest deleted bucket of that name).
    RestoreBucket {
        #[command(flatten)]
        access: Access,
        /// Bucket id (see `cairn trash ls`).
        #[arg(long, conflicts_with = "name")]
        id: Option<String>,
        /// Bucket name.
        #[arg(long)]
        name: Option<String>,
        /// Restore under a different name.
        #[arg(long = "as")]
        as_name: Option<String>,
    },
}

/// `cairn pitr` subcommands.
#[derive(clap::Subcommand, Debug)]
pub enum PitrCmd {
    /// Make a bucket (or prefix) look as it did at an instant, without a prior snapshot. Works
    /// across a bucket delete. Every change is a new, reversible version sharing old blobs.
    Restore {
        #[command(flatten)]
        access: Access,
        /// Bucket.
        #[arg(long)]
        bucket: String,
        /// Instant: RFC 3339, unix nanoseconds, or `-<duration>` (e.g. `-15m`) before now.
        #[arg(long, alias = "as-of", allow_hyphen_values = true)]
        at: String,
        /// Only keys under this prefix.
        #[arg(long)]
        prefix: Option<String>,
        /// Write into this bucket instead (nothing is deleted there).
        #[arg(long)]
        to_bucket: Option<String>,
        /// Write under this prefix instead.
        #[arg(long)]
        to_prefix: Option<String>,
        /// Only report what would change.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show what differs between now and an instant.
    Diff {
        #[command(flatten)]
        access: Access,
        /// Bucket.
        #[arg(long)]
        bucket: String,
        /// Instant (same forms as `restore --at`).
        #[arg(long, alias = "as-of", allow_hyphen_values = true)]
        at: String,
        /// Only keys under this prefix.
        #[arg(long)]
        prefix: Option<String>,
    },
}

/// Parse `--at`: RFC 3339, unix nanoseconds, or `-<duration>` relative to now.
pub fn parse_instant(s: &str) -> anyhow::Result<String> {
    let ts = match s
        .strip_prefix('-')
        .and_then(cairn_core::config::parse_duration)
    {
        Some(d) => Ts::now().minus(d),
        None => Ts::parse(s).with_context(|| {
            format!("invalid instant {s:?}: use RFC 3339, unix nanoseconds or -<duration>")
        })?,
    };
    Ok(ts.to_rfc3339())
}

enum Backend {
    Local(CairnEngine, EngineAdmin),
    Remote(Box<Remote>),
}

/// What a remote backend needs for plain S3 calls (liveness checks).
struct Remote {
    client: cairn_admin::AdminClient,
    endpoint: String,
    access_key: String,
    secret_key: cairn_auth::SecretString,
    region: String,
    http: reqwest::Client,
}

fn from<T: DeserializeOwned>(v: Value) -> anyhow::Result<T> {
    serde_json::from_value(v).context("unexpected admin API response")
}

fn q(pairs: &[(&'static str, Option<String>)]) -> Vec<(&'static str, String)> {
    pairs
        .iter()
        .filter_map(|(k, v)| v.clone().map(|v| (*k, v)))
        .collect()
}

impl Backend {
    async fn open(a: &Access) -> anyhow::Result<Backend> {
        if let Some(ep) = &a.endpoint {
            let ak = a
                .access_key
                .clone()
                .context("--access-key or CAIRN_ACCESS_KEY is required with --endpoint")?;
            let sk = a
                .secret_key
                .clone()
                .context("--secret-key or CAIRN_SECRET_KEY is required with --endpoint")?;
            let client = cairn_admin::AdminClient::new(
                ep,
                &ak,
                cairn_auth::SecretString::new(sk.clone()),
                None,
                &a.region,
            )?;
            return Ok(Backend::Remote(Box::new(Remote {
                client,
                endpoint: ep.trim_end_matches('/').to_string(),
                access_key: ak,
                secret_key: cairn_auth::SecretString::new(sk),
                region: a.region.clone(),
                http: reqwest::Client::new(),
            })));
        }
        let cfg = crate::load_target(&crate::Target {
            config: a.config.clone(),
            data_dir: a.data_dir.clone(),
        })?;
        let engine = open_local(&cfg).await?;
        let admin = EngineAdmin::new(engine.clone(), cfg.server.region.clone());
        Ok(Backend::Local(engine, admin))
    }

    fn close(self) {
        if let Backend::Local(e, _) = self {
            e.shutdown();
        }
    }

    async fn buckets(&self) -> anyhow::Result<Vec<BucketSummary>> {
        Ok(match self {
            Backend::Local(_, a) => a.list_buckets().await?,
            Backend::Remote(rm) => {
                from(rm.client.call("GET", "/buckets", &[], None).await?["items"].take())?
            }
        })
    }

    async fn trash(&self, query: TrashQuery) -> anyhow::Result<Vec<TrashEntry>> {
        let mut out = Vec::new();
        let mut query = query;
        loop {
            let page: TrashPage = match self {
                Backend::Local(_, a) => a.list_trash(query.clone()).await?,
                Backend::Remote(rm) => {
                    let qs = q(&[
                        ("bucket", query.bucket.clone()),
                        ("prefix", query.prefix.clone()),
                        ("cursor", query.cursor.clone()),
                    ]);
                    from(rm.client.call("GET", "/trash", &qs, None).await?)?
                }
            };
            out.extend(page.entries);
            match page.next_cursor {
                Some(c) => query.cursor = Some(c),
                None => return Ok(out),
            }
        }
    }

    async fn restore(&self, r: RestoreRequest) -> anyhow::Result<RestoreResult> {
        Ok(match self {
            Backend::Local(_, a) => a.restore(r).await?,
            Backend::Remote(rm) => from(
                rm.client
                    .call("POST", "/trash/restore", &[], Some(&json!(r)))
                    .await?,
            )?,
        })
    }

    async fn restore_bucket(&self, r: RestoreBucketRequest) -> anyhow::Result<BucketSummary> {
        Ok(match self {
            Backend::Local(_, a) => a.restore_bucket(r).await?,
            Backend::Remote(rm) => from(
                rm.client
                    .call("POST", "/trash/restore-bucket", &[], Some(&json!(r)))
                    .await?,
            )?,
        })
    }

    async fn pitr_restore(&self, r: PitrRequest) -> anyhow::Result<PitrResult> {
        Ok(match self {
            Backend::Local(_, a) => a.pitr_restore(r).await?,
            Backend::Remote(rm) => from(
                rm.client
                    .call("POST", "/pitr/restore", &[], Some(&json!(r)))
                    .await?,
            )?,
        })
    }

    async fn pitr_diff(&self, d: PitrDiffQuery) -> anyhow::Result<Vec<PitrChange>> {
        Ok(match self {
            Backend::Local(_, a) => a.pitr_diff(d).await?,
            Backend::Remote(rm) => {
                let qs = q(&[
                    ("bucket", Some(d.bucket)),
                    ("from", Some(d.from)),
                    ("prefix", d.prefix),
                ]);
                from(rm.client.call("GET", "/pitr/diff", &qs, None).await?["items"].take())?
            }
        })
    }

    /// True if `key` currently has a live (non-delete-marker) version.
    async fn is_live(&self, bucket: &str, key: &str) -> anyhow::Result<bool> {
        match self {
            Backend::Local(e, _) => {
                let req = cairn_server::cairn_engine::types::GetObjectReq {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    ..Default::default()
                };
                match e.get_object(req, false).await {
                    Ok(_) => Ok(true),
                    Err(err) if err.code == cairn_core::S3ErrorCode::NoSuchKey => Ok(false),
                    Err(err) => Err(err.into()),
                }
            }
            Backend::Remote(rm) => {
                let url = reqwest::Url::parse(&rm.endpoint).context("invalid --endpoint")?;
                let base = url.path().trim_end_matches('/');
                let path = format!(
                    "{base}/{}/{}",
                    cairn_auth::sigv4::uri_encode(bucket.as_bytes(), false),
                    cairn_auth::sigv4::uri_encode(key.as_bytes(), true)
                );
                let host = match url.port() {
                    Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
                    None => url.host_str().unwrap_or_default().to_string(),
                };
                let hs = vec![("host".to_string(), host)];
                let signed = cairn_auth::sigv4::sign_headers(
                    "HEAD",
                    &path,
                    "",
                    &hs,
                    b"",
                    &rm.access_key,
                    &rm.secret_key,
                    None,
                    cairn_auth::Ts::now(),
                    &rm.region,
                    "s3",
                );
                let mut u = url.clone();
                u.set_path(&path);
                let mut rb = rm.http.head(u);
                for (k, v) in &signed {
                    rb = rb.header(k.as_str(), v.as_str());
                }
                let st = rb.send().await?.status();
                match st.as_u16() {
                    200 => Ok(true),
                    404 => Ok(false),
                    other => anyhow::bail!("HEAD {bucket}/{key} returned {other}"),
                }
            }
        }
    }

    /// Newest trashed bucket called `name`, if any.
    async fn trashed_named(&self, name: &str) -> anyhow::Result<Option<BucketSummary>> {
        let mut v: Vec<_> = self
            .buckets()
            .await?
            .into_iter()
            .filter(|b| b.trashed && b.name == name)
            .collect();
        v.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(v.pop())
    }
}

async fn open_local(cfg: &Config) -> anyhow::Result<CairnEngine> {
    let meta = cfg.meta_path();
    cairn_server::open_engine(cfg, Default::default())
        .await
        .with_context(|| {
            format!(
                "opening {} (stop `cairn serve` first, or pass --endpoint to go through it)",
                meta.display()
            )
        })
}

fn print(as_json: bool, v: &Value, human: impl FnOnce() -> String) -> anyhow::Result<()> {
    if as_json {
        println!("{}", serde_json::to_string_pretty(v)?);
    } else {
        print!("{}", human());
    }
    Ok(())
}

async fn restore_all(b: &Backend, bucket: &str, prefix: Option<String>) -> anyhow::Result<Value> {
    let live = b.buckets().await?;
    let mut bucket_restored = None;
    if !live.iter().any(|s| s.name == bucket && !s.trashed) {
        let t = b
            .trashed_named(bucket)
            .await?
            .with_context(|| format!("no live or deleted bucket named {bucket:?}"))?;
        let s = b
            .restore_bucket(RestoreBucketRequest {
                bucket_id: t.id.clone(),
                as_name: Some(bucket.to_string()),
                all_versions: prefix.is_none(),
                ..Default::default()
            })
            .await?;
        bucket_restored = Some(s.id);
    }
    let entries = b
        .trash(TrashQuery {
            bucket: Some(bucket.to_string()),
            prefix: prefix.clone(),
            ..Default::default()
        })
        .await?;
    let mut keys: Vec<String> = entries
        .iter()
        .filter(|e| prefix.as_deref().is_none_or(|p| e.key.starts_with(p)))
        .map(|e| e.key.clone())
        .collect();
    keys.dedup();
    let mut restored = Vec::new();
    let mut skipped = 0u64;
    let mut live = 0u64;
    for key in keys {
        if b.is_live(bucket, &key).await? {
            live += 1;
            continue;
        }
        match b
            .restore(RestoreRequest {
                bucket: bucket.to_string(),
                key: key.clone(),
                version_id: None,
            })
            .await
        {
            Ok(r) => restored.push(r),
            Err(e) => {
                tracing::warn!(%key, error = %e, "not restored");
                skipped += 1;
            }
        }
    }
    Ok(json!({
        "bucket": bucket,
        "bucket_restored": bucket_restored,
        "restored": restored,
        "already_live": live,
        "failed": skipped,
    }))
}

/// Run `cairn trash …`.
pub async fn trash(cmd: TrashCmd) -> anyhow::Result<i32> {
    match cmd {
        TrashCmd::Ls {
            access,
            bucket,
            prefix,
        } => {
            let b = Backend::open(&access).await?;
            let r = async {
                let buckets: Vec<_> = b
                    .buckets()
                    .await?
                    .into_iter()
                    .filter(|s| s.trashed && bucket.as_ref().is_none_or(|n| n == &s.name))
                    .collect();
                let live_bucket = match &bucket {
                    Some(n) => b
                        .buckets()
                        .await?
                        .iter()
                        .any(|s| &s.name == n && !s.trashed),
                    None => true,
                };
                let entries = if live_bucket {
                    b.trash(TrashQuery {
                        bucket: bucket.clone(),
                        prefix: prefix.clone(),
                        ..Default::default()
                    })
                    .await?
                } else {
                    Vec::new()
                };
                anyhow::Ok((buckets, entries))
            }
            .await;
            b.close();
            let (buckets, entries) = r?;
            let v = json!({ "buckets": buckets, "objects": entries });
            print(access.json, &v, || {
                let mut s = String::new();
                for t in &buckets {
                    s.push_str(&format!(
                        "bucket  {}  id={}  created={}\n",
                        t.name, t.id, t.created_at
                    ));
                }
                for e in &entries {
                    s.push_str(&format!(
                        "{}/{}  version={}  size={}  deleted={}  by={}  reason={}  expires={}\n",
                        e.bucket,
                        e.key,
                        e.version_id,
                        e.size,
                        e.deleted_at,
                        e.deleted_by,
                        e.reason,
                        e.expires_at
                    ));
                }
                if s.is_empty() {
                    s.push_str("trash is empty\n");
                }
                s
            })?;
            Ok(0)
        }
        TrashCmd::Restore {
            access,
            bucket,
            key,
            version,
            all,
            prefix,
        } => {
            anyhow::ensure!(
                all || key.is_some(),
                "pass --key <key> [--version <id>] or --all"
            );
            let b = Backend::open(&access).await?;
            let r = async {
                if all {
                    let v = restore_all(&b, &bucket, prefix).await?;
                    let failed = v["failed"].as_u64().unwrap_or(0);
                    anyhow::Ok((v, failed))
                } else {
                    let r = b
                        .restore(RestoreRequest {
                            bucket: bucket.clone(),
                            key: key.clone().unwrap_or_default(),
                            version_id: version.clone(),
                        })
                        .await?;
                    Ok((json!(r), 0))
                }
            }
            .await;
            b.close();
            let (v, failed) = r?;
            print(access.json, &v, || {
                if let Some(arr) = v["restored"].as_array() {
                    let mut s = String::new();
                    if let Some(id) = v["bucket_restored"].as_str() {
                        s.push_str(&format!("restored bucket {bucket} (id {id})\n"));
                    }
                    for r in arr {
                        s.push_str(&format!(
                            "restored {}/{} as version {}\n",
                            bucket,
                            r["key"].as_str().unwrap_or_default(),
                            r["version_id"].as_str().unwrap_or_default()
                        ));
                    }
                    s.push_str(&format!("{} key(s) restored, {failed} failed\n", arr.len()));
                    s
                } else {
                    format!(
                        "restored {}/{} as version {}\n",
                        bucket,
                        v["key"].as_str().unwrap_or_default(),
                        v["version_id"].as_str().unwrap_or_default()
                    )
                }
            })?;
            Ok(if failed == 0 { 0 } else { 1 })
        }
        TrashCmd::RestoreBucket {
            access,
            id,
            name,
            as_name,
        } => {
            anyhow::ensure!(id.is_some() || name.is_some(), "pass --id or --name");
            let b = Backend::open(&access).await?;
            let r = async {
                let bucket_id = match (&id, &name) {
                    (Some(i), _) => i.clone(),
                    (None, Some(n)) => {
                        b.trashed_named(n)
                            .await?
                            .with_context(|| format!("no deleted bucket named {n:?}"))?
                            .id
                    }
                    (None, None) => unreachable!(),
                };
                b.restore_bucket(RestoreBucketRequest {
                    bucket_id,
                    as_name: as_name.clone().or(name.clone()),
                    ..Default::default()
                })
                .await
            }
            .await;
            b.close();
            let s = r?;
            print(access.json, &json!(s), || {
                format!("restored bucket {} (id {})\n", s.name, s.id)
            })?;
            Ok(0)
        }
    }
}

/// Run `cairn pitr …`.
pub async fn pitr(cmd: PitrCmd) -> anyhow::Result<i32> {
    match cmd {
        PitrCmd::Restore {
            access,
            bucket,
            at,
            prefix,
            to_bucket,
            to_prefix,
            dry_run,
        } => {
            let as_of = parse_instant(&at)?;
            let b = Backend::open(&access).await?;
            let r = b
                .pitr_restore(PitrRequest {
                    bucket: bucket.clone(),
                    prefix,
                    as_of: as_of.clone(),
                    target_bucket: to_bucket,
                    target_prefix: to_prefix,
                    dry_run,
                    ..Default::default()
                })
                .await;
            b.close();
            let r = r?;
            print(access.json, &json!(r), || {
                let mut s = String::new();
                for c in &r.changes {
                    s.push_str(&format!("{:<8} {}\n", c.action, c.key));
                }
                s.push_str(&format!(
                    "{} {} key(s) to {as_of}; {} unchanged\n",
                    if dry_run { "would restore" } else { "restored" },
                    r.restored,
                    r.unchanged
                ));
                s
            })?;
            Ok(0)
        }
        PitrCmd::Diff {
            access,
            bucket,
            at,
            prefix,
        } => {
            let from = parse_instant(&at)?;
            let b = Backend::open(&access).await?;
            let r = b
                .pitr_diff(PitrDiffQuery {
                    bucket,
                    prefix,
                    from,
                    to: None,
                })
                .await;
            b.close();
            let r = r?;
            print(access.json, &json!({ "items": r }), || {
                let mut s = String::new();
                for c in &r {
                    s.push_str(&format!("{:<8} {}\n", c.action, c.key));
                }
                if r.is_empty() {
                    s.push_str("no differences\n");
                }
                s
            })?;
            Ok(0)
        }
    }
}
