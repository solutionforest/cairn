//! Asynchronous bucket replication (DESIGN §9, PRODUCTION-READINESS C6).
//!
//! * **Rules**: [`ReplicationConfiguration`] round-trips the AWS `ReplicationConfiguration` XML
//!   (Role, Rule: ID / Priority / Status / Filter {Prefix | Tag | And} / legacy Prefix /
//!   Destination {Bucket ARN, Account, StorageClass} / DeleteMarkerReplication /
//!   ExistingObjectReplication) and is stored as the bucket's `replication` config document (so
//!   `bucket_history` keeps every revision).
//! * **Targets**: the destination ARN of a rule names a target registered out-of-band in
//!   [`TargetRegistry`] (`kv` rows `repl/target/<arn>`: endpoint, region, remote bucket, access
//!   key, secret sealed with ChaCha20-Poly1305 under a server key), like `mc admin bucket remote
//!   add`. In-process targets (tests, same-server copies) are registered with
//!   [`TargetRegistry::register`].
//! * **Cursor**: one row per (bucket, destination) in the `repl_cursor` table:
//!   `BucketId ‖ destination ARN` → [`ReplCursor`] (high-water `created_at` plus the version ids
//!   delivered inside the overlap window). Version ids are time-ordered, so "new versions" is
//!   `created_at > watermark − overlap` minus the recently delivered set; the overlap window
//!   absorbs wall-clock steps. The cursor only advances past versions that were delivered or
//!   permanently skipped, so a crash re-delivers at most the last batch (idempotent on Tidemark
//!   targets thanks to `x-tidemark-version-id`).
//! * **Worker**: [`ReplicationWorker::tick`] scans each replicated bucket's versions, delivers
//!   new versions and delete markers in `created_at` order through a [`ReplicationTarget`]
//!   ([`S3Target`] over aws-sdk-s3, [`EngineTarget`] in-process), with exponential backoff per
//!   destination and a lag hook ([`ReplicationObserver`]).
//!
//! Each tick reads every version row of a replicated bucket (`O(versions)`), which is fine for
//! the v1 single-node scale; an engine-maintained change index can replace the scan later
//! without changing the cursor format.

use crate::TidemarkEngine;
use crate::commit::{active_bucket, incref_checked};
use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tidemark_blob::remote_s3::{RemoteS3, S3Endpoint, aws_sdk_s3};
use tidemark_blob::{BlobReader, BlobStore, DataKey, FsBlobStore, WriteOpts};
use tidemark_core::{BucketId, S3Error, S3ErrorCode, S3Result, Ts, VersionId};
use tidemark_meta::{
    BucketRecord, BucketState, Flow, MetaError, MetaStore, PartRef, ReadExt, Reader, RedbMetaStore,
    Table, VersionKind, VersionRecord, VersionState, Versioning, decode, encode,
};
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

/// Bucket config-document kind holding the replication XML.
pub const CONFIG_KIND: &str = "replication";
/// `kv` prefix of registered targets.
pub const TARGET_PREFIX: &[u8] = b"repl/target/";
/// Header carrying the source version id on Tidemark → Tidemark replication.
pub const VERSION_ID_HEADER: &str = "x-tidemark-version-id";
const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
const ARN_PREFIX: &str = "arn:aws:s3:::";

// ---------------------------------------------------------------------------------------------
// Configuration model
// ---------------------------------------------------------------------------------------------

/// Rule filter (`<Filter>`); empty = whole bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleFilter {
    /// Key prefix.
    pub prefix: Option<String>,
    /// Object tags that must all match.
    pub tags: Vec<(String, String)>,
}

/// `<Destination>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Destination {
    /// Bucket ARN (`arn:aws:s3:::name`); names the registered target.
    pub bucket_arn: String,
    /// Destination account id.
    pub account: Option<String>,
    /// Storage class for replicas.
    pub storage_class: Option<String>,
}

impl Destination {
    /// Bucket name part of the ARN.
    pub fn bucket_name(&self) -> &str {
        self.bucket_arn
            .strip_prefix(ARN_PREFIX)
            .unwrap_or(&self.bucket_arn)
    }
}

/// One `<Rule>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicationRule {
    /// `<ID>`.
    pub id: Option<String>,
    /// `<Priority>` (higher wins when several rules match).
    pub priority: Option<i32>,
    /// `<Status>Enabled</Status>`.
    pub enabled: bool,
    /// V2 `<Filter>` (None when the rule uses the V1 `<Prefix>` form).
    pub filter: Option<RuleFilter>,
    /// V1 `<Prefix>`.
    pub prefix: Option<String>,
    /// `<DeleteMarkerReplication><Status>`.
    pub delete_marker_replication: Option<bool>,
    /// `<ExistingObjectReplication><Status>`.
    pub existing_object_replication: Option<bool>,
    /// `<Destination>`.
    pub destination: Destination,
}

impl ReplicationRule {
    /// Whether this rule selects an object `key` with `tags` (delete markers pass `None`).
    pub fn matches(&self, key: &str, tags: Option<&BTreeMap<String, String>>) -> bool {
        if let Some(p) = &self.prefix
            && !key.starts_with(p.as_str())
        {
            return false;
        }
        let Some(f) = &self.filter else {
            return true;
        };
        if let Some(p) = &f.prefix
            && !key.starts_with(p.as_str())
        {
            return false;
        }
        if f.tags.is_empty() {
            return true;
        }
        let Some(tags) = tags else {
            return false;
        };
        f.tags.iter().all(|(k, v)| tags.get(k) == Some(v))
    }

    /// Whether delete markers are replicated (V1 rules: yes; V2: only when enabled).
    pub fn replicates_delete_markers(&self) -> bool {
        match (&self.filter, self.delete_marker_replication) {
            (_, Some(b)) => b,
            (None, None) => true,
            (Some(_), None) => false,
        }
    }
}

/// `<ReplicationConfiguration>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicationConfiguration {
    /// `<Role>` (accepted and echoed; Tidemark authenticates to targets with registered keys).
    pub role: Option<String>,
    /// Rules.
    pub rules: Vec<ReplicationRule>,
}

#[derive(Debug, Default)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn child(&self, n: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == n)
    }
    fn all<'a>(&'a self, n: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == n)
    }
    fn text_of(&self, n: &str) -> Option<String> {
        self.child(n).map(|c| c.text.trim().to_string())
    }
}

fn malformed(msg: impl std::fmt::Display) -> S3Error {
    S3Error::new(
        S3ErrorCode::MalformedXML,
        format!("replication configuration: {msg}"),
    )
}

fn parse_tree(xml: &str) -> S3Result<Node> {
    use quick_xml::events::Event as X;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack: Vec<Node> = vec![Node::default()];
    loop {
        match reader.read_event().map_err(malformed)? {
            X::Start(e) => stack.push(Node {
                name: e.local_name().as_ref().to_string(),
                ..Default::default()
            }),
            X::Empty(e) => {
                let n = Node {
                    name: e.local_name().as_ref().to_string(),
                    ..Default::default()
                };
                stack.last_mut().expect("root").children.push(n);
            }
            X::Text(t) => stack
                .last_mut()
                .expect("root")
                .text
                .push_str(&t.xml10_content()),
            X::CData(c) => stack
                .last_mut()
                .expect("root")
                .text
                .push_str(&c.into_inner()),
            X::GeneralRef(r) => {
                let ch = if r.is_char_ref() {
                    r.resolve_char_ref().map_err(malformed)?
                } else {
                    match r.xml10_content().as_ref() {
                        "amp" => Some('&'),
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        other => return Err(malformed(format!("unknown entity &{other};"))),
                    }
                };
                let ch = ch.ok_or_else(|| malformed("invalid character reference"))?;
                stack.last_mut().expect("root").text.push(ch);
            }
            X::End(_) => {
                let n = stack.pop().expect("balanced");
                stack
                    .last_mut()
                    .ok_or_else(|| malformed("unbalanced end tag"))?
                    .children
                    .push(n);
            }
            X::DocType(_) => return Err(malformed("DOCTYPE is not allowed")),
            X::Eof => break,
            _ => {}
        }
        if stack.len() > 16 {
            return Err(malformed("document nested too deeply"));
        }
    }
    if stack.len() != 1 {
        return Err(malformed("unexpected end of document"));
    }
    let root = stack.pop().expect("root");
    let mut elems = root.children.into_iter();
    match (elems.next(), elems.next()) {
        (Some(n), None) => Ok(n),
        _ => Err(malformed("expected exactly one root element")),
    }
}

fn status(n: Option<&Node>) -> S3Result<Option<bool>> {
    match n.and_then(|n| n.text_of("Status")).as_deref() {
        None => Ok(None),
        Some("Enabled") => Ok(Some(true)),
        Some("Disabled") => Ok(Some(false)),
        Some(o) => Err(malformed(format!("bad Status {o}"))),
    }
}

fn tag_of(n: &Node) -> S3Result<(String, String)> {
    Ok((
        n.text_of("Key")
            .ok_or_else(|| malformed("Tag without Key"))?,
        n.text_of("Value").unwrap_or_default(),
    ))
}

impl ReplicationConfiguration {
    /// Parse the S3 XML document.
    pub fn from_xml(xml: &str) -> S3Result<ReplicationConfiguration> {
        let root = parse_tree(xml)?;
        if root.name != "ReplicationConfiguration" {
            return Err(malformed(format!("unexpected root {}", root.name)));
        }
        let mut cfg = ReplicationConfiguration {
            role: root.text_of("Role").filter(|r| !r.is_empty()),
            rules: Vec::new(),
        };
        for r in root.all("Rule") {
            let enabled = match r.text_of("Status").as_deref() {
                Some("Enabled") => true,
                Some("Disabled") => false,
                _ => return Err(malformed("Rule needs Status Enabled|Disabled")),
            };
            let filter = match r.child("Filter") {
                None => None,
                Some(f) => {
                    let mut rf = RuleFilter {
                        prefix: f.text_of("Prefix"),
                        tags: Vec::new(),
                    };
                    if let Some(t) = f.child("Tag") {
                        rf.tags.push(tag_of(t)?);
                    }
                    if let Some(a) = f.child("And") {
                        if rf.prefix.is_some() || !rf.tags.is_empty() {
                            return Err(malformed("Filter And must be the only filter element"));
                        }
                        rf.prefix = a.text_of("Prefix");
                        for t in a.all("Tag") {
                            rf.tags.push(tag_of(t)?);
                        }
                    }
                    Some(rf)
                }
            };
            let d = r
                .child("Destination")
                .ok_or_else(|| malformed("Rule without Destination"))?;
            let priority = match r.text_of("Priority") {
                Some(p) => Some(
                    p.parse()
                        .map_err(|_| malformed(format!("bad Priority {p}")))?,
                ),
                None => None,
            };
            cfg.rules.push(ReplicationRule {
                id: r.text_of("ID").filter(|s| !s.is_empty()),
                priority,
                enabled,
                prefix: if filter.is_none() {
                    r.text_of("Prefix")
                } else {
                    None
                },
                filter,
                delete_marker_replication: status(r.child("DeleteMarkerReplication"))?,
                existing_object_replication: status(r.child("ExistingObjectReplication"))?,
                destination: Destination {
                    bucket_arn: d
                        .text_of("Bucket")
                        .ok_or_else(|| malformed("Destination without Bucket"))?,
                    account: d.text_of("Account"),
                    storage_class: d.text_of("StorageClass"),
                },
            });
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Serialise to the S3 XML document.
    pub fn to_xml(&self) -> String {
        use quick_xml::escape::escape;
        let mut o = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        o.push_str(&format!(r#"<ReplicationConfiguration xmlns="{S3_XMLNS}">"#));
        if let Some(r) = &self.role {
            o.push_str(&format!("<Role>{}</Role>", escape(r.as_str())));
        }
        let st = |b: bool| if b { "Enabled" } else { "Disabled" };
        let tag = |k: &str, v: &str| {
            format!(
                "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
                escape(k),
                escape(v)
            )
        };
        for r in &self.rules {
            o.push_str("<Rule>");
            if let Some(id) = &r.id {
                o.push_str(&format!("<ID>{}</ID>", escape(id.as_str())));
            }
            if let Some(p) = r.priority {
                o.push_str(&format!("<Priority>{p}</Priority>"));
            }
            o.push_str(&format!("<Status>{}</Status>", st(r.enabled)));
            if let Some(p) = &r.prefix {
                o.push_str(&format!("<Prefix>{}</Prefix>", escape(p.as_str())));
            }
            if let Some(f) = &r.filter {
                o.push_str("<Filter>");
                let n = usize::from(f.prefix.is_some()) + f.tags.len();
                if n > 1 {
                    o.push_str("<And>");
                }
                if let Some(p) = &f.prefix {
                    o.push_str(&format!("<Prefix>{}</Prefix>", escape(p.as_str())));
                }
                for (k, v) in &f.tags {
                    o.push_str(&tag(k, v));
                }
                if n > 1 {
                    o.push_str("</And>");
                }
                o.push_str("</Filter>");
            }
            if let Some(b) = r.delete_marker_replication {
                o.push_str(&format!(
                    "<DeleteMarkerReplication><Status>{}</Status></DeleteMarkerReplication>",
                    st(b)
                ));
            }
            o.push_str("<Destination>");
            o.push_str(&format!(
                "<Bucket>{}</Bucket>",
                escape(r.destination.bucket_arn.as_str())
            ));
            if let Some(a) = &r.destination.account {
                o.push_str(&format!("<Account>{}</Account>", escape(a.as_str())));
            }
            if let Some(s) = &r.destination.storage_class {
                o.push_str(&format!(
                    "<StorageClass>{}</StorageClass>",
                    escape(s.as_str())
                ));
            }
            o.push_str("</Destination>");
            if let Some(b) = r.existing_object_replication {
                o.push_str(&format!(
                    "<ExistingObjectReplication><Status>{}</Status></ExistingObjectReplication>",
                    st(b)
                ));
            }
            o.push_str("</Rule>");
        }
        o.push_str("</ReplicationConfiguration>");
        o
    }

    /// AWS validation rules that Tidemark enforces.
    pub fn validate(&self) -> S3Result<()> {
        if self.rules.is_empty() || self.rules.len() > 1000 {
            return Err(malformed("between 1 and 1000 rules required"));
        }
        let mut ids = std::collections::HashSet::new();
        let mut prios = std::collections::HashSet::new();
        for r in &self.rules {
            if let Some(id) = &r.id
                && (id.len() > 255 || !ids.insert(id.clone()))
            {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    format!("duplicate or too long rule ID {id}"),
                ));
            }
            if !r.destination.bucket_arn.starts_with(ARN_PREFIX)
                || r.destination.bucket_name().is_empty()
                || r.destination.bucket_name().contains('/')
            {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    format!(
                        "invalid destination bucket ARN {}",
                        r.destination.bucket_arn
                    ),
                ));
            }
            if r.filter.is_some() {
                let Some(p) = r.priority else {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "rules with a Filter need a Priority",
                    ));
                };
                if !prios.insert(p) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        format!("duplicate rule Priority {p}"),
                    ));
                }
                if r.delete_marker_replication.is_none() {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "rules with a Filter need DeleteMarkerReplication",
                    ));
                }
                if r.delete_marker_replication == Some(true)
                    && r.filter.as_ref().is_some_and(|f| !f.tags.is_empty())
                {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "delete marker replication is not supported for tag-based rules",
                    ));
                }
            }
        }
        Ok(())
    }

    /// The highest-priority enabled rule for `dest` that selects the version.
    pub fn rule_for(&self, dest: &str, v: &VersionRecord) -> Option<&ReplicationRule> {
        let tags = v.body().map(|b| &b.tags);
        self.rules
            .iter()
            .filter(|r| r.enabled && r.destination.bucket_arn == dest)
            .filter(|r| r.matches(&v.key, tags))
            .filter(|r| !v.is_delete_marker() || r.replicates_delete_markers())
            .max_by_key(|r| r.priority.unwrap_or(0))
    }

    /// Distinct destinations of enabled rules.
    pub fn destinations(&self) -> Vec<String> {
        let mut d: Vec<String> = self
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.destination.bucket_arn.clone())
            .collect();
        d.sort();
        d.dedup();
        d
    }
}

// ---------------------------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------------------------

/// Durable progress of one (bucket, destination) pair (`repl_cursor` table).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplCursor {
    /// Versions created before this are never replicated (ExistingObjectReplication disabled).
    pub since: Option<Ts>,
    /// Every version with `created_at <= watermark − overlap` is done (`None` = from the start).
    pub watermark: Option<Ts>,
    /// Versions delivered (or skipped) inside the overlap window.
    pub recent: Vec<VersionId>,
    /// Versions delivered so far.
    pub delivered: u64,
    /// Versions skipped after a permanent target error.
    pub failed: u64,
    /// Last error (target message, never credentials).
    pub last_error: Option<String>,
    /// Last successful delivery.
    pub last_success: Option<Ts>,
}

fn cursor_key(b: BucketId, dest: &str) -> Vec<u8> {
    let mut k = b.to_bytes().to_vec();
    k.extend_from_slice(dest.as_bytes());
    k
}

/// Load a cursor.
pub fn load_cursor<R: Reader + ?Sized>(
    r: &R,
    b: BucketId,
    dest: &str,
) -> Result<Option<ReplCursor>, MetaError> {
    r.get(Table::ReplCursor, &cursor_key(b, dest))?
        .map(|v| decode(&v))
        .transpose()
}

/// `x-amz-replication-status` of a source version for one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationStatus {
    /// Not yet delivered.
    Pending,
    /// Delivered.
    Completed,
}

impl ReplicationStatus {
    /// Header value.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReplicationStatus::Pending => "PENDING",
            ReplicationStatus::Completed => "COMPLETED",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------------------------

/// Delivery failure.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReplError {
    /// Retry later (network, 5xx, throttling, auth/config problems an operator can fix).
    #[error("transient replication error: {0}")]
    Transient(String),
    /// Retrying cannot help (the version is skipped and counted as failed).
    #[error("permanent replication error: {0}")]
    Permanent(String),
}

/// Source data of one version, part by part.
#[async_trait]
pub trait PartSource: Send + Sync {
    /// Plaintext stream of part `index` (0-based, in `ObjectBody::parts` order).
    async fn open_part(&self, index: usize) -> Result<BlobReader, ReplError>;
}

/// Reads parts from an engine's blob store.
pub struct EnginePartSource {
    blobs: FsBlobStore,
    key: Option<DataKey>,
    parts: Vec<PartRef>,
}

impl EnginePartSource {
    /// Parts of `v` in `engine`.
    pub fn new(engine: &TidemarkEngine, v: &VersionRecord) -> EnginePartSource {
        EnginePartSource {
            blobs: engine.blobs().clone(),
            key: engine.config().at_rest_key.clone(),
            parts: v.body().map(|b| b.parts.clone()).unwrap_or_default(),
        }
    }
}

#[async_trait]
impl PartSource for EnginePartSource {
    async fn open_part(&self, index: usize) -> Result<BlobReader, ReplError> {
        let p = self
            .parts
            .get(index)
            .ok_or_else(|| ReplError::Permanent(format!("no part {index}")))?;
        self.blobs
            .open(&p.blob, 0..p.size, self.key.as_ref())
            .await
            .map_err(|e| match e {
                tidemark_blob::BlobError::NotFound(_) => {
                    ReplError::Permanent(format!("source blob {} missing", p.blob))
                }
                e => ReplError::Transient(e.to_string()),
            })
    }
}

/// A replication destination bound to one destination bucket.
#[async_trait]
pub trait ReplicationTarget: Send + Sync {
    /// Store object version `v` (same key, metadata, tags, part layout; same version id where
    /// the target supports it). Must be idempotent for the same version id where possible.
    async fn replicate_object(
        &self,
        v: &VersionRecord,
        data: &dyn PartSource,
    ) -> Result<(), ReplError>;
    /// Create the delete marker `v`.
    async fn replicate_delete_marker(&self, v: &VersionRecord) -> Result<(), ReplError>;
}

/// In-process target: another [`TidemarkEngine`] (version ids preserved, idempotent).
#[derive(Clone)]
pub struct EngineTarget {
    engine: TidemarkEngine,
    bucket: String,
}

impl EngineTarget {
    /// Replicate into `bucket` of `engine` (must have versioning enabled).
    pub fn new(engine: TidemarkEngine, bucket: &str) -> EngineTarget {
        EngineTarget {
            engine,
            bucket: bucket.to_string(),
        }
    }
}

fn s3_repl_err(e: S3Error) -> ReplError {
    let retry = e.http_status() >= 500
        || matches!(
            e.code,
            S3ErrorCode::NoSuchBucket | S3ErrorCode::AccessDenied | S3ErrorCode::InvalidRequest
        );
    if retry {
        ReplError::Transient(e.to_string())
    } else {
        ReplError::Permanent(e.to_string())
    }
}

#[async_trait]
impl ReplicationTarget for EngineTarget {
    async fn replicate_object(
        &self,
        v: &VersionRecord,
        data: &dyn PartSource,
    ) -> Result<(), ReplError> {
        self.engine
            .put_replica(&self.bucket, v, Some(data))
            .await
            .map(|_| ())
            .map_err(s3_repl_err)
    }
    async fn replicate_delete_marker(&self, v: &VersionRecord) -> Result<(), ReplError> {
        self.engine
            .put_replica(&self.bucket, v, None)
            .await
            .map(|_| ())
            .map_err(s3_repl_err)
    }
}

/// Target on any S3 endpoint via aws-sdk-s3 (rustls). With `tidemark_peer`, every request carries
/// [`VERSION_ID_HEADER`] so a Tidemark destination keeps the source version id.
#[derive(Clone)]
pub struct S3Target {
    s3: RemoteS3,
    tidemark_peer: bool,
    spool: PathBuf,
}

impl S3Target {
    /// Target for `ep` (bucket = destination bucket); parts are spooled under `spool_dir`.
    pub fn new(ep: &S3Endpoint, tidemark_peer: bool, spool_dir: &Path) -> S3Target {
        S3Target {
            s3: RemoteS3::new(ep),
            tidemark_peer,
            spool: spool_dir.to_path_buf(),
        }
    }

    async fn spool_part(&self, data: &dyn PartSource, i: usize) -> Result<PathBuf, ReplError> {
        let mut r = data.open_part(i).await?;
        let p = self.spool.join(format!("repl-{}", uuid::Uuid::new_v4()));
        let res: Result<(), std::io::Error> = async {
            let mut f = tokio::fs::File::create(&p).await?;
            while let Some(c) = r.next().await {
                f.write_all(&c?).await?;
            }
            f.flush().await
        }
        .await;
        if let Err(e) = res {
            let _ = tokio::fs::remove_file(&p).await;
            return Err(ReplError::Transient(format!("spooling part: {e}")));
        }
        Ok(p)
    }
}

fn sdk_repl_err<E: std::error::Error + Send + Sync + 'static>(
    e: aws_sdk_s3::error::SdkError<E, aws_sdk_s3::config::http::HttpResponse>,
) -> ReplError {
    let status = e.raw_response().map(|r| r.status().as_u16());
    let msg = format!("{}", aws_sdk_s3::error::DisplayErrorContext(&e));
    match status {
        Some(400 | 405 | 411 | 413 | 501) => ReplError::Permanent(msg),
        _ => ReplError::Transient(msg),
    }
}

fn tagging(tags: &BTreeMap<String, String>) -> Option<String> {
    if tags.is_empty() {
        return None;
    }
    let enc = |s: &str| {
        let mut o = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    o.push(b as char)
                }
                _ => o.push_str(&format!("%{b:02X}")),
            }
        }
        o
    };
    Some(
        tags.iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&"),
    )
}

macro_rules! object_meta {
    ($req:expr, $body:expr) => {{
        let b = $body;
        let mut r = $req
            .set_content_type(b.content_type.clone())
            .set_cache_control(b.cache_control.clone())
            .set_content_disposition(b.content_disposition.clone())
            .set_content_encoding(b.content_encoding.clone())
            .set_content_language(b.content_language.clone())
            .set_website_redirect_location(b.website_redirect.clone())
            .set_tagging(tagging(&b.tags));
        for (k, v) in &b.user_metadata {
            r = r.metadata(k, v);
        }
        r
    }};
}

#[async_trait]
impl ReplicationTarget for S3Target {
    async fn replicate_object(
        &self,
        v: &VersionRecord,
        data: &dyn PartSource,
    ) -> Result<(), ReplError> {
        let body = v
            .body()
            .ok_or_else(|| ReplError::Permanent("not an object".into()))?;
        let vid = v.version_id.to_string();
        let peer = self.tidemark_peer;
        let client = self.s3.client();
        let key = self.s3.key(&v.key);
        if body.parts.len() <= 1 {
            let path = if body.parts.is_empty() {
                None
            } else {
                Some(self.spool_part(data, 0).await?)
            };
            let stream = match &path {
                Some(p) => aws_sdk_s3::primitives::ByteStream::from_path(p)
                    .await
                    .map_err(|e| ReplError::Transient(e.to_string()))?,
                None => aws_sdk_s3::primitives::ByteStream::from_static(b""),
            };
            let req = client
                .put_object()
                .bucket(self.s3.bucket())
                .key(&key)
                .body(stream);
            let res = object_meta!(req, body)
                .customize()
                .mutate_request(move |r| {
                    if peer {
                        r.headers_mut().insert(VERSION_ID_HEADER, vid.clone());
                    }
                })
                .send()
                .await;
            if let Some(p) = path {
                let _ = tokio::fs::remove_file(p).await;
            }
            res.map_err(sdk_repl_err)?;
            return Ok(());
        }
        let req = client
            .create_multipart_upload()
            .bucket(self.s3.bucket())
            .key(&key);
        let up = object_meta!(req, body).send().await.map_err(sdk_repl_err)?;
        let upload_id = up
            .upload_id()
            .ok_or_else(|| ReplError::Transient("no upload id".into()))?
            .to_string();
        let res: Result<(), ReplError> = async {
            let mut done = Vec::new();
            for (i, _) in body.parts.iter().enumerate() {
                let p = self.spool_part(data, i).await?;
                let stream = aws_sdk_s3::primitives::ByteStream::from_path(&p)
                    .await
                    .map_err(|e| ReplError::Transient(e.to_string()));
                let r = match stream {
                    Ok(s) => client
                        .upload_part()
                        .bucket(self.s3.bucket())
                        .key(&key)
                        .upload_id(&upload_id)
                        .part_number(i as i32 + 1)
                        .body(s)
                        .send()
                        .await
                        .map_err(sdk_repl_err),
                    Err(e) => Err(e),
                };
                let _ = tokio::fs::remove_file(&p).await;
                let r = r?;
                done.push(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(i as i32 + 1)
                        .set_e_tag(r.e_tag().map(str::to_string))
                        .build(),
                );
            }
            let vid = vid.clone();
            client
                .complete_multipart_upload()
                .bucket(self.s3.bucket())
                .key(&key)
                .upload_id(&upload_id)
                .multipart_upload(
                    aws_sdk_s3::types::CompletedMultipartUpload::builder()
                        .set_parts(Some(done))
                        .build(),
                )
                .customize()
                .mutate_request(move |r| {
                    if peer {
                        r.headers_mut().insert(VERSION_ID_HEADER, vid.clone());
                    }
                })
                .send()
                .await
                .map_err(sdk_repl_err)?;
            Ok(())
        }
        .await;
        if res.is_err() {
            let _ = client
                .abort_multipart_upload()
                .bucket(self.s3.bucket())
                .key(&key)
                .upload_id(&upload_id)
                .send()
                .await;
        }
        res
    }

    async fn replicate_delete_marker(&self, v: &VersionRecord) -> Result<(), ReplError> {
        let vid = v.version_id.to_string();
        let peer = self.tidemark_peer;
        self.s3
            .client()
            .delete_object()
            .bucket(self.s3.bucket())
            .key(self.s3.key(&v.key))
            .customize()
            .mutate_request(move |r| {
                if peer {
                    r.headers_mut().insert(VERSION_ID_HEADER, vid.clone());
                }
            })
            .send()
            .await
            .map_err(sdk_repl_err)?;
        Ok(())
    }
}

/// Resolves a destination ARN of a bucket's rule to a target.
pub trait TargetResolver: Send + Sync {
    /// Target for `dest_arn`, or `None` if nothing is registered.
    fn resolve(&self, dest_arn: &str) -> Result<Option<Arc<dyn ReplicationTarget>>, ReplError>;
}

/// A registered remote target (secret never serialised in clear).
#[derive(Clone)]
pub struct TargetConfig {
    /// Destination ARN used in rules (`arn:aws:s3:::name`).
    pub arn: String,
    /// Endpoint, region, remote bucket, prefix (usually empty), credentials.
    pub endpoint: S3Endpoint,
    /// The destination is a Tidemark server: send `x-tidemark-version-id`.
    pub tidemark_peer: bool,
}

impl std::fmt::Debug for TargetConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetConfig")
            .field("arn", &self.arn)
            .field("endpoint", &self.endpoint)
            .field("tidemark_peer", &self.tidemark_peer)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct TargetRecord {
    arn: String,
    endpoint: Option<String>,
    region: String,
    bucket: String,
    prefix: String,
    access_key: String,
    sealed_secret: Vec<u8>,
    path_style: bool,
    tidemark_peer: bool,
}

/// Public view of a registered target (no secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetInfo {
    /// ARN.
    pub arn: String,
    /// Endpoint URL.
    pub endpoint: Option<String>,
    /// Remote bucket.
    pub bucket: String,
    /// Access key id.
    pub access_key: String,
    /// Tidemark peer.
    pub tidemark_peer: bool,
}

/// Persistent target registry (`kv` rows `repl/target/<arn>`) plus in-process registrations.
pub struct TargetRegistry {
    meta: RedbMetaStore,
    key: Zeroizing<[u8; 32]>,
    spool: PathBuf,
    local: RwLock<HashMap<String, Arc<dyn ReplicationTarget>>>,
    cache: Mutex<HashMap<String, Arc<dyn ReplicationTarget>>>,
}

fn target_key(arn: &str) -> Vec<u8> {
    let mut k = TARGET_PREFIX.to_vec();
    k.extend_from_slice(arn.as_bytes());
    k
}

fn secret_cipher(key: &[u8; 32]) -> chacha20poly1305::ChaCha20Poly1305 {
    use chacha20poly1305::KeyInit;
    let sub = Zeroizing::new(blake3::derive_key(
        "tidemark replication target secret v1",
        key,
    ));
    chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(sub.as_ref()))
}

impl TargetRegistry {
    /// Registry over `engine`'s metadata; secrets are sealed with `sealing_key` (derive it from
    /// the server master key). Remote targets spool parts under `<data_dir>/tmp`.
    pub fn new(engine: &TidemarkEngine, sealing_key: [u8; 32]) -> TargetRegistry {
        TargetRegistry {
            meta: engine.meta().clone(),
            key: Zeroizing::new(sealing_key),
            spool: engine.data_dir().join("tmp"),
            local: RwLock::new(HashMap::new()),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Register an in-process target for `arn` (takes precedence over persisted ones).
    pub fn register(&self, arn: &str, t: Arc<dyn ReplicationTarget>) {
        self.local
            .write()
            .expect("registry lock")
            .insert(arn.to_string(), t);
    }

    /// Persist (create or replace) a remote target.
    pub async fn put(&self, cfg: &TargetConfig) -> S3Result<()> {
        use chacha20poly1305::aead::{Aead, Payload};
        if !cfg.arn.starts_with(ARN_PREFIX) {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "target ARN must look like arn:aws:s3:::bucket",
            ));
        }
        let nonce: [u8; 12] = rand::random();
        let ct = secret_cipher(&self.key)
            .encrypt(
                chacha20poly1305::Nonce::from_slice(&nonce),
                Payload {
                    msg: cfg.endpoint.secret_key.as_bytes(),
                    aad: cfg.arn.as_bytes(),
                },
            )
            .map_err(|_| S3Error::internal("sealing target secret failed"))?;
        let mut sealed = nonce.to_vec();
        sealed.extend(ct);
        let rec = TargetRecord {
            arn: cfg.arn.clone(),
            endpoint: cfg.endpoint.endpoint.clone(),
            region: cfg.endpoint.region.clone(),
            bucket: cfg.endpoint.bucket.clone(),
            prefix: cfg.endpoint.prefix.clone(),
            access_key: cfg.endpoint.access_key.clone(),
            sealed_secret: sealed,
            path_style: cfg.endpoint.path_style,
            tidemark_peer: cfg.tidemark_peer,
        };
        let (k, v) = (target_key(&cfg.arn), encode(&rec));
        self.meta
            .write(move |txn| txn.put(Table::Kv, &k, &v))
            .await?;
        self.cache.lock().expect("cache").remove(&cfg.arn);
        Ok(())
    }

    /// Remove a persisted target.
    pub async fn remove(&self, arn: &str) -> S3Result<bool> {
        let k = target_key(arn);
        let gone = self.meta.write(move |txn| txn.del(Table::Kv, &k)).await?;
        self.cache.lock().expect("cache").remove(arn);
        Ok(gone)
    }

    /// Persisted targets (without secrets).
    pub fn list(&self) -> S3Result<Vec<TargetInfo>> {
        let r = self.meta.read()?;
        let mut out = Vec::new();
        r.scan_prefix(Table::Kv, TARGET_PREFIX, &mut |_, v| {
            let t: TargetRecord = decode(v)?;
            out.push(TargetInfo {
                arn: t.arn,
                endpoint: t.endpoint,
                bucket: t.bucket,
                access_key: t.access_key,
                tidemark_peer: t.tidemark_peer,
            });
            Ok(Flow::Continue)
        })?;
        Ok(out)
    }

    fn load(&self, arn: &str) -> Result<Option<TargetConfig>, ReplError> {
        use chacha20poly1305::aead::{Aead, Payload};
        let r = self
            .meta
            .read()
            .map_err(|e| ReplError::Transient(e.to_string()))?;
        let Some(raw) = r
            .get(Table::Kv, &target_key(arn))
            .map_err(|e| ReplError::Transient(e.to_string()))?
        else {
            return Ok(None);
        };
        let t: TargetRecord = decode(&raw).map_err(|e| ReplError::Transient(e.to_string()))?;
        if t.sealed_secret.len() < 12 {
            return Err(ReplError::Transient("corrupt target secret".into()));
        }
        let (nonce, ct) = t.sealed_secret.split_at(12);
        let secret = secret_cipher(&self.key)
            .decrypt(
                chacha20poly1305::Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: arn.as_bytes(),
                },
            )
            .map_err(|_| {
                ReplError::Transient("target secret does not decrypt (key changed?)".into())
            })?;
        let secret = Zeroizing::new(
            String::from_utf8(secret).map_err(|_| ReplError::Transient("bad secret".into()))?,
        );
        Ok(Some(TargetConfig {
            arn: t.arn,
            endpoint: S3Endpoint {
                endpoint: t.endpoint,
                region: t.region,
                bucket: t.bucket,
                prefix: t.prefix,
                access_key: t.access_key,
                secret_key: secret.to_string(),
                path_style: t.path_style,
            },
            tidemark_peer: t.tidemark_peer,
        }))
    }
}

impl TargetResolver for TargetRegistry {
    fn resolve(&self, arn: &str) -> Result<Option<Arc<dyn ReplicationTarget>>, ReplError> {
        if let Some(t) = self.local.read().expect("registry lock").get(arn) {
            return Ok(Some(t.clone()));
        }
        if let Some(t) = self.cache.lock().expect("cache").get(arn) {
            return Ok(Some(t.clone()));
        }
        let Some(cfg) = self.load(arn)? else {
            return Ok(None);
        };
        let t: Arc<dyn ReplicationTarget> =
            Arc::new(S3Target::new(&cfg.endpoint, cfg.tidemark_peer, &self.spool));
        self.cache
            .lock()
            .expect("cache")
            .insert(arn.to_string(), t.clone());
        Ok(Some(t))
    }
}

// ---------------------------------------------------------------------------------------------
// Engine API: bucket config + replica writes
// ---------------------------------------------------------------------------------------------

impl TidemarkEngine {
    /// PutBucketReplication: validate, require versioning `Enabled`, store the document and seed
    /// a cursor per destination (at "now" unless the rule enables ExistingObjectReplication).
    pub async fn put_bucket_replication(&self, bucket: &str, xml: &str) -> S3Result<()> {
        let cfg = ReplicationConfiguration::from_xml(xml)?;
        let b = self.bucket(bucket)?;
        if b.versioning != Versioning::Enabled {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Versioning must be 'Enabled' on the bucket to apply a replication configuration",
            ));
        }
        self.put_bucket_config(bucket, CONFIG_KIND, Some(cfg.to_xml().into_bytes()))
            .await?;
        let now = Ts::now();
        let seeds: Vec<(String, Option<Ts>)> = cfg
            .destinations()
            .into_iter()
            .map(|d| {
                let existing = cfg.rules.iter().any(|r| {
                    r.enabled
                        && r.destination.bucket_arn == d
                        && r.existing_object_replication == Some(true)
                });
                (d, if existing { None } else { Some(now) })
            })
            .collect();
        let id = b.id;
        self.meta()
            .write(move |txn| -> Result<(), MetaError> {
                for (d, wm) in &seeds {
                    let k = cursor_key(id, d);
                    if txn.get(Table::ReplCursor, &k)?.is_none() {
                        let c = ReplCursor {
                            since: *wm,
                            watermark: *wm,
                            ..Default::default()
                        };
                        txn.put(Table::ReplCursor, &k, &encode(&c))?;
                    }
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// GetBucketReplication (`None` → `ReplicationConfigurationNotFoundError`).
    pub fn get_bucket_replication(
        &self,
        bucket: &str,
    ) -> S3Result<Option<ReplicationConfiguration>> {
        let b = self.bucket(bucket)?;
        bucket_replication(&b)
    }

    /// DeleteBucketReplication (cursors are dropped so a later configuration starts fresh).
    pub async fn delete_bucket_replication(&self, bucket: &str) -> S3Result<()> {
        let b = self.bucket(bucket)?;
        self.put_bucket_config(bucket, CONFIG_KIND, None).await?;
        let id = b.id;
        self.meta()
            .write(move |txn| -> Result<(), MetaError> {
                let mut ks = Vec::new();
                txn.scan_prefix(Table::ReplCursor, &id.to_bytes(), &mut |k, _| {
                    ks.push(k.to_vec());
                    Ok(Flow::Continue)
                })?;
                for k in &ks {
                    txn.del(Table::ReplCursor, k)?;
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Replication status of a source version for header `x-amz-replication-status`
    /// (`None` when no rule selects it). PENDING until every selecting destination has it.
    pub fn replication_status(
        &self,
        bucket: &BucketRecord,
        v: &VersionRecord,
    ) -> S3Result<Option<ReplicationStatus>> {
        status_from(&self.read()?, bucket, v)
    }

    /// Write a replica of `v` into `bucket` keeping its version id, timestamps, metadata, tags and
    /// part layout. `data = None` writes a delete marker. Returns `false` if that version id is
    /// already present (idempotent re-delivery). The bucket must have versioning `Enabled`.
    /// This is also what the S3 layer calls for a PUT / DELETE / CompleteMultipartUpload carrying
    /// `x-tidemark-version-id` from a principal allowed `tidemark:ReplicateObject`.
    pub async fn put_replica(
        &self,
        bucket: &str,
        v: &VersionRecord,
        data: Option<&dyn PartSource>,
    ) -> S3Result<bool> {
        let b = self.bucket(bucket)?;
        if b.versioning != Versioning::Enabled {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "replica bucket must have versioning enabled",
            ));
        }
        if self.read()?.version(b.id, &v.key, &v.version_id)?.is_some() {
            return Ok(false);
        }
        let mut written = Vec::new();
        let kind = match (&v.kind, data) {
            (VersionKind::DeleteMarker, _) => VersionKind::DeleteMarker,
            (VersionKind::Object(_), None) => {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "object replica without data",
                ));
            }
            (VersionKind::Object(body), Some(src)) => {
                for (i, p) in body.parts.iter().enumerate() {
                    let res = self.copy_part_in(src, i, p).await;
                    match res {
                        Ok(deduped) => {
                            if !deduped {
                                written.push(p.blob);
                            }
                        }
                        Err(e) => {
                            for id in written {
                                self.discard_blob(id).await;
                            }
                            return Err(e);
                        }
                    }
                }
                VersionKind::Object(body.clone())
            }
        };
        let rec = VersionRecord {
            key: v.key.clone(),
            version_id: v.version_id,
            created_at: v.created_at,
            is_null: false,
            kind,
            state: VersionState::Live,
            lock: None,
            legal_hold: false,
            owner: v.owner.clone(),
        };
        let (blobs, bn, id) = (self.blobs().clone(), bucket.to_string(), b.id);
        let res = self
            .meta()
            .write(move |txn| -> S3Result<bool> {
                active_bucket(txn, id, &bn)?;
                if txn.version(id, &rec.key, &rec.version_id)?.is_some() {
                    return Ok(false);
                }
                if let Some(body) = rec.body() {
                    for p in &body.parts {
                        incref_checked(txn, &blobs, &p.blob, p.size)?;
                    }
                }
                txn.put_version(id, &rec)?;
                txn.refresh_latest(id, &rec.key)?;
                Ok(true)
            })
            .await;
        if !matches!(res, Ok(true)) {
            for id in written {
                self.discard_blob(id).await;
            }
        }
        res
    }

    /// Stream one part into the local blob store and check it hashes to the source blob id.
    /// Returns whether the blob already existed.
    async fn copy_part_in(&self, src: &dyn PartSource, i: usize, p: &PartRef) -> S3Result<bool> {
        let mut r = src.open_part(i).await.map_err(|e| match e {
            ReplError::Transient(m) => S3Error::new(S3ErrorCode::ServiceUnavailable, m),
            ReplError::Permanent(m) => S3Error::new(S3ErrorCode::InvalidRequest, m),
        })?;
        let mut w = self
            .blobs()
            .begin_write(WriteOpts {
                key: self.config().at_rest_key.clone(),
                ..Default::default()
            })
            .await?;
        while let Some(c) = r.next().await {
            let c = c.map_err(|e| S3Error::new(S3ErrorCode::ServiceUnavailable, e.to_string()))?;
            w.write_all(&c).await?;
        }
        let d = w.finish().await?;
        if d.blob_id != p.blob || d.size != p.size {
            if !d.deduped {
                self.discard_blob(d.blob_id).await;
            }
            return Err(S3Error::new(
                S3ErrorCode::BadDigest,
                format!(
                    "replica part {} does not match source blob {}",
                    p.number, p.blob
                ),
            ));
        }
        Ok(d.deduped)
    }
}

/// Parse a bucket's stored replication document.
pub fn bucket_replication(b: &BucketRecord) -> S3Result<Option<ReplicationConfiguration>> {
    match b.configs.get(CONFIG_KIND) {
        None => Ok(None),
        Some(x) => {
            let s = std::str::from_utf8(x).map_err(|_| malformed("stored document not UTF-8"))?;
            ReplicationConfiguration::from_xml(s).map(Some)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------------------------

/// Worker settings.
#[derive(Debug, Clone)]
pub struct ReplicationSettings {
    /// Pause between ticks in [`ReplicationWorker::run`].
    pub interval: Duration,
    /// Versions delivered per destination per tick.
    pub batch: usize,
    /// Re-check window below the watermark (absorbs wall-clock steps).
    pub overlap: Duration,
    /// First retry delay after a transient failure.
    pub backoff_base: Duration,
    /// Retry delay cap.
    pub backoff_max: Duration,
    /// Persist the cursor at least every this many deliveries.
    pub checkpoint_every: usize,
}

impl Default for ReplicationSettings {
    fn default() -> Self {
        ReplicationSettings {
            interval: Duration::from_secs(2),
            batch: 1000,
            overlap: Duration::from_secs(5),
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(300),
            checkpoint_every: 32,
        }
    }
}

/// Per-destination state after a tick (feed `/metrics`: lag, pending, delivered, failed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DestinationStatus {
    /// Source bucket name.
    pub bucket: String,
    /// Destination ARN.
    pub destination: String,
    /// Versions still waiting.
    pub pending: u64,
    /// Age of the oldest waiting version (zero when caught up).
    pub lag: Duration,
    /// Delivered so far (cursor lifetime).
    pub delivered: u64,
    /// Permanently failed so far.
    pub failed: u64,
    /// Last error message.
    pub last_error: Option<String>,
    /// In backoff until the next attempt.
    pub backing_off: bool,
}

/// Hook for metrics / logging.
pub trait ReplicationObserver: Send + Sync {
    /// Called once per destination per tick.
    fn observe(&self, status: &DestinationStatus);
}

/// What one tick did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReplTickStats {
    /// Versions delivered.
    pub delivered: u64,
    /// Versions skipped (no rule selects them, or permanent failure).
    pub skipped: u64,
    /// Versions failed permanently.
    pub failed: u64,
    /// Destinations that hit a transient error (now backing off).
    pub transient_errors: u64,
    /// Per-destination state.
    pub destinations: Vec<DestinationStatus>,
}

struct Backoff {
    failures: u32,
    until: Instant,
}

/// Replication worker over one engine.
pub struct ReplicationWorker {
    engine: TidemarkEngine,
    targets: Arc<dyn TargetResolver>,
    cfg: ReplicationSettings,
    observer: Option<Arc<dyn ReplicationObserver>>,
    backoff: Mutex<HashMap<(BucketId, String), Backoff>>,
}

enum Item {
    Done,
    Skip,
    Failed(String),
}

impl ReplicationWorker {
    /// Worker with default settings.
    pub fn new(engine: TidemarkEngine, targets: Arc<dyn TargetResolver>) -> ReplicationWorker {
        ReplicationWorker::with_settings(engine, targets, ReplicationSettings::default())
    }

    /// Worker with explicit settings.
    pub fn with_settings(
        engine: TidemarkEngine,
        targets: Arc<dyn TargetResolver>,
        cfg: ReplicationSettings,
    ) -> ReplicationWorker {
        ReplicationWorker {
            engine,
            targets,
            cfg,
            observer: None,
            backoff: Mutex::new(HashMap::new()),
        }
    }

    /// Attach a metrics/lag observer.
    pub fn with_observer(mut self, o: Arc<dyn ReplicationObserver>) -> ReplicationWorker {
        self.observer = Some(o);
        self
    }

    /// Clear backoff state (operator "retry now").
    pub fn reset_backoff(&self) {
        self.backoff.lock().expect("backoff").clear();
    }

    /// One pass over every replicated bucket.
    pub async fn tick(&self) -> S3Result<ReplTickStats> {
        let buckets: Vec<BucketRecord> = self
            .engine
            .list_buckets()?
            .into_iter()
            .filter(|b| b.state == BucketState::Active && b.configs.contains_key(CONFIG_KIND))
            .collect();
        let mut st = ReplTickStats::default();
        for b in buckets {
            let cfg = match bucket_replication(&b) {
                Ok(Some(c)) => c,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(bucket = %b.name, error = %e, "bad stored replication config");
                    continue;
                }
            };
            for dest in cfg.destinations() {
                let s = self.run_destination(&b, &cfg, &dest, &mut st).await?;
                if let Some(o) = &self.observer {
                    o.observe(&s);
                }
                st.destinations.push(s);
            }
        }
        Ok(st)
    }

    async fn run_destination(
        &self,
        b: &BucketRecord,
        cfg: &ReplicationConfiguration,
        dest: &str,
        st: &mut ReplTickStats,
    ) -> S3Result<DestinationStatus> {
        let bkey = (b.id, dest.to_string());
        let backing_off = self
            .backoff
            .lock()
            .expect("backoff")
            .get(&bkey)
            .is_some_and(|x| x.until > Instant::now());
        let r = self.engine.read()?;
        let mut cur = load_cursor(&r, b.id, dest)?.unwrap_or_else(|| {
            let now = Ts::now();
            ReplCursor {
                since: Some(now),
                watermark: Some(now),
                ..Default::default()
            }
        });
        let floor = cur.watermark.map(|w| w.minus(self.cfg.overlap));
        let mut pending: Vec<VersionRecord> = Vec::new();
        r.scan_prefix(Table::Versions, &b.id.to_bytes(), &mut |_, v| {
            let rec: VersionRecord = decode(v)?;
            if rec.is_live()
                && floor.is_none_or(|f| rec.created_at > f)
                && cur.since.is_none_or(|s| rec.created_at >= s)
                && !cur.recent.contains(&rec.version_id)
            {
                pending.push(rec);
            }
            Ok(Flow::Continue)
        })?;
        drop(r);
        pending.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.key.cmp(&b.key))
        });
        let now = Ts::now();
        let mut status = DestinationStatus {
            bucket: b.name.clone(),
            destination: dest.to_string(),
            pending: pending.len() as u64,
            lag: pending
                .first()
                .map(|v| {
                    Duration::from_nanos((now.0 - v.created_at.0).clamp(0, u64::MAX as i128) as u64)
                })
                .unwrap_or_default(),
            delivered: cur.delivered,
            failed: cur.failed,
            last_error: cur.last_error.clone(),
            backing_off,
        };
        if backing_off || pending.is_empty() {
            return Ok(status);
        }
        let target = match self.targets.resolve(dest) {
            Ok(Some(t)) => t,
            Ok(None) => {
                let msg = format!("no replication target registered for {dest}");
                return self
                    .fail_transient(b, dest, &mut cur, msg, status, st)
                    .await;
            }
            Err(e) => {
                return self
                    .fail_transient(b, dest, &mut cur, e.to_string(), status, st)
                    .await;
            }
        };
        let mut since_checkpoint = 0usize;
        for v in pending.into_iter().take(self.cfg.batch.max(1)) {
            let item = match cfg.rule_for(dest, &v) {
                None => Item::Skip,
                Some(_) => {
                    let res = if v.is_delete_marker() {
                        target.replicate_delete_marker(&v).await
                    } else {
                        let src = EnginePartSource::new(&self.engine, &v);
                        target.replicate_object(&v, &src).await
                    };
                    match res {
                        Ok(()) => Item::Done,
                        Err(ReplError::Permanent(m)) => Item::Failed(m),
                        Err(ReplError::Transient(m)) => {
                            self.save_cursor(b.id, dest, &cur).await?;
                            status.delivered = cur.delivered;
                            return self.fail_transient(b, dest, &mut cur, m, status, st).await;
                        }
                    }
                }
            };
            match item {
                Item::Done => {
                    cur.delivered += 1;
                    cur.last_success = Some(Ts::now());
                    st.delivered += 1;
                }
                Item::Skip => st.skipped += 1,
                Item::Failed(m) => {
                    tracing::warn!(bucket = %b.name, key = %v.key, destination = dest, error = %m, "replication failed permanently; skipping version");
                    cur.failed += 1;
                    cur.last_error = Some(m);
                    st.failed += 1;
                    st.skipped += 1;
                }
            }
            self.advance(&mut cur, &v);
            status.pending -= 1;
            since_checkpoint += 1;
            if since_checkpoint >= self.cfg.checkpoint_every.max(1) {
                self.save_cursor(b.id, dest, &cur).await?;
                since_checkpoint = 0;
            }
        }
        if cur.last_error.is_some() && status.failed == cur.failed {
            cur.last_error = None;
        }
        self.save_cursor(b.id, dest, &cur).await?;
        self.backoff.lock().expect("backoff").remove(&bkey);
        status.delivered = cur.delivered;
        status.failed = cur.failed;
        status.last_error = cur.last_error.clone();
        if status.pending == 0 {
            status.lag = Duration::ZERO;
        }
        Ok(status)
    }

    fn advance(&self, cur: &mut ReplCursor, v: &VersionRecord) {
        let w = cur.watermark.map_or(v.created_at, |w| w.max(v.created_at));
        cur.watermark = Some(w);
        cur.recent.push(v.version_id);
        let floor = w.minus(self.cfg.overlap);
        cur.recent.retain(|id| id.created_at() > floor);
    }

    async fn save_cursor(&self, b: BucketId, dest: &str, cur: &ReplCursor) -> S3Result<()> {
        let (k, v) = (cursor_key(b, dest), encode(cur));
        self.engine
            .meta()
            .write(move |txn| txn.put(Table::ReplCursor, &k, &v))
            .await?;
        Ok(())
    }

    async fn fail_transient(
        &self,
        b: &BucketRecord,
        dest: &str,
        cur: &mut ReplCursor,
        msg: String,
        mut status: DestinationStatus,
        st: &mut ReplTickStats,
    ) -> S3Result<DestinationStatus> {
        let delay = {
            let mut m = self.backoff.lock().expect("backoff");
            let e = m.entry((b.id, dest.to_string())).or_insert(Backoff {
                failures: 0,
                until: Instant::now(),
            });
            e.failures = e.failures.saturating_add(1);
            let d = self
                .cfg
                .backoff_base
                .saturating_mul(1u32 << (e.failures - 1).min(20))
                .min(self.cfg.backoff_max);
            e.until = Instant::now() + d;
            d
        };
        tracing::warn!(bucket = %b.name, destination = dest, error = %msg, retry_in = ?delay, "replication delivery failed; backing off");
        cur.last_error = Some(msg.clone());
        self.save_cursor(b.id, dest, cur).await?;
        st.transient_errors += 1;
        status.last_error = Some(msg);
        status.backing_off = true;
        Ok(status)
    }

    /// Run ticks every `interval` until `shutdown` resolves.
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()> + Send) {
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            if let Err(e) = self.tick().await {
                tracing::warn!(error = %e, "replication tick failed");
            }
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(self.cfg.interval) => {}
            }
        }
    }
}

/// `x-amz-replication-status` for the version `v` of bucket `b`, read from a snapshot.
pub fn status_from<R: Reader + ?Sized>(
    r: &R,
    b: &BucketRecord,
    v: &VersionRecord,
) -> S3Result<Option<ReplicationStatus>> {
    let Some(cfg) = bucket_replication(b)? else {
        return Ok(None);
    };
    let mut any = false;
    for d in cfg.destinations() {
        if cfg.rule_for(&d, v).is_none() {
            continue;
        }
        any = true;
        let c = r
            .get(Table::ReplCursor, &cursor_key(b.id, &d))?
            .map(|x| decode::<ReplCursor>(&x))
            .transpose()?;
        if c.as_ref()
            .is_some_and(|c| c.since.is_some_and(|s| v.created_at < s))
        {
            continue;
        }
        let done = c.is_some_and(|c| {
            c.recent.contains(&v.version_id) || c.watermark.is_some_and(|w| v.created_at <= w)
        });
        if !done {
            return Ok(Some(ReplicationStatus::Pending));
        }
    }
    Ok(any.then_some(ReplicationStatus::Completed))
}
