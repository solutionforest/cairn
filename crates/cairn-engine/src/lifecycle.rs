//! Bucket lifecycle rules (S3 `PutBucketLifecycleConfiguration` subset): current-version
//! expiration (days / date), expired delete-marker cleanup, noncurrent-version expiration and
//! abort of incomplete multipart uploads. Expiration goes through soft delete with reason
//! `Lifecycle`, so it is recoverable from the trash like any other delete (DESIGN §7.2).
//! Transitions are not supported (single storage class).

use crate::CairnEngine;
use crate::commit::{active_bucket, commit_version, soft_delete_as};
use crate::types::WriteConditions;
use cairn_core::{PrincipalId, S3Error, S3ErrorCode, S3Result, Ts, VersionId};
use cairn_events::EventName;
use cairn_meta::{
    BucketRecord, DeleteReason, Flow, MultipartRecord, ReadExt, Reader, Table, VersionKind,
    VersionRecord, Versioning, decode, pitr,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

/// Bucket config key of the lifecycle document.
pub const CONFIG_KIND: &str = "lifecycle";
const DAY: u64 = 86_400;
/// Most rules a configuration may hold (AWS limit).
pub const MAX_RULES: usize = 1000;

/// Which objects a rule applies to (all conditions must hold).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleFilter {
    /// Key prefix (empty = every key).
    pub prefix: String,
    /// Tags the object must carry.
    pub tags: BTreeMap<String, String>,
    /// Object size must be greater than this.
    pub size_greater_than: Option<u64>,
    /// Object size must be less than this.
    pub size_less_than: Option<u64>,
}

/// One lifecycle rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleRule {
    /// Rule id.
    pub id: Option<String>,
    /// `Status = Enabled`.
    pub enabled: bool,
    /// Filter.
    pub filter: LifecycleFilter,
    /// Expire current versions this many days after creation.
    pub expiration_days: Option<u32>,
    /// Expire current versions on/after this date.
    pub expiration_date: Option<Ts>,
    /// Remove delete markers that have no noncurrent versions left.
    pub expired_object_delete_marker: bool,
    /// Expire noncurrent versions this many days after they became noncurrent.
    pub noncurrent_days: Option<u32>,
    /// Keep this many newest noncurrent versions regardless of age.
    pub newer_noncurrent_versions: Option<u32>,
    /// Abort multipart uploads this many days after initiation.
    pub abort_incomplete_multipart_days: Option<u32>,
}

/// A bucket's lifecycle configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleConfiguration {
    /// Rules in document order.
    pub rules: Vec<LifecycleRule>,
}

fn invalid(msg: impl Into<String>) -> S3Error {
    S3Error::new(S3ErrorCode::InvalidArgument, msg)
}

impl LifecycleConfiguration {
    /// Semantic validation (AWS rules that matter for evaluation).
    pub fn validate(&self) -> S3Result<()> {
        if self.rules.is_empty() {
            return Err(S3Error::new(
                S3ErrorCode::MalformedXML,
                "a lifecycle configuration needs at least one rule",
            ));
        }
        if self.rules.len() > MAX_RULES {
            return Err(invalid("too many lifecycle rules"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for r in &self.rules {
            if let Some(id) = &r.id {
                if id.len() > 255 {
                    return Err(invalid("rule ID is longer than 255 characters"));
                }
                if !ids.insert(id.clone()) {
                    return Err(invalid(format!("duplicate rule ID {id:?}")));
                }
            }
            let has_action = r.expiration_days.is_some()
                || r.expiration_date.is_some()
                || r.expired_object_delete_marker
                || r.noncurrent_days.is_some()
                || r.abort_incomplete_multipart_days.is_some();
            if !has_action {
                return Err(invalid(
                    "each rule needs Expiration, NoncurrentVersionExpiration or AbortIncompleteMultipartUpload",
                ));
            }
            if r.expiration_days.is_some() && r.expiration_date.is_some() {
                return Err(invalid("Expiration may set Days or Date, not both"));
            }
            for d in [
                r.expiration_days,
                r.noncurrent_days,
                r.abort_incomplete_multipart_days,
            ]
            .into_iter()
            .flatten()
            {
                if d == 0 {
                    return Err(invalid("lifecycle day counts must be positive"));
                }
            }
            if r.abort_incomplete_multipart_days.is_some() && !r.filter.tags.is_empty() {
                return Err(invalid(
                    "AbortIncompleteMultipartUpload cannot be combined with a tag filter",
                ));
            }
        }
        Ok(())
    }

    fn matches(f: &LifecycleFilter, key: &str, v: &VersionRecord) -> bool {
        if !key.starts_with(&f.prefix) {
            return false;
        }
        let Some(body) = v.body() else {
            return f.tags.is_empty() && f.size_greater_than.is_none();
        };
        f.tags.iter().all(|(k, val)| body.tags.get(k) == Some(val))
            && f.size_greater_than.is_none_or(|n| body.size > n)
            && f.size_less_than.is_none_or(|n| body.size < n)
    }
}

fn days(d: u32) -> Duration {
    Duration::from_secs(u64::from(d) * DAY)
}

/// What one lifecycle pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LifecycleStats {
    /// Current versions expired (soft-deleted or hidden behind a delete marker).
    pub expired: u64,
    /// Noncurrent versions expired.
    pub noncurrent_expired: u64,
    /// Orphaned delete markers removed.
    pub delete_markers_removed: u64,
    /// Multipart uploads aborted.
    pub uploads_aborted: u64,
}

#[derive(Debug)]
enum Action {
    ExpireCurrent(String, VersionId),
    ExpireVersion(String, VersionId, bool),
    Abort(String, String),
}

/// Principal recorded on lifecycle deletes and events.
pub fn lifecycle_principal() -> PrincipalId {
    PrincipalId("cairn:lifecycle".into())
}

/// The lifecycle configuration stored on a bucket record.
pub fn bucket_lifecycle(b: &BucketRecord) -> S3Result<Option<LifecycleConfiguration>> {
    b.configs
        .get(CONFIG_KIND)
        .map(|d| cairn_meta::decode(d).map_err(S3Error::from))
        .transpose()
}

impl CairnEngine {
    /// PutBucketLifecycleConfiguration.
    pub async fn put_bucket_lifecycle(
        &self,
        name: &str,
        cfg: LifecycleConfiguration,
    ) -> S3Result<()> {
        cfg.validate()?;
        self.put_bucket_config(name, CONFIG_KIND, Some(cairn_meta::encode(&cfg)))
            .await
    }

    /// GetBucketLifecycleConfiguration (`None` when unset).
    pub fn get_bucket_lifecycle(&self, name: &str) -> S3Result<Option<LifecycleConfiguration>> {
        bucket_lifecycle(&self.bucket(name)?)
    }

    /// DeleteBucketLifecycle.
    pub async fn delete_bucket_lifecycle(&self, name: &str) -> S3Result<()> {
        self.put_bucket_config(name, CONFIG_KIND, None).await
    }

    /// One lifecycle pass over every bucket with rules, as of `now` (explicit so tests can
    /// fake the clock).
    pub async fn lifecycle_tick(&self, now: Ts) -> S3Result<LifecycleStats> {
        let mut stats = LifecycleStats::default();
        for b in self.list_buckets()? {
            let Some(cfg) = bucket_lifecycle(&b)? else {
                continue;
            };
            let rules: Vec<&LifecycleRule> = cfg.rules.iter().filter(|r| r.enabled).collect();
            if rules.is_empty() {
                continue;
            }
            let actions = self.plan(&b, &rules, now)?;
            for a in actions {
                match self.apply(&b, a, now).await {
                    Ok(Some(kind)) => match kind {
                        0 => stats.expired += 1,
                        1 => stats.noncurrent_expired += 1,
                        2 => stats.delete_markers_removed += 1,
                        _ => stats.uploads_aborted += 1,
                    },
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(bucket = %b.name, error = %e, "lifecycle action failed")
                    }
                }
            }
        }
        if stats != LifecycleStats::default() {
            tracing::info!(?stats, "lifecycle tick");
        }
        Ok(stats)
    }

    fn plan(&self, b: &BucketRecord, rules: &[&LifecycleRule], now: Ts) -> S3Result<Vec<Action>> {
        let r = self.read()?;
        let mut out = Vec::new();
        let versioned = b.versioning != Versioning::Off;
        pitr::keys_with_history(&r, b.id, "", |key| {
            let all = r.versions_of(b.id, key)?;
            let live: Vec<&VersionRecord> = all.iter().filter(|v| v.is_live()).collect();
            let Some(cur) = live.first() else {
                return Ok(true);
            };
            for rule in rules {
                if cur.is_delete_marker() {
                    if rule.expired_object_delete_marker
                        && live.len() == 1
                        && key.starts_with(&rule.filter.prefix)
                    {
                        out.push(Action::ExpireVersion(key.to_string(), cur.version_id, true));
                        break;
                    }
                } else if LifecycleConfiguration::matches(&rule.filter, key, cur) {
                    let due = match (rule.expiration_days, rule.expiration_date) {
                        (Some(d), _) => cur.created_at.plus(days(d)) <= now,
                        (None, Some(t)) => t <= now,
                        _ => false,
                    };
                    if due {
                        out.push(Action::ExpireCurrent(key.to_string(), cur.version_id));
                        break;
                    }
                }
            }
            if versioned {
                for rule in rules {
                    let Some(nd) = rule.noncurrent_days else {
                        continue;
                    };
                    if !key.starts_with(&rule.filter.prefix) {
                        continue;
                    }
                    let keep = rule.newer_noncurrent_versions.unwrap_or(0) as usize;
                    for (i, w) in live.windows(2).enumerate() {
                        let (newer, v) = (w[0], w[1]);
                        if i < keep || !LifecycleConfiguration::matches(&rule.filter, key, v) {
                            continue;
                        }
                        if newer.created_at.plus(days(nd)) <= now {
                            out.push(Action::ExpireVersion(key.to_string(), v.version_id, false));
                        }
                    }
                    break;
                }
            }
            Ok(true)
        })?;
        let aborts: Vec<(u32, &str)> = rules
            .iter()
            .filter_map(|r| {
                r.abort_incomplete_multipart_days
                    .map(|d| (d, r.filter.prefix.as_str()))
            })
            .collect();
        if !aborts.is_empty() {
            r.scan_prefix(Table::Uploads, &b.id.to_bytes(), &mut |_, v| {
                let u: MultipartRecord = decode(v)?;
                if aborts
                    .iter()
                    .any(|(d, p)| u.key.starts_with(p) && u.initiated_at.plus(days(*d)) <= now)
                {
                    out.push(Action::Abort(u.key, u.upload_id));
                }
                Ok(Flow::Continue)
            })?;
        }
        Ok(out)
    }

    /// Apply one planned action, re-checking it against current state. Returns the stats slot.
    async fn apply(&self, b: &BucketRecord, a: Action, now: Ts) -> S3Result<Option<u8>> {
        let by = lifecycle_principal();
        if let Action::Abort(key, upload) = &a {
            return match self.abort_multipart_upload(&b.name, key, upload).await {
                Ok(()) => Ok(Some(3)),
                Err(e) if e.code == S3ErrorCode::NoSuchUpload => Ok(None),
                Err(e) => Err(e),
            };
        }
        let inner = self.inner.clone();
        let em = self.emitter(&by);
        let (id, name) = (b.id, b.name.clone());
        let res = self
            .inner
            .meta
            .write(move |txn| -> S3Result<Option<u8>> {
                let b = active_bucket(txn, id, &name)?;
                let now = now.max(crate::commit::now_for_key(txn, id, key_of(&a))?);
                match &a {
                    Action::ExpireCurrent(key, vid) => {
                        let Some(cur) = txn.latest(id, key)? else {
                            return Ok(None);
                        };
                        if cur.version_id != *vid || cur.is_delete_marker() {
                            return Ok(None);
                        }
                        if b.versioning == Versioning::Off {
                            em.emit(
                                txn,
                                &b,
                                EventName::LifecycleExpirationDelete,
                                key,
                                Some(&cur),
                                Vec::new(),
                            )?;
                            soft_delete_as(
                                txn,
                                &b,
                                &inner.cfg,
                                cur,
                                now,
                                &by,
                                DeleteReason::Lifecycle,
                            )?;
                            txn.refresh_latest(id, key)?;
                        } else {
                            if b.versioning == Versioning::Suspended
                                && let Some(old) = txn.null_version(id, key, false)?
                            {
                                soft_delete_as(
                                    txn,
                                    &b,
                                    &inner.cfg,
                                    old,
                                    now,
                                    &by,
                                    DeleteReason::Lifecycle,
                                )?;
                            }
                            let (v, b) = commit_version(
                                txn,
                                &inner.blobs,
                                &inner.cfg,
                                id,
                                &name,
                                key,
                                VersionKind::DeleteMarker,
                                &by,
                                &WriteConditions::default(),
                            )?;
                            em.emit(
                                txn,
                                &b,
                                EventName::LifecycleExpirationDeleteMarkerCreated,
                                key,
                                Some(&v),
                                Vec::new(),
                            )?;
                        }
                        Ok(Some(0))
                    }
                    Action::ExpireVersion(key, vid, is_marker) => {
                        let Some(v) = txn.version(id, key, vid)?.filter(|v| v.is_live()) else {
                            return Ok(None);
                        };
                        if v.legal_hold || v.lock.is_some_and(|l| l.retain_until > now) {
                            return Ok(None);
                        }
                        em.emit(
                            txn,
                            &b,
                            EventName::LifecycleExpirationDelete,
                            key,
                            Some(&v),
                            Vec::new(),
                        )?;
                        soft_delete_as(txn, &b, &inner.cfg, v, now, &by, DeleteReason::Lifecycle)?;
                        txn.refresh_latest(id, key)?;
                        Ok(Some(if *is_marker { 2 } else { 1 }))
                    }
                    Action::Abort(..) => Ok(None),
                }
            })
            .await?;
        self.notify();
        Ok(res)
    }
}

fn key_of(a: &Action) -> &str {
    match a {
        Action::ExpireCurrent(k, _) | Action::ExpireVersion(k, _, _) | Action::Abort(k, _) => k,
    }
}
