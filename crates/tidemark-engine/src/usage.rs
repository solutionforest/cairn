//! Per-bucket usage counters (kv `usage/<BucketId>`) and bucket quotas (`BucketRecord.configs`
//! key [`QUOTA_CONFIG`]). Counters are maintained inside the same write job as the mutation and
//! initialised by a one-time scan of the bucket's versions when missing (pre-counter data).

use serde::{Deserialize, Serialize};
use tidemark_core::{BucketId, S3Error, S3ErrorCode, S3Result};
use tidemark_meta::{
    BucketRecord, Flow, MetaError, Reader, Table, VersionRecord, WriteTxn, decode, encode,
};

/// Bucket config key holding the quota as a big-endian `u64` byte count.
pub const QUOTA_CONFIG: &str = "tidemark.quota";
const PREFIX: &[u8] = b"usage/";

/// Storage accounting of one bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketUsage {
    /// Bytes of every stored version (live and hidden) until GC purges it.
    pub stored_bytes: u64,
    /// Bytes of soft-deleted / superseded versions (trash and shadow history).
    pub hidden_bytes: u64,
    /// Live object versions (current and noncurrent; delete markers excluded).
    pub objects: u64,
    /// Hidden versions.
    pub hidden_versions: u64,
}

impl BucketUsage {
    /// Bytes counted against the quota: everything not in the trash.
    pub fn live_bytes(&self) -> u64 {
        self.stored_bytes.saturating_sub(self.hidden_bytes)
    }
}

fn key(b: BucketId) -> Vec<u8> {
    let mut k = PREFIX.to_vec();
    k.extend_from_slice(&b.to_bytes());
    k
}

fn size_of(v: &VersionRecord) -> u64 {
    v.body().map_or(0, |b| b.size)
}

/// Recompute a bucket's usage from its version rows.
pub fn compute<R: Reader + ?Sized>(r: &R, b: BucketId) -> Result<BucketUsage, MetaError> {
    let mut u = BucketUsage::default();
    r.scan_prefix(Table::Versions, &b.to_bytes(), &mut |_, v| {
        let v: VersionRecord = decode(v)?;
        let n = size_of(&v);
        u.stored_bytes += n;
        if v.is_live() {
            if !v.is_delete_marker() {
                u.objects += 1;
            }
        } else {
            u.hidden_bytes += n;
            u.hidden_versions += 1;
        }
        Ok(Flow::Continue)
    })?;
    Ok(u)
}

/// Stored counters, or a fresh computation when none exist yet.
pub fn load<R: Reader + ?Sized>(r: &R, b: BucketId) -> Result<BucketUsage, MetaError> {
    match r.get(Table::Kv, &key(b))? {
        Some(v) => decode(&v),
        None => compute(r, b),
    }
}

fn adjust(txn: &WriteTxn, b: BucketId, f: impl FnOnce(&mut BucketUsage)) -> Result<(), MetaError> {
    let mut u = load(txn, b)?;
    f(&mut u);
    txn.put(Table::Kv, &key(b), &encode(&u))
}

/// A new Live version is about to be written.
pub(crate) fn on_create(txn: &WriteTxn, b: BucketId, v: &VersionRecord) -> Result<(), MetaError> {
    let n = size_of(v);
    let obj = !v.is_delete_marker();
    adjust(txn, b, |u| {
        u.stored_bytes += n;
        u.objects += u64::from(obj);
    })
}

/// A Live version is about to become hidden.
pub(crate) fn on_hide(txn: &WriteTxn, b: BucketId, v: &VersionRecord) -> Result<(), MetaError> {
    if !v.is_live() {
        return Ok(());
    }
    let n = size_of(v);
    let obj = !v.is_delete_marker();
    adjust(txn, b, |u| {
        u.hidden_bytes += n;
        u.hidden_versions += 1;
        u.objects = u.objects.saturating_sub(u64::from(obj));
    })
}

/// A version row is about to be hard-deleted.
pub(crate) fn on_purge(txn: &WriteTxn, b: BucketId, v: &VersionRecord) -> Result<(), MetaError> {
    let n = size_of(v);
    let live = v.is_live();
    let obj = !v.is_delete_marker();
    adjust(txn, b, |u| {
        u.stored_bytes = u.stored_bytes.saturating_sub(n);
        if live {
            u.objects = u.objects.saturating_sub(u64::from(obj));
        } else {
            u.hidden_bytes = u.hidden_bytes.saturating_sub(n);
            u.hidden_versions = u.hidden_versions.saturating_sub(1);
        }
    })
}

/// Drop a purged bucket's counters.
pub(crate) fn forget(txn: &WriteTxn, b: BucketId) -> Result<(), MetaError> {
    txn.del(Table::Kv, &key(b))?;
    Ok(())
}

/// The bucket's quota in bytes, if one is set.
pub fn quota(b: &BucketRecord) -> Option<u64> {
    b.configs
        .get(QUOTA_CONFIG)
        .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
        .map(u64::from_be_bytes)
}

/// Refuse a write of `adding` bytes that would push the bucket's live bytes over its quota.
pub(crate) fn check_quota(txn: &WriteTxn, b: &BucketRecord, adding: u64) -> S3Result<()> {
    let Some(q) = quota(b) else {
        return Ok(());
    };
    let u = load(txn, b.id)?;
    if u.live_bytes().saturating_add(adding) > q {
        return Err(S3Error::new(
            S3ErrorCode::QuotaExceeded,
            format!(
                "The bucket quota of {q} bytes would be exceeded ({} bytes in use).",
                u.live_bytes()
            ),
        )
        .with_resource(b.name.clone()));
    }
    Ok(())
}
