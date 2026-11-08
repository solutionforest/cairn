//! `cairn fsck` (DESIGN §9, PRODUCTION-READINESS C3): metadata ↔ blob consistency.
//!
//! Checks orphan blobs (file on disk, no `blobs` row), missing blobs (referenced, not on disk),
//! refcount drift (recount from `versions` + `uploads`), corrupt blobs (BLAKE3 mismatch, sampled
//! or full), dangling multipart uploads and `latest` rows that disagree with the newest Live
//! version. `repair` fixes only what is safe and reversible:
//! - refcounts are rewritten with a compare-and-set against the value fsck saw, so concurrent
//!   traffic is never overwritten (changed rows are reported as skipped);
//! - orphan files are indexed into `blob_gc_idx` with refcount 0, so the normal GC removes them
//!   after its grace period (nothing is unlinked by fsck);
//! - versions whose blobs are missing or corrupt are flagged damaged in `kv` (never deleted);
//!   GET should answer them with an error carrying `x-cairn-damaged: true` (see
//!   [`version_damage`]);
//! - dangling uploads and `latest` rows use the engine's own recovery routines.
//!
//! Damage registry (`kv` table): `damaged/b/<BlobId>` and `damaged/v/<versions key>` →
//! [`DamageRecord`]. `cairn scrub` writes blob entries too, and fsck reports them.

use crate::CairnEngine;
use crate::recovery::BATCH;
use cairn_blob::BlobStore;
use cairn_core::{BlobId, BucketId, S3Error, S3Result, Ts, VersionId};
use cairn_meta::{
    BlobRef, BucketState, Flow, MetaError, MultipartRecord, ReadExt, Reader, Table, VersionRecord,
    WriteTxn, decode, encode, keys,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// `kv` prefix of blob-level damage records.
pub const DAMAGED_BLOB_PREFIX: &[u8] = b"damaged/b/";
/// `kv` prefix of version-level damage records.
pub const DAMAGED_VERSION_PREFIX: &[u8] = b"damaged/v/";
/// Response header GET/HEAD should set on a damaged version.
pub const DAMAGED_HEADER: &str = "x-cairn-damaged";

/// Why a blob is considered damaged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DamageKind {
    /// The blob file is gone.
    Missing,
    /// The blob content no longer hashes to its id.
    Corrupt,
}

/// A damage registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DamageRecord {
    /// Affected blob.
    pub blob: BlobId,
    /// What is wrong.
    pub kind: DamageKind,
    /// When it was detected.
    pub detected_at: Ts,
    /// Detector (`fsck` or `scrub`).
    pub source: String,
}

/// How many blobs fsck re-hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifyMode {
    /// Do not re-hash (fast metadata-only check).
    #[default]
    None,
    /// Re-hash this many randomly chosen referenced blobs.
    Sample(usize),
    /// Re-hash every referenced blob.
    Full,
}

/// fsck options.
#[derive(Debug, Clone)]
pub struct FsckOptions {
    /// Blob re-hashing.
    pub verify: VerifyMode,
    /// Files younger than this are never called orphans (in-flight uploads).
    pub orphan_min_age: Duration,
    /// Apply the safe repairs.
    pub repair: bool,
}

impl Default for FsckOptions {
    fn default() -> Self {
        FsckOptions {
            verify: VerifyMode::None,
            orphan_min_age: Duration::from_secs(3600),
            repair: false,
        }
    }
}

/// One version that references a blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionRef {
    /// Bucket id.
    pub bucket: BucketId,
    /// Object key.
    pub key: String,
    /// Version id.
    pub version_id: VersionId,
}

/// A referenced blob that is missing or corrupt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BadBlob {
    /// Blob id.
    pub blob: BlobId,
    /// Versions referencing it.
    pub versions: Vec<VersionRef>,
    /// Multipart uploads referencing it (`bucket`, `upload_id`).
    pub uploads: Vec<(BucketId, String)>,
}

/// Stored refcount differs from the recount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RefDrift {
    /// Blob id.
    pub blob: BlobId,
    /// Refcount in `blobs` (`None` = no row).
    pub stored: Option<u32>,
    /// References found in `versions` + `uploads`.
    pub actual: u32,
}

/// A multipart upload or index row that cannot be valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DanglingUpload {
    /// Bucket id.
    pub bucket: BucketId,
    /// Upload id.
    pub upload_id: String,
    /// Why.
    pub reason: &'static str,
}

/// What repair changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RepairStats {
    /// Refcounts rewritten.
    pub refcounts_fixed: u64,
    /// Refcounts left alone because they changed while fsck ran.
    pub refcounts_skipped: u64,
    /// Orphan files indexed for GC.
    pub orphans_indexed: u64,
    /// Blobs newly flagged damaged.
    pub blobs_marked_damaged: u64,
    /// Versions newly flagged damaged.
    pub versions_marked_damaged: u64,
    /// Damage flags cleared because the blob is healthy again.
    pub damage_cleared: u64,
    /// Uploads aborted + upload index rows repaired.
    pub uploads_cleaned: u64,
    /// `latest` rows rewritten.
    pub latest_fixed: u64,
}

/// fsck findings.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FsckReport {
    /// Blob files (or cold stubs) found on disk.
    pub blobs_on_disk: u64,
    /// Rows in `blobs`.
    pub blob_rows: u64,
    /// Version rows scanned.
    pub versions_scanned: u64,
    /// Upload rows scanned.
    pub uploads_scanned: u64,
    /// Blobs re-hashed.
    pub blobs_verified: u64,
    /// On disk, no metadata row, older than `orphan_min_age`.
    pub orphan_blobs: Vec<BlobId>,
    /// Referenced but absent.
    pub missing_blobs: Vec<BadBlob>,
    /// Hash mismatch.
    pub corrupt_blobs: Vec<BadBlob>,
    /// Refcount drift.
    pub refcount_drift: Vec<RefDrift>,
    /// Invalid multipart uploads / index rows.
    pub dangling_uploads: Vec<DanglingUpload>,
    /// Keys whose `latest` row is not the newest Live version.
    pub latest_mismatch: Vec<(BucketId, String)>,
    /// Damage registry entries (from scrub or earlier fsck runs) at the end of the run.
    pub damaged: Vec<DamageRecord>,
    /// Repairs applied (all zero without `repair`).
    pub repaired: RepairStats,
}

impl FsckReport {
    /// No inconsistencies found (damage registry entries count as findings).
    pub fn is_clean(&self) -> bool {
        self.orphan_blobs.is_empty()
            && self.missing_blobs.is_empty()
            && self.corrupt_blobs.is_empty()
            && self.refcount_drift.is_empty()
            && self.dangling_uploads.is_empty()
            && self.latest_mismatch.is_empty()
            && self.damaged.is_empty()
    }
}

fn damaged_blob_key(id: &BlobId) -> Vec<u8> {
    let mut k = DAMAGED_BLOB_PREFIX.to_vec();
    k.extend_from_slice(id.as_bytes());
    k
}

fn damaged_version_key(b: BucketId, key: &str, vid: &VersionId) -> Vec<u8> {
    let mut k = DAMAGED_VERSION_PREFIX.to_vec();
    k.extend(keys::version_key(b, key, vid));
    k
}

/// Damage record of a blob, if flagged.
pub fn blob_damage<R: Reader + ?Sized>(
    r: &R,
    id: &BlobId,
) -> Result<Option<DamageRecord>, MetaError> {
    r.get(Table::Kv, &damaged_blob_key(id))?
        .map(|v| decode(&v))
        .transpose()
}

/// Damage affecting a version: its own flag, or a flag on any blob it references. GET/HEAD
/// wiring: if `Some`, fail with `InternalError` + header [`DAMAGED_HEADER`]`: true`.
pub fn version_damage<R: Reader + ?Sized>(
    r: &R,
    bucket: BucketId,
    v: &VersionRecord,
) -> Result<Option<DamageRecord>, MetaError> {
    if let Some(d) = r.get(
        Table::Kv,
        &damaged_version_key(bucket, &v.key, &v.version_id),
    )? {
        return decode(&d).map(Some);
    }
    for b in v.blobs() {
        if let Some(d) = blob_damage(r, &b)? {
            return Ok(Some(d));
        }
    }
    Ok(None)
}

/// The S3 error a GET of a damaged version should return.
pub fn damaged_error(key: &str) -> S3Error {
    S3Error::new(
        cairn_core::S3ErrorCode::InternalError,
        "The object data is damaged on this server (see `cairn fsck`); restore it from a replica or backup.",
    )
    .with_resource(key)
    .with_header(DAMAGED_HEADER, "true")
}

/// All blob-level damage records.
pub fn damaged_blobs<R: Reader + ?Sized>(r: &R) -> Result<Vec<DamageRecord>, MetaError> {
    let mut out = Vec::new();
    r.scan_prefix(Table::Kv, DAMAGED_BLOB_PREFIX, &mut |_, v| {
        out.push(decode(v)?);
        Ok(Flow::Continue)
    })?;
    Ok(out)
}

/// Flag a blob damaged (idempotent: keeps the first record). Returns whether it was new.
pub fn mark_blob_damaged(
    txn: &WriteTxn,
    id: &BlobId,
    kind: DamageKind,
    source: &str,
    now: Ts,
) -> Result<bool, MetaError> {
    let k = damaged_blob_key(id);
    if txn.get(Table::Kv, &k)?.is_some() {
        return Ok(false);
    }
    let rec = DamageRecord {
        blob: *id,
        kind,
        detected_at: now,
        source: source.to_string(),
    };
    txn.put(Table::Kv, &k, &encode(&rec))?;
    Ok(true)
}

fn mark_version_damaged(
    txn: &WriteTxn,
    v: &VersionRef,
    rec: &DamageRecord,
) -> Result<bool, MetaError> {
    let k = damaged_version_key(v.bucket, &v.key, &v.version_id);
    if txn.get(Table::Kv, &k)?.is_some() {
        return Ok(false);
    }
    txn.put(Table::Kv, &k, &encode(rec))?;
    Ok(true)
}

/// A blob file (or cold stub) present under `blobs/`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DiskBlob {
    pub modified: SystemTime,
    pub stub: bool,
}

/// Every blob id present under `blobs/ab/cd/` (plain, `.enc`, or `.cold` stub).
pub(crate) fn walk_disk(root: &Path) -> std::io::Result<BTreeMap<BlobId, DiskBlob>> {
    let mut out = BTreeMap::new();
    for l1 in entries(root)? {
        for l2 in entries(&l1)? {
            for f in entries(&l2)? {
                let Some(name) = f.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let (hex, stub) = match name.strip_suffix(".cold") {
                    Some(h) => (h, true),
                    None => (name.strip_suffix(".enc").unwrap_or(name), false),
                };
                let Ok(id) = hex.parse::<BlobId>() else {
                    continue;
                };
                let modified = std::fs::metadata(&f)
                    .and_then(|m| m.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                let e = out.entry(id).or_insert(DiskBlob { modified, stub });
                e.stub &= stub;
                e.modified = e.modified.max(modified);
            }
        }
    }
    Ok(out)
}

fn entries(p: &Path) -> std::io::Result<Vec<PathBuf>> {
    match std::fs::read_dir(p) {
        Ok(rd) => rd.map(|e| e.map(|e| e.path())).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn bucket_of(k: &[u8]) -> Option<BucketId> {
    Some(BucketId::from_bytes(k.get(..16)?.try_into().ok()?))
}

#[derive(Default)]
struct Recount {
    refs: BTreeMap<BlobId, (u32, u64)>,
    versions: u64,
    uploads: u64,
    dangling: Vec<DanglingUpload>,
    latest_bad: BTreeSet<(BucketId, String)>,
}

fn recount<R: Reader>(r: &R) -> Result<Recount, MetaError> {
    let mut rc = Recount::default();
    let mut last_key: Option<(BucketId, String)> = None;
    r.scan(
        Table::Versions,
        Bound::Unbounded,
        Bound::Unbounded,
        &mut |k, v| {
            let rec: VersionRecord = decode(v)?;
            rc.versions += 1;
            if let Some(body) = rec.body() {
                for p in &body.parts {
                    let e = rc.refs.entry(p.blob).or_insert((0, p.size));
                    e.0 = e.0.saturating_add(1);
                }
            }
            if let Some(b) = bucket_of(k) {
                let this = (b, rec.key.clone());
                if last_key.as_ref() != Some(&this) {
                    if r.newest_live(b, &rec.key)? != r.latest(b, &rec.key)? {
                        rc.latest_bad.insert(this.clone());
                    }
                    last_key = Some(this);
                }
            }
            Ok(Flow::Continue)
        },
    )?;
    r.scan(
        Table::Latest,
        Bound::Unbounded,
        Bound::Unbounded,
        &mut |k, _| {
            if let (Some(b), Some(key)) = (bucket_of(k), keys::split_latest_key(k))
                && r.newest_live(b, key)?.is_none()
            {
                rc.latest_bad.insert((b, key.to_string()));
            }
            Ok(Flow::Continue)
        },
    )?;
    r.scan(
        Table::Uploads,
        Bound::Unbounded,
        Bound::Unbounded,
        &mut |_, v| {
            let u: MultipartRecord = decode(v)?;
            rc.uploads += 1;
            for p in u.parts.values() {
                let e = rc.refs.entry(p.blob).or_insert((0, p.size));
                e.0 = e.0.saturating_add(1);
            }
            let active = matches!(
                r.bucket(u.bucket)?.map(|b| b.state),
                Some(BucketState::Active)
            );
            if !active {
                rc.dangling.push(DanglingUpload {
                    bucket: u.bucket,
                    upload_id: u.upload_id.clone(),
                    reason: "bucket is not active",
                });
            } else if r
                .get(
                    Table::UploadsByKey,
                    &keys::upload_by_key(u.bucket, &u.key, &u.upload_id),
                )?
                .is_none()
            {
                rc.dangling.push(DanglingUpload {
                    bucket: u.bucket,
                    upload_id: u.upload_id.clone(),
                    reason: "missing uploads_by_key index row",
                });
            }
            Ok(Flow::Continue)
        },
    )?;
    r.scan(
        Table::UploadsByKey,
        Bound::Unbounded,
        Bound::Unbounded,
        &mut |k, _| {
            let Some(b) = bucket_of(k) else {
                return Ok(Flow::Continue);
            };
            if let Some((_, uid)) = keys::split_upload_by_key(k)
                && r.get(Table::Uploads, &keys::upload_key(b, uid))?.is_none()
            {
                rc.dangling.push(DanglingUpload {
                    bucket: b,
                    upload_id: uid.to_string(),
                    reason: "index row without upload",
                });
            }
            Ok(Flow::Continue)
        },
    )?;
    Ok(rc)
}

/// Versions and uploads that reference any blob in `want`.
fn referrers<R: Reader>(r: &R, want: &BTreeSet<BlobId>) -> Result<Vec<BadBlob>, MetaError> {
    let mut map: BTreeMap<BlobId, BadBlob> = want
        .iter()
        .map(|b| {
            (
                *b,
                BadBlob {
                    blob: *b,
                    versions: Vec::new(),
                    uploads: Vec::new(),
                },
            )
        })
        .collect();
    if want.is_empty() {
        return Ok(Vec::new());
    }
    r.scan(
        Table::Versions,
        Bound::Unbounded,
        Bound::Unbounded,
        &mut |k, v| {
            let rec: VersionRecord = decode(v)?;
            let Some(b) = bucket_of(k) else {
                return Ok(Flow::Continue);
            };
            for blob in rec.blobs() {
                if let Some(e) = map.get_mut(&blob) {
                    let vr = VersionRef {
                        bucket: b,
                        key: rec.key.clone(),
                        version_id: rec.version_id,
                    };
                    if !e.versions.contains(&vr) {
                        e.versions.push(vr);
                    }
                }
            }
            Ok(Flow::Continue)
        },
    )?;
    r.scan(
        Table::Uploads,
        Bound::Unbounded,
        Bound::Unbounded,
        &mut |_, v| {
            let u: MultipartRecord = decode(v)?;
            for p in u.parts.values() {
                if let Some(e) = map.get_mut(&p.blob) {
                    e.uploads.push((u.bucket, u.upload_id.clone()));
                }
            }
            Ok(Flow::Continue)
        },
    )?;
    Ok(map.into_values().collect())
}

impl CairnEngine {
    /// Run fsck (see the module docs). Online-safe: reads one metadata snapshot, and every repair
    /// re-checks its precondition inside the write transaction.
    pub async fn fsck(&self, opts: FsckOptions) -> S3Result<FsckReport> {
        let root = self.data_dir().join("blobs");
        let disk = tokio::task::spawn_blocking(move || walk_disk(&root))
            .await
            .map_err(S3Error::internal)??;
        let r = self.read()?;
        let rc = recount(&r)?;
        let mut stored: BTreeMap<BlobId, BlobRef> = BTreeMap::new();
        r.scan(
            Table::Blobs,
            Bound::Unbounded,
            Bound::Unbounded,
            &mut |k, v| {
                if let Ok(a) = <[u8; 32]>::try_from(k) {
                    stored.insert(BlobId(a), decode(v)?);
                }
                Ok(Flow::Continue)
            },
        )?;
        let mut rep = FsckReport {
            blobs_on_disk: disk.len() as u64,
            blob_rows: stored.len() as u64,
            versions_scanned: rc.versions,
            uploads_scanned: rc.uploads,
            dangling_uploads: rc.dangling.clone(),
            latest_mismatch: rc.latest_bad.iter().cloned().collect(),
            ..Default::default()
        };
        for (id, (actual, _)) in &rc.refs {
            let s = stored.get(id).map(|r| r.refcount);
            if s != Some(*actual) {
                rep.refcount_drift.push(RefDrift {
                    blob: *id,
                    stored: s,
                    actual: *actual,
                });
            }
        }
        for (id, row) in &stored {
            if row.refcount > 0 && !rc.refs.contains_key(id) {
                rep.refcount_drift.push(RefDrift {
                    blob: *id,
                    stored: Some(row.refcount),
                    actual: 0,
                });
            }
        }
        let now_sys = SystemTime::now();
        for (id, d) in &disk {
            let old = now_sys.duration_since(d.modified).unwrap_or_default() >= opts.orphan_min_age;
            if old && !stored.contains_key(id) && !rc.refs.contains_key(id) {
                rep.orphan_blobs.push(*id);
            }
        }
        let missing: BTreeSet<BlobId> = rc
            .refs
            .keys()
            .filter(|id| !disk.contains_key(id))
            .copied()
            .collect();
        let candidates: Vec<BlobId> = rc
            .refs
            .keys()
            .filter(|id| disk.get(id).is_some_and(|d| !d.stub))
            .copied()
            .collect();
        let to_verify: Vec<BlobId> = match opts.verify {
            VerifyMode::None => Vec::new(),
            VerifyMode::Full => candidates,
            VerifyMode::Sample(n) => {
                use rand::seq::IndexedRandom;
                candidates
                    .choose_multiple(&mut rand::rng(), n)
                    .copied()
                    .collect()
            }
        };
        let key = self.config().at_rest_key.clone();
        let mut corrupt = BTreeSet::new();
        for id in &to_verify {
            match self.blobs().verify(id, key.as_ref()).await {
                Ok(true) => rep.blobs_verified += 1,
                Ok(false) => {
                    rep.blobs_verified += 1;
                    corrupt.insert(*id);
                }
                Err(cairn_blob::BlobError::KeyRequired(_)) => {}
                Err(cairn_blob::BlobError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        rep.missing_blobs = referrers(&r, &missing)?;
        rep.corrupt_blobs = referrers(&r, &corrupt)?;
        drop(r);
        if opts.repair {
            rep.repaired = self.fsck_repair(&rep, &rc, &disk).await?;
        }
        rep.damaged = damaged_blobs(&self.read()?)?;
        tracing::info!(
            clean = rep.is_clean(),
            orphans = rep.orphan_blobs.len(),
            missing = rep.missing_blobs.len(),
            corrupt = rep.corrupt_blobs.len(),
            drift = rep.refcount_drift.len(),
            dangling = rep.dangling_uploads.len(),
            latest = rep.latest_mismatch.len(),
            repaired = ?rep.repaired,
            "fsck finished"
        );
        Ok(rep)
    }

    async fn fsck_repair(
        &self,
        rep: &FsckReport,
        rc: &Recount,
        disk: &BTreeMap<BlobId, DiskBlob>,
    ) -> S3Result<RepairStats> {
        let mut st = RepairStats::default();
        for chunk in rep.refcount_drift.chunks(BATCH) {
            let fixes: Vec<(RefDrift, u64)> = chunk
                .iter()
                .map(|d| (*d, rc.refs.get(&d.blob).map_or(0, |r| r.1)))
                .collect();
            let (fixed, skipped) = self
                .meta()
                .write(move |txn| -> Result<(u64, u64), MetaError> {
                    let now = Ts::now();
                    let (mut fixed, mut skipped) = (0, 0);
                    for (d, size) in &fixes {
                        let cur = txn.blob_ref(&d.blob)?;
                        if cur.map(|r| r.refcount) != d.stored {
                            skipped += 1;
                            continue;
                        }
                        set_refcount(txn, &d.blob, cur, d.actual, *size, now)?;
                        fixed += 1;
                    }
                    Ok((fixed, skipped))
                })
                .await?;
            st.refcounts_fixed += fixed;
            st.refcounts_skipped += skipped;
        }
        let mut orphans: Vec<(BlobId, u64)> = Vec::new();
        for id in &rep.orphan_blobs {
            let size = self.blobs().size(id).await.unwrap_or(0);
            orphans.push((*id, size));
        }
        for chunk in orphans.chunks(BATCH) {
            let chunk = chunk.to_vec();
            let blobs = self.blobs().clone();
            st.orphans_indexed += self
                .meta()
                .write(move |txn| -> Result<u64, MetaError> {
                    let now = Ts::now();
                    let mut n = 0;
                    for (id, size) in &chunk {
                        if txn.blob_ref(id)?.is_some() || !blobs.exists_sync(id) {
                            continue;
                        }
                        let r = BlobRef {
                            refcount: 0,
                            size: *size,
                            last_unref_at: Some(now),
                        };
                        txn.put(Table::Blobs, id.as_bytes(), &encode(&r))?;
                        txn.put(Table::BlobGcIdx, &keys::blob_gc_key(now, id), &[])?;
                        n += 1;
                    }
                    Ok(n)
                })
                .await?;
        }
        let mut bad: Vec<(BadBlob, DamageKind)> = Vec::new();
        bad.extend(
            rep.missing_blobs
                .iter()
                .map(|b| (b.clone(), DamageKind::Missing)),
        );
        bad.extend(
            rep.corrupt_blobs
                .iter()
                .map(|b| (b.clone(), DamageKind::Corrupt)),
        );
        for chunk in bad.chunks(BATCH / 4) {
            let chunk = chunk.to_vec();
            let blobs = self.blobs().clone();
            let (nb, nv) = self
                .meta()
                .write(move |txn| -> Result<(u64, u64), MetaError> {
                    let now = Ts::now();
                    let (mut nb, mut nv) = (0, 0);
                    for (b, kind) in &chunk {
                        if *kind == DamageKind::Missing && blobs.exists_sync(&b.blob) {
                            continue;
                        }
                        if mark_blob_damaged(txn, &b.blob, *kind, "fsck", now)? {
                            nb += 1;
                        }
                        let rec = blob_damage(txn, &b.blob)?.expect("just marked");
                        for v in &b.versions {
                            if mark_version_damaged(txn, v, &rec)? {
                                nv += 1;
                            }
                        }
                    }
                    Ok((nb, nv))
                })
                .await?;
            st.blobs_marked_damaged += nb;
            st.versions_marked_damaged += nv;
        }
        st.damage_cleared = self.clear_healed_damage(disk).await?;
        if !rep.dangling_uploads.is_empty() {
            let (a, b) = self.cleanup_orphan_uploads().await?;
            st.uploads_cleaned = a + b;
        }
        if !rep.latest_mismatch.is_empty() {
            st.latest_fixed = self.check_latest(usize::MAX).await?.1;
        }
        Ok(st)
    }

    /// Drop damage flags of blobs that are present and verify again (e.g. restored from backup).
    async fn clear_healed_damage(&self, disk: &BTreeMap<BlobId, DiskBlob>) -> S3Result<u64> {
        let flagged = damaged_blobs(&self.read()?)?;
        let key = self.config().at_rest_key.clone();
        let mut healed = Vec::new();
        for d in flagged {
            if disk.get(&d.blob).is_some_and(|x| !x.stub)
                && matches!(self.blobs().verify(&d.blob, key.as_ref()).await, Ok(true))
            {
                healed.push(d.blob);
            }
        }
        if healed.is_empty() {
            return Ok(0);
        }
        let want: BTreeSet<BlobId> = healed.iter().copied().collect();
        let refs = referrers(&self.read()?, &want)?;
        let n = healed.len() as u64;
        self.meta()
            .write(move |txn| -> Result<(), MetaError> {
                for b in &refs {
                    txn.del(Table::Kv, &damaged_blob_key(&b.blob))?;
                    for v in &b.versions {
                        txn.del(
                            Table::Kv,
                            &damaged_version_key(v.bucket, &v.key, &v.version_id),
                        )?;
                    }
                }
                Ok(())
            })
            .await?;
        Ok(n)
    }
}

/// Rewrite a blob's refcount (keeping `blob_gc_idx` consistent).
fn set_refcount(
    txn: &WriteTxn,
    id: &BlobId,
    cur: Option<BlobRef>,
    actual: u32,
    size: u64,
    now: Ts,
) -> Result<(), MetaError> {
    let mut r = cur.unwrap_or(BlobRef {
        refcount: 0,
        size,
        last_unref_at: None,
    });
    r.refcount = actual;
    if actual == 0 {
        if r.last_unref_at.is_none() {
            r.last_unref_at = Some(now);
            txn.put(Table::BlobGcIdx, &keys::blob_gc_key(now, id), &[])?;
        }
    } else if let Some(at) = r.last_unref_at.take() {
        txn.del(Table::BlobGcIdx, &keys::blob_gc_key(at, id))?;
    }
    txn.put(Table::Blobs, id.as_bytes(), &encode(&r))
}
