//! `tidemark scrub` (DESIGN §9, PRODUCTION-READINESS C4): background re-hashing of blobs under an IO
//! budget, resumable across restarts.
//!
//! State lives in the `kv` table (no new tables): `scrub/cursor` → [`ScrubCursor`] (last blob id
//! verified in BLOB-id order, pass number) and `scrub/at/<BlobId>` → last verified time
//! (`keys::ts_bytes`). A blob that is gone or fails its hash is written to the fsck damage
//! registry ([`crate::fsck::mark_blob_damaged`], source `scrub`), so `tidemark fsck` reports it and
//! GET can refuse it. Blobs that live only in the cold tier (stub) are skipped: re-hashing them
//! would download them.

use crate::TidemarkEngine;
use crate::fsck::{DamageKind, mark_blob_damaged};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::ops::Bound;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tidemark_blob::BlobStore;
use tidemark_core::{BlobId, S3Result, Ts};
use tidemark_meta::{BlobRef, Flow, MetaError, Reader, Table, decode, encode, keys};

/// `kv` key of the scrub cursor.
pub const SCRUB_CURSOR_KEY: &[u8] = b"scrub/cursor";
/// `kv` prefix of per-blob last-verified timestamps.
pub const SCRUB_AT_PREFIX: &[u8] = b"scrub/at/";

/// Time source for throttling (a fake in tests).
pub trait Clock: Send + Sync {
    /// Monotonic time since an arbitrary origin.
    fn elapsed(&self) -> Duration;
    /// Wall-clock time for `scrub/at` records.
    fn now(&self) -> Ts;
    /// Sleep for `d`.
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// The real clock (`tokio::time`).
#[derive(Debug)]
pub struct SystemClock(std::time::Instant);

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock(std::time::Instant::now())
    }
}

impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn now(&self) -> Ts {
        Ts::now()
    }
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// Scrub settings.
#[derive(Debug, Clone)]
pub struct ScrubConfig {
    /// Read budget in bytes per second (0 = unthrottled).
    pub bytes_per_sec: u64,
    /// Blobs verified concurrently.
    pub max_concurrent: usize,
    /// Blobs per step (one metadata write per step).
    pub batch: usize,
    /// Skip blobs verified more recently than this.
    pub reverify_after: Duration,
}

impl Default for ScrubConfig {
    fn default() -> Self {
        ScrubConfig {
            bytes_per_sec: 50 * 1024 * 1024,
            max_concurrent: 2,
            batch: 256,
            reverify_after: Duration::from_secs(30 * 86_400),
        }
    }
}

/// Persistent scrub position.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubCursor {
    /// Last blob id handled in the current pass.
    pub after: Option<BlobId>,
    /// Completed passes.
    pub passes: u64,
    /// Start of the current pass.
    pub pass_started: Option<Ts>,
}

/// What one [`Scrubber::step`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScrubReport {
    /// Blobs re-hashed.
    pub blobs_verified: u64,
    /// Bytes re-hashed.
    pub bytes_verified: u64,
    /// Skipped: verified recently.
    pub skipped_recent: u64,
    /// Skipped: cold-tier stub or encrypted without a key.
    pub skipped_other: u64,
    /// Hash mismatches found (flagged damaged).
    pub corrupt: Vec<BlobId>,
    /// Referenced blobs missing on disk (flagged damaged).
    pub missing: Vec<BlobId>,
    /// This step finished a full pass (the cursor wrapped).
    pub pass_completed: bool,
    /// Time spent waiting for the IO budget.
    pub throttled: Duration,
}

/// Read the persisted cursor.
pub fn load_cursor<R: Reader + ?Sized>(r: &R) -> Result<ScrubCursor, MetaError> {
    Ok(r.get(Table::Kv, SCRUB_CURSOR_KEY)?
        .map(|v| decode(&v))
        .transpose()?
        .unwrap_or_default())
}

fn at_key(id: &BlobId) -> Vec<u8> {
    let mut k = SCRUB_AT_PREFIX.to_vec();
    k.extend_from_slice(id.as_bytes());
    k
}

/// When a blob was last verified by scrub.
pub fn last_verified<R: Reader + ?Sized>(r: &R, id: &BlobId) -> Result<Option<Ts>, MetaError> {
    Ok(r.get(Table::Kv, &at_key(id))?
        .filter(|v| v.len() == 16)
        .map(|v| keys::ts_from_bytes(&v)))
}

struct Throttle {
    rate: u64,
    start: Duration,
    consumed: Mutex<u64>,
}

impl Throttle {
    async fn acquire(&self, clock: &dyn Clock, n: u64) -> Duration {
        if self.rate == 0 {
            return Duration::ZERO;
        }
        let wait = {
            let mut c = self.consumed.lock().expect("throttle lock");
            *c = c.saturating_add(n);
            let due = self.start + Duration::from_secs_f64(*c as f64 / self.rate as f64);
            due.saturating_sub(clock.elapsed())
        };
        if !wait.is_zero() {
            clock.sleep(wait).await;
        }
        wait
    }
}

enum Outcome {
    Ok(u64),
    Corrupt,
    Missing,
    Skipped,
}

/// Background blob verifier.
#[derive(Clone)]
pub struct Scrubber {
    engine: TidemarkEngine,
    cfg: ScrubConfig,
    clock: Arc<dyn Clock>,
}

impl Scrubber {
    /// Scrubber with the system clock.
    pub fn new(engine: TidemarkEngine, cfg: ScrubConfig) -> Scrubber {
        Scrubber::with_clock(engine, cfg, Arc::new(SystemClock::default()))
    }

    /// Scrubber with an explicit clock.
    pub fn with_clock(engine: TidemarkEngine, cfg: ScrubConfig, clock: Arc<dyn Clock>) -> Scrubber {
        Scrubber { engine, cfg, clock }
    }

    /// Verify the next batch of referenced blobs after the cursor, record results, advance.
    pub async fn step(&self) -> S3Result<ScrubReport> {
        let r = self.engine.read()?;
        let mut cur = load_cursor(&r)?;
        let start = cur.after.map(|b| b.0.to_vec());
        let lower = match &start {
            Some(s) => Bound::Excluded(s.as_slice()),
            None => Bound::Unbounded,
        };
        let batch = self.cfg.batch.max(1);
        let mut todo: Vec<(BlobId, u64)> = Vec::new();
        let mut last = None;
        r.scan(Table::Blobs, lower, Bound::Unbounded, &mut |k, v| {
            let Ok(a) = <[u8; 32]>::try_from(k) else {
                return Ok(Flow::Continue);
            };
            let row: BlobRef = decode(v)?;
            last = Some(BlobId(a));
            if row.refcount > 0 {
                todo.push((BlobId(a), row.size));
            }
            Ok(if todo.len() >= batch {
                Flow::Stop
            } else {
                Flow::Continue
            })
        })?;
        let wrapped = todo.len() < batch;
        let now = self.clock.now();
        let mut rep = ScrubReport::default();
        let mut work = Vec::new();
        for (id, size) in todo {
            let recent =
                last_verified(&r, &id)?.is_some_and(|t| t.plus(self.cfg.reverify_after) > now);
            if recent {
                rep.skipped_recent += 1;
            } else {
                work.push((id, size));
            }
        }
        drop(r);
        let throttle = Throttle {
            rate: self.cfg.bytes_per_sec,
            start: self.clock.elapsed(),
            consumed: Mutex::new(0),
        };
        let throttled = Mutex::new(Duration::ZERO);
        let key = self.engine.config().at_rest_key.clone();
        let blobs = self.engine.blobs().clone();
        let stub_dir = self.engine.data_dir().join("blobs");
        let results: Vec<(BlobId, Outcome)> = futures::stream::iter(work)
            .map(|(id, size)| {
                let (blobs, key, throttle, throttled, clock) =
                    (&blobs, &key, &throttle, &throttled, &*self.clock);
                let stub_dir = &stub_dir;
                async move {
                    if !blobs.exists_sync(&id) {
                        let hex = id.to_hex();
                        let stub = stub_dir
                            .join(&hex[..2])
                            .join(&hex[2..4])
                            .join(format!("{hex}.cold"));
                        return (
                            id,
                            if stub.exists() {
                                Outcome::Skipped
                            } else {
                                Outcome::Missing
                            },
                        );
                    }
                    let waited = throttle.acquire(clock, size).await;
                    *throttled.lock().expect("lock") += waited;
                    let o = match blobs.verify(&id, key.as_ref()).await {
                        Ok(true) => Outcome::Ok(size),
                        Ok(false) => Outcome::Corrupt,
                        Err(tidemark_blob::BlobError::NotFound(_)) => Outcome::Missing,
                        Err(tidemark_blob::BlobError::KeyRequired(_)) => Outcome::Skipped,
                        Err(e) => {
                            tracing::warn!(blob = %id, error = %e, "scrub read failed");
                            Outcome::Skipped
                        }
                    };
                    (id, o)
                }
            })
            .buffer_unordered(self.cfg.max_concurrent.max(1))
            .collect()
            .await;
        rep.throttled = *throttled.lock().expect("lock");
        let mut ok = Vec::new();
        for (id, o) in results {
            match o {
                Outcome::Ok(n) => {
                    rep.blobs_verified += 1;
                    rep.bytes_verified += n;
                    ok.push(id);
                }
                Outcome::Corrupt => {
                    rep.blobs_verified += 1;
                    rep.corrupt.push(id);
                }
                Outcome::Missing => rep.missing.push(id),
                Outcome::Skipped => rep.skipped_other += 1,
            }
        }
        rep.corrupt.sort();
        rep.missing.sort();
        if wrapped {
            cur.after = None;
            cur.passes += 1;
            cur.pass_started = None;
            rep.pass_completed = true;
        } else {
            if cur.pass_started.is_none() {
                cur.pass_started = Some(now);
            }
            cur.after = last;
        }
        let (corrupt, missing, blobs) = (rep.corrupt.clone(), rep.missing.clone(), blobs.clone());
        self.engine
            .meta()
            .write(move |txn| -> Result<(), MetaError> {
                for id in &ok {
                    txn.put(Table::Kv, &at_key(id), &keys::ts_bytes(now))?;
                }
                for id in &corrupt {
                    mark_blob_damaged(txn, id, DamageKind::Corrupt, "scrub", now)?;
                }
                for id in &missing {
                    let still_referenced = txn
                        .get(Table::Blobs, id.as_bytes())?
                        .map(|v| decode::<BlobRef>(&v))
                        .transpose()?
                        .is_some_and(|r| r.refcount > 0);
                    if still_referenced && !blobs.exists_sync(id) {
                        mark_blob_damaged(txn, id, DamageKind::Missing, "scrub", now)?;
                    }
                }
                txn.put(Table::Kv, SCRUB_CURSOR_KEY, &encode(&cur))?;
                Ok(())
            })
            .await?;
        if !rep.corrupt.is_empty() || !rep.missing.is_empty() {
            tracing::error!(
                corrupt = rep.corrupt.len(),
                missing = rep.missing.len(),
                "scrub found damaged blobs; run `tidemark fsck` for affected objects"
            );
        }
        Ok(rep)
    }

    /// Run until the current pass completes; returns the merged report.
    pub async fn run_pass(&self) -> S3Result<ScrubReport> {
        let mut total = ScrubReport::default();
        loop {
            let r = self.step().await?;
            total.blobs_verified += r.blobs_verified;
            total.bytes_verified += r.bytes_verified;
            total.skipped_recent += r.skipped_recent;
            total.skipped_other += r.skipped_other;
            total.corrupt.extend(r.corrupt);
            total.missing.extend(r.missing);
            total.throttled += r.throttled;
            if r.pass_completed {
                total.pass_completed = true;
                return Ok(total);
            }
        }
    }

    /// Background loop: one step at a time, sleeping `idle` after each completed pass, until
    /// `shutdown` resolves. Errors are logged and retried after `idle`.
    pub async fn run(self, idle: Duration, shutdown: impl Future<Output = ()> + Send) {
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            let pause = match self.step().await {
                Ok(r) if r.pass_completed => idle,
                Ok(_) => Duration::ZERO,
                Err(e) => {
                    tracing::warn!(error = %e, "scrub step failed");
                    idle
                }
            };
            tokio::select! {
                _ = &mut shutdown => return,
                _ = self.clock.sleep(pause) => {}
            }
        }
    }
}
