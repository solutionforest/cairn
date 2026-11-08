//! The delivery worker: tails the outbox from a sink's durable cursor, delivers batches with
//! exponential backoff and jitter, and dead-letters batches that exhaust their attempts.
//!
//! Guarantee: at-least-once delivery of exactly the committed set. The cursor advances only
//! after the destination accepted a batch (or the batch was dead-lettered), so a crash between
//! delivery and cursor commit re-delivers that batch; receivers dedupe on `cairn.id` /
//! `x-cairn-idempotency-key`.

use crate::EventsError;
use crate::outbox::{DlqRecord, Outbox};
use crate::sink::{Delivery, Sink, SinkError};
use cairn_core::Ts;
use cairn_meta::{MetaStore, RedbMetaStore};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Observability hooks; every method has a no-op default.
pub trait EventMetrics: Send + Sync {
    /// `n` events were accepted by `sink`.
    fn delivered(&self, _sink: &str, _n: usize) {}
    /// One delivery attempt failed.
    fn attempt_failed(&self, _sink: &str, _err: &SinkError) {}
    /// `n` events were moved to the dead-letter queue.
    fn dead_lettered(&self, _sink: &str, _n: usize) {}
    /// Outbox rows not yet processed by `sink`.
    fn lag(&self, _sink: &str, _pending: u64) {}
}

/// Metrics sink that records nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMetrics;
impl EventMetrics for NoopMetrics {}

/// Worker tuning.
#[derive(Debug, Clone)]
pub struct WorkerOptions {
    /// Attempts per batch before dead-lettering (≥ 1).
    pub max_attempts: u32,
    /// First retry delay.
    pub base_backoff: Duration,
    /// Retry delay cap.
    pub max_backoff: Duration,
    /// Fallback poll interval when no wake-up arrives.
    pub poll_interval: Duration,
    /// Outbox rows read per pass.
    pub scan_limit: usize,
}

impl Default for WorkerOptions {
    fn default() -> Self {
        WorkerOptions {
            max_attempts: 8,
            base_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(300),
            poll_interval: Duration::from_secs(1),
            scan_limit: 1000,
        }
    }
}

impl WorkerOptions {
    /// Delay before retry number `attempt` (1-based): `base · 2^(attempt-1)` capped at
    /// `max_backoff`, with equal jitter (uniform in `[d/2, d]`).
    pub fn backoff(&self, attempt: u32) -> Duration {
        let exp = self
            .base_backoff
            .saturating_mul(1u32 << attempt.saturating_sub(1).min(20));
        let d = exp.min(self.max_backoff);
        let half = d / 2;
        let jitter_ns = rand::rng().random_range(0..=half.as_nanos().min(u64::MAX as u128) as u64);
        half + Duration::from_nanos(jitter_ns)
    }
}

/// Drives one [`Sink`] from the outbox.
pub struct DeliveryWorker {
    store: RedbMetaStore,
    outbox: Outbox,
    sink: Arc<dyn Sink>,
    opts: WorkerOptions,
    metrics: Arc<dyn EventMetrics>,
}

enum Outcome {
    Delivered,
    Failed { attempts: u32, error: String },
    Shutdown,
}

impl DeliveryWorker {
    /// New worker with default options and no-op metrics.
    pub fn new(store: RedbMetaStore, outbox: Outbox, sink: Arc<dyn Sink>) -> DeliveryWorker {
        DeliveryWorker {
            store,
            outbox,
            sink,
            opts: WorkerOptions::default(),
            metrics: Arc::new(NoopMetrics),
        }
    }

    /// Replace the options.
    pub fn with_options(mut self, opts: WorkerOptions) -> DeliveryWorker {
        self.opts = opts;
        self
    }

    /// Replace the metrics hooks.
    pub fn with_metrics(mut self, m: Arc<dyn EventMetrics>) -> DeliveryWorker {
        self.metrics = m;
        self
    }

    /// Spawn [`DeliveryWorker::run`] on the current runtime.
    pub fn spawn(
        self,
        shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<Result<(), EventsError>> {
        tokio::spawn(self.run(shutdown))
    }

    /// Run until `shutdown` becomes `true` (or its sender is dropped).
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), EventsError> {
        let mut wake = self.outbox.subscribe();
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            match self.run_once(&mut shutdown).await {
                Ok(n) if n > 0 => continue,
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(sink = self.sink.id(), error = %e, "event delivery pass failed")
                }
            }
            tokio::select! {
                _ = wake.changed() => {}
                _ = tokio::time::sleep(self.opts.poll_interval) => {}
                r = shutdown.changed() => if r.is_err() { return Ok(()) },
            }
        }
    }

    /// One pass: read up to `scan_limit` rows after the cursor, deliver what this sink accepts,
    /// advance the cursor. Returns the number of outbox rows processed.
    pub async fn run_once(
        &self,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<usize, EventsError> {
        let id = self.sink.id().to_string();
        let (cursor, rows, last) = {
            let r = self.store.read()?;
            let cursor = Outbox::cursor(&r, &id)?;
            let rows = Outbox::read_after(&r, cursor, self.opts.scan_limit.max(1))?;
            (cursor, rows, Outbox::last_seq(&r)?)
        };
        let Some(&(end, _)) = rows.last() else {
            self.metrics.lag(&id, 0);
            return Ok(0);
        };
        let processed = rows.len();
        let mut deliveries: Vec<Delivery> = Vec::new();
        for (seq, record) in rows {
            if let Some(configuration_id) = self.sink.accepts(&record) {
                deliveries.push(Delivery {
                    seq,
                    record,
                    configuration_id,
                });
            }
        }
        for batch in deliveries.chunks(self.sink.batch_size().max(1)) {
            let batch_end = batch.last().map(|d| d.seq).unwrap_or(cursor);
            match self.deliver_with_retry(batch, shutdown).await {
                Outcome::Shutdown => return Ok(0),
                Outcome::Delivered => {
                    self.metrics.delivered(&id, batch.len());
                    self.commit(batch_end, Vec::new()).await?;
                }
                Outcome::Failed { attempts, error } => {
                    tracing::warn!(sink = %id, attempts, error = %error, events = batch.len(),
                        "event batch dead-lettered");
                    let now = Ts::now();
                    let dlq = batch
                        .iter()
                        .map(|d| DlqRecord {
                            sink: id.clone(),
                            seq: d.seq,
                            record: d.record.clone(),
                            attempts,
                            last_error: error.clone(),
                            failed_at: now,
                        })
                        .collect();
                    self.metrics.dead_lettered(&id, batch.len());
                    self.commit(batch_end, dlq).await?;
                }
            }
        }
        self.commit(end, Vec::new()).await?;
        self.metrics.lag(&id, last.saturating_sub(end));
        Ok(processed)
    }

    async fn commit(&self, seq: u64, dlq: Vec<DlqRecord>) -> Result<(), EventsError> {
        let id = self.sink.id().to_string();
        self.store
            .write(move |txn| {
                for d in &dlq {
                    Outbox::dead_letter(txn, d)?;
                }
                Outbox::set_cursor(txn, &id, seq)
            })
            .await
    }

    async fn deliver_with_retry(
        &self,
        batch: &[Delivery],
        shutdown: &mut watch::Receiver<bool>,
    ) -> Outcome {
        let max = self.opts.max_attempts.max(1);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let res = tokio::select! {
                r = self.sink.deliver(batch) => r,
                _ = shutdown.changed() => return Outcome::Shutdown,
            };
            match res {
                Ok(()) => return Outcome::Delivered,
                Err(e) => {
                    self.metrics.attempt_failed(self.sink.id(), &e);
                    let (SinkError::Permanent(msg) | SinkError::Retryable(msg)) = &e;
                    if matches!(e, SinkError::Permanent(_)) || attempt >= max {
                        return Outcome::Failed {
                            attempts: attempt,
                            error: msg.clone(),
                        };
                    }
                    tracing::debug!(sink = self.sink.id(), attempt, error = %msg, "event delivery retry");
                    tokio::select! {
                        _ = tokio::time::sleep(self.opts.backoff(attempt)) => {}
                        _ = shutdown.changed() => return Outcome::Shutdown,
                    }
                }
            }
        }
    }
}

/// Delete outbox rows every sink in `sinks` has processed (at most `limit` per call).
pub async fn compact_outbox(
    store: &RedbMetaStore,
    sinks: Vec<String>,
    limit: usize,
) -> Result<usize, EventsError> {
    store
        .write(move |txn| {
            let ids: Vec<&str> = sinks.iter().map(String::as_str).collect();
            let upto = Outbox::min_cursor(txn, &ids)?;
            Outbox::compact(txn, upto, limit)
        })
        .await
}
