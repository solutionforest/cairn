//! Prometheus metrics (`GET /metrics`, text exposition format 0.0.4).

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
use tidemark_events::{EventMetrics, SinkError};

/// All server metrics.
pub struct Metrics {
    registry: Registry,
    /// Requests by operation and HTTP status.
    pub requests: IntCounterVec,
    /// Request latency (to response head) by operation.
    pub latency: HistogramVec,
    /// Request body bytes received.
    pub bytes_in: IntCounter,
    /// Response body bytes sent (declared `Content-Length`).
    pub bytes_out: IntCounter,
    /// Blob files tracked in metadata.
    pub blobs: IntGauge,
    /// Plaintext bytes of tracked blobs.
    pub blob_bytes: IntGauge,
    /// Bytes held in trash and shadow history.
    pub trash_bytes: IntGauge,
    /// Bytes of non-trashed objects.
    pub live_bytes: IntGauge,
    /// GC passes.
    pub gc_runs: IntCounter,
    /// Versions purged by GC.
    pub gc_versions_purged: IntCounter,
    /// Blob files unlinked by GC.
    pub gc_blobs_deleted: IntCounter,
    /// Lifecycle passes.
    pub lifecycle_runs: IntCounter,
    /// Lifecycle actions by kind.
    pub lifecycle_actions: IntCounterVec,
    /// Outbox rows not yet processed by the slowest sink.
    pub outbox_depth: IntGauge,
    /// Events delivered per sink.
    pub events_delivered: IntCounterVec,
    /// Failed delivery attempts per sink.
    pub events_failed: IntCounterVec,
    /// Events dead-lettered per sink.
    pub events_dead_lettered: IntCounterVec,
    /// Replication lag per bucket/destination (seconds).
    pub replication_lag: IntGaugeVec,
    /// Replication versions pending per bucket/destination.
    pub replication_pending: IntGaugeVec,
    /// Audit records dropped because the writer fell behind.
    pub audit_dropped: IntCounter,
}

macro_rules! reg {
    ($r:expr, $m:expr) => {{
        let m = $m.expect("valid metric");
        $r.register(Box::new(m.clone())).expect("unique metric");
        m
    }};
}

impl Metrics {
    /// Register every metric in a fresh registry.
    pub fn new() -> Metrics {
        let r = Registry::new();
        let c = |n: &str, h: &str| IntCounter::new(n, h);
        let g = |n: &str, h: &str| IntGauge::new(n, h);
        Metrics {
            requests: reg!(
                r,
                IntCounterVec::new(
                    Opts::new(
                        "tidemark_requests_total",
                        "Requests by operation and status"
                    ),
                    &["op", "status"]
                )
            ),
            latency: reg!(
                r,
                HistogramVec::new(
                    HistogramOpts::new(
                        "tidemark_request_duration_seconds",
                        "Time to response head by operation"
                    )
                    .buckets(vec![
                        0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                        10.0
                    ]),
                    &["op"]
                )
            ),
            bytes_in: reg!(
                r,
                c("tidemark_bytes_in_total", "Request body bytes received")
            ),
            bytes_out: reg!(r, c("tidemark_bytes_out_total", "Response body bytes sent")),
            blobs: reg!(r, g("tidemark_blobs", "Blob files tracked in metadata")),
            blob_bytes: reg!(
                r,
                g("tidemark_blob_bytes", "Plaintext bytes of tracked blobs")
            ),
            trash_bytes: reg!(
                r,
                g("tidemark_trash_bytes", "Bytes in trash and shadow history")
            ),
            live_bytes: reg!(r, g("tidemark_live_bytes", "Bytes of non-trashed objects")),
            gc_runs: reg!(r, c("tidemark_gc_runs_total", "GC passes")),
            gc_versions_purged: reg!(
                r,
                c("tidemark_gc_versions_purged_total", "Versions purged by GC")
            ),
            gc_blobs_deleted: reg!(
                r,
                c(
                    "tidemark_gc_blobs_deleted_total",
                    "Blob files unlinked by GC"
                )
            ),
            lifecycle_runs: reg!(r, c("tidemark_lifecycle_runs_total", "Lifecycle passes")),
            lifecycle_actions: reg!(
                r,
                IntCounterVec::new(
                    Opts::new(
                        "tidemark_lifecycle_actions_total",
                        "Lifecycle actions by kind"
                    ),
                    &["action"]
                )
            ),
            outbox_depth: reg!(
                r,
                g(
                    "tidemark_events_outbox_depth",
                    "Outbox rows not yet processed by the slowest sink"
                )
            ),
            events_delivered: reg!(
                r,
                IntCounterVec::new(
                    Opts::new("tidemark_events_delivered_total", "Events delivered"),
                    &["sink"]
                )
            ),
            events_failed: reg!(
                r,
                IntCounterVec::new(
                    Opts::new(
                        "tidemark_events_delivery_failures_total",
                        "Failed delivery attempts"
                    ),
                    &["sink"]
                )
            ),
            events_dead_lettered: reg!(
                r,
                IntCounterVec::new(
                    Opts::new(
                        "tidemark_events_dead_lettered_total",
                        "Events dead-lettered"
                    ),
                    &["sink"]
                )
            ),
            replication_lag: reg!(
                r,
                IntGaugeVec::new(
                    Opts::new(
                        "tidemark_replication_lag_seconds",
                        "Age of the oldest unreplicated version"
                    ),
                    &["bucket", "destination"]
                )
            ),
            replication_pending: reg!(
                r,
                IntGaugeVec::new(
                    Opts::new(
                        "tidemark_replication_pending",
                        "Versions waiting to replicate"
                    ),
                    &["bucket", "destination"]
                )
            ),
            audit_dropped: reg!(
                r,
                c(
                    "tidemark_audit_dropped_total",
                    "Audit records dropped (writer behind)"
                )
            ),
            registry: r,
        }
    }

    /// Text exposition of every metric.
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        let _ = TextEncoder::new().encode(&self.registry.gather(), &mut buf);
        String::from_utf8(buf).unwrap_or_default()
    }

    /// Record one finished request.
    pub fn observe_request(&self, op: &str, status: u16, secs: f64, bytes_in: u64, out: u64) {
        self.requests
            .with_label_values(&[op, &status.to_string()])
            .inc();
        self.latency.with_label_values(&[op]).observe(secs);
        self.bytes_in.inc_by(bytes_in);
        self.bytes_out.inc_by(out);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics::new()
    }
}

impl EventMetrics for Metrics {
    fn delivered(&self, sink: &str, n: usize) {
        self.events_delivered
            .with_label_values(&[sink])
            .inc_by(n as u64);
    }
    fn attempt_failed(&self, sink: &str, _err: &SinkError) {
        self.events_failed.with_label_values(&[sink]).inc();
    }
    fn dead_lettered(&self, sink: &str, n: usize) {
        self.events_dead_lettered
            .with_label_values(&[sink])
            .inc_by(n as u64);
    }
}

impl tidemark_engine::replication::ReplicationObserver for Metrics {
    fn observe(&self, s: &tidemark_engine::replication::DestinationStatus) {
        let l = [s.bucket.as_str(), s.destination.as_str()];
        self.replication_lag
            .with_label_values(&l)
            .set(s.lag.as_secs() as i64);
        self.replication_pending
            .with_label_values(&l)
            .set(s.pending as i64);
    }
}
