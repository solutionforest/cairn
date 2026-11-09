//! Background tasks: GC, lifecycle, storage gauges, event delivery, outbox compaction,
//! replication and scrub. Each stops when the shutdown watch flips.

use crate::State;
use crate::clock::Clock;
use std::sync::Arc;
use std::time::Duration;
use tidemark_engine::tidemark_meta::{BlobRef, Flow, MetaStore, Reader, Table, decode};
use tidemark_events::{DeliveryWorker, Outbox, SseBroadcast, WebhookSink, WorkerOptions};
use tokio::sync::watch;
use tokio::task::JoinSet;

pub(crate) struct Workers {
    pub clock: Arc<dyn Clock>,
    pub gc_interval: Duration,
    pub lifecycle_interval: Duration,
    pub stats_interval: Duration,
    pub events_enabled: bool,
    pub max_attempts: u32,
    pub sinks: Vec<WebhookSink>,
    pub sse: Option<SseBroadcast>,
    pub outbox: Outbox,
    #[allow(dead_code)]
    pub replication_key: [u8; 32],
    pub scrub: Option<tidemark_engine::scrub::ScrubConfig>,
    pub scrub_idle: Duration,
    pub targets: Arc<tidemark_engine::replication::TargetRegistry>,
}

/// Sleep for `d` or return `true` if shutdown was requested first.
async fn stopped(stop: &mut watch::Receiver<bool>, d: Duration) -> bool {
    if *stop.borrow() {
        return true;
    }
    tokio::select! {
        r = stop.changed() => r.is_err() || *stop.borrow(),
        _ = tokio::time::sleep(d) => false,
    }
}

async fn until_stop(mut stop: watch::Receiver<bool>) {
    let _ = stop.wait_for(|v| *v).await;
}

/// Recompute the storage gauges (blob count/bytes from the `blobs` table, live/trash bytes
/// from the per-bucket usage counters).
pub(crate) fn refresh_storage_gauges(st: &State) -> anyhow::Result<()> {
    let r = st.engine.meta().read()?;
    let (mut n, mut bytes) = (0i64, 0i64);
    r.scan(
        Table::Blobs,
        std::ops::Bound::Unbounded,
        std::ops::Bound::Unbounded,
        &mut |_, v| {
            let b: BlobRef = decode(v)?;
            n += 1;
            bytes += b.size as i64;
            Ok(Flow::Continue)
        },
    )?;
    st.metrics.blobs.set(n);
    st.metrics.blob_bytes.set(bytes);
    let (mut live, mut trash) = (0u64, 0u64);
    for b in st.engine.list_buckets()? {
        let u = st.engine.usage_of(&b)?;
        live += u.live_bytes();
        trash += u.hidden_bytes;
    }
    st.metrics.live_bytes.set(live as i64);
    st.metrics.trash_bytes.set(trash as i64);
    Ok(())
}

/// Outbox depth behind the slowest configured sink.
pub(crate) fn outbox_depth(st: &State) -> u64 {
    if st.sink_ids.is_empty() {
        return 0;
    }
    let Ok(r) = st.engine.meta().read() else {
        return 0;
    };
    let ids: Vec<&str> = st.sink_ids.iter().map(String::as_str).collect();
    Outbox::min_cursor(&r, &ids)
        .and_then(|c| Outbox::depth_after(&r, c))
        .unwrap_or(0)
}

impl Workers {
    pub(crate) fn spawn(self, st: Arc<State>, stop: watch::Receiver<bool>) -> JoinSet<()> {
        let mut set = JoinSet::new();
        let engine = st.engine.clone();
        {
            let (st, clock, every, mut stop) = (
                st.clone(),
                self.clock.clone(),
                self.gc_interval.max(Duration::from_millis(50)),
                stop.clone(),
            );
            set.spawn(async move {
                loop {
                    if stopped(&mut stop, every).await {
                        return;
                    }
                    match st.engine.gc_tick(clock.now()).await {
                        Ok(s) => {
                            let m = &st.metrics;
                            m.gc_runs.inc();
                            m.gc_versions_purged.inc_by(s.versions_purged);
                            m.gc_blobs_deleted.inc_by(s.blobs_deleted);
                        }
                        Err(e) => tracing::warn!(error = %e, "gc tick failed"),
                    }
                    if !st.sink_ids.is_empty()
                        && let Err(e) = tidemark_events::worker::compact_outbox(
                            st.engine.meta(),
                            st.sink_ids.clone(),
                            10_000,
                        )
                        .await
                    {
                        tracing::warn!(error = %e, "outbox compaction failed");
                    }
                }
            });
        }
        {
            let (st, clock, every, mut stop) = (
                st.clone(),
                self.clock.clone(),
                self.lifecycle_interval.max(Duration::from_millis(50)),
                stop.clone(),
            );
            set.spawn(async move {
                loop {
                    if stopped(&mut stop, every).await {
                        return;
                    }
                    match st.engine.lifecycle_tick(clock.now()).await {
                        Ok(s) => {
                            let m = &st.metrics;
                            m.lifecycle_runs.inc();
                            for (k, n) in [
                                ("expire", s.expired),
                                ("expire_noncurrent", s.noncurrent_expired),
                                ("remove_delete_marker", s.delete_markers_removed),
                                ("abort_multipart", s.uploads_aborted),
                            ] {
                                m.lifecycle_actions.with_label_values(&[k]).inc_by(n);
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "lifecycle tick failed"),
                    }
                }
            });
        }
        {
            let (st, every, mut stop) = (
                st.clone(),
                self.stats_interval.max(Duration::from_millis(50)),
                stop.clone(),
            );
            set.spawn(async move {
                loop {
                    let s2 = st.clone();
                    match tokio::task::spawn_blocking(move || refresh_storage_gauges(&s2)).await {
                        Ok(Err(e)) => tracing::warn!(error = %e, "storage gauge refresh failed"),
                        Err(e) => tracing::warn!(error = %e, "storage gauge task failed"),
                        Ok(Ok(())) => {}
                    }
                    if stopped(&mut stop, every).await {
                        return;
                    }
                }
            });
        }
        let opts = WorkerOptions {
            max_attempts: self.max_attempts.max(1),
            ..Default::default()
        };
        let mut delivery: Vec<Arc<dyn tidemark_events::Sink>> = Vec::new();
        if self.events_enabled {
            for s in self.sinks {
                delivery.push(Arc::new(s));
            }
        }
        if let Some(b) = self.sse {
            delivery.push(Arc::new(b));
        }
        for sink in delivery {
            let w = DeliveryWorker::new(engine.meta().clone(), self.outbox.clone(), sink)
                .with_options(opts.clone())
                .with_metrics(st.metrics.clone());
            let stop = stop.clone();
            set.spawn(async move {
                if let Err(e) = w.run(stop).await {
                    tracing::error!(error = %e, "event delivery worker stopped");
                }
            });
        }
        let repl = tidemark_engine::replication::ReplicationWorker::new(
            engine.clone(),
            self.targets.clone(),
        )
        .with_observer(st.metrics.clone());
        set.spawn(repl.run(until_stop(stop.clone())));
        if let Some(cfg) = self.scrub {
            let s = tidemark_engine::scrub::Scrubber::new(engine.clone(), cfg);
            set.spawn(s.run(self.scrub_idle, until_stop(stop.clone())));
        }
        set
    }
}

/// `GET /events` (mounted under `/_tidemark/v1` behind admin auth): the live SSE stream.
pub(crate) fn sse_routes(b: SseBroadcast) -> axum::Router {
    use axum::extract::{Query, State};
    use axum::response::sse::{KeepAlive, Sse};
    async fn handler(
        State(b): State<SseBroadcast>,
        Query(q): Query<tidemark_events::sse::SseQuery>,
    ) -> impl axum::response::IntoResponse {
        Sse::new(tidemark_events::sse::event_stream(b.subscribe(), q))
            .keep_alive(KeepAlive::default())
    }
    axum::Router::new()
        .route("/events", axum::routing::get(handler))
        .with_state(b)
}
