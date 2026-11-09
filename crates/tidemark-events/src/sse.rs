//! In-process broadcast sink and the `GET /_tidemark/v1/events` Server-Sent Events stream.
//!
//! The stream is live-only: a subscriber sees events committed after it connected (the
//! broadcast sink's worker feeds it from the durable outbox). Slow subscribers that fall more
//! than the channel capacity behind receive an `event: lagged` frame with the number of missed
//! events. Authentication and authorisation are applied by the caller's router layers.

use crate::event::Event;
use crate::matcher::{event_matches, key_matches};
use crate::notification::FilterRule;
use crate::outbox::OutboxRecord;
use crate::sink::{Delivery, Sink, SinkError};
use axum::extract::{Query, State};
use axum::response::sse::{self, KeepAlive, Sse};
use axum::routing::get;
use futures::future::BoxFuture;
use futures::stream::{self, Stream};
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Route path of the SSE stream.
pub const SSE_PATH: &str = "/_tidemark/v1/events";

/// One broadcast item.
#[derive(Debug, Clone)]
pub struct Broadcasted {
    /// Outbox sequence.
    pub seq: u64,
    /// The event.
    pub event: Arc<Event>,
}

/// Sink that fans committed events out to live SSE subscribers.
#[derive(Clone, Debug)]
pub struct SseBroadcast {
    id: String,
    tx: broadcast::Sender<Broadcasted>,
}

impl SseBroadcast {
    /// Sink id used for its cursor.
    pub const DEFAULT_ID: &'static str = "_sse";

    /// New broadcaster buffering up to `capacity` events per subscriber.
    pub fn new(capacity: usize) -> SseBroadcast {
        SseBroadcast {
            id: SseBroadcast::DEFAULT_ID.into(),
            tx: broadcast::channel(capacity.max(1)).0,
        }
    }

    /// Subscribe to the live feed.
    pub fn subscribe(&self) -> broadcast::Receiver<Broadcasted> {
        self.tx.subscribe()
    }

    /// Current subscriber count.
    pub fn subscribers(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Sink for SseBroadcast {
    fn id(&self) -> &str {
        &self.id
    }

    fn accepts(&self, rec: &OutboxRecord) -> Option<String> {
        rec.only_sink.is_none().then(String::new)
    }

    fn batch_size(&self) -> usize {
        100
    }

    fn deliver<'a>(&'a self, batch: &'a [Delivery]) -> BoxFuture<'a, Result<(), SinkError>> {
        Box::pin(async move {
            for d in batch {
                let _ = self.tx.send(Broadcasted {
                    seq: d.seq,
                    event: Arc::new(d.record.event.clone()),
                });
            }
            Ok(())
        })
    }
}

/// Query parameters of the stream.
#[derive(Debug, Default, Deserialize)]
pub struct SseQuery {
    /// Comma-separated event-name globs (e.g. `s3:ObjectCreated:*,tidemark:*`); default all.
    pub filter: Option<String>,
    /// Only this bucket.
    pub bucket: Option<String>,
    /// Key prefix.
    pub prefix: Option<String>,
    /// Key suffix.
    pub suffix: Option<String>,
}

impl SseQuery {
    /// Whether an event passes this subscription's filters.
    pub fn matches(&self, e: &Event) -> bool {
        if let Some(b) = &self.bucket
            && b != &e.bucket
        {
            return false;
        }
        if let Some(f) = &self.filter
            && !f
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .any(|p| event_matches(p, e.name))
        {
            return false;
        }
        let mut rules = Vec::new();
        if let Some(p) = &self.prefix {
            rules.push(FilterRule {
                name: "prefix".into(),
                value: p.clone(),
            });
        }
        if let Some(s) = &self.suffix {
            rules.push(FilterRule {
                name: "suffix".into(),
                value: s.clone(),
            });
        }
        key_matches(&rules, &e.key)
    }
}

/// The filtered SSE frame stream for one subscriber.
pub fn event_stream(
    rx: broadcast::Receiver<Broadcasted>,
    q: SseQuery,
) -> impl Stream<Item = Result<sse::Event, Infallible>> + Send + 'static {
    stream::unfold((rx, q), |(mut rx, q)| async move {
        loop {
            match rx.recv().await {
                Ok(b) if q.matches(&b.event) => {
                    let data = b.event.to_record(b.seq, "").to_string();
                    let frame = sse::Event::default()
                        .id(b.seq.to_string())
                        .event(b.event.name.as_str())
                        .data(data);
                    return Some((Ok(frame), (rx, q)));
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    let frame = sse::Event::default().event("lagged").data(n.to_string());
                    return Some((Ok(frame), (rx, q)));
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

async fn handler(
    State(b): State<SseBroadcast>,
    Query(q): Query<SseQuery>,
) -> Sse<impl Stream<Item = Result<sse::Event, Infallible>>> {
    Sse::new(event_stream(b.subscribe(), q)).keep_alive(KeepAlive::default())
}

/// Router serving `GET /_tidemark/v1/events`; merge it into the admin router behind auth.
pub fn sse_router(b: SseBroadcast) -> axum::Router {
    axum::Router::new()
        .route(SSE_PATH, get(handler))
        .with_state(b)
}
