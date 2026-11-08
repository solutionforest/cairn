#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Cairn event notifications (DESIGN §10).
//!
//! Flow: the engine calls [`Outbox::append`] inside the same metadata write transaction that
//! commits a mutation, so the outbox holds exactly the committed set. One [`DeliveryWorker`] per
//! sink tails the outbox from its durable cursor, delivers batches with retries and exponential
//! backoff, and moves exhausted batches to the dead-letter queue. Sinks are HTTP webhooks (HMAC
//! signed), function sinks (`bearer`, `sigv4-lambda`, `cf-access`) and the in-process
//! [`SseBroadcast`] behind `GET /_cairn/v1/events`.

pub mod event;
pub mod matcher;
pub mod notification;
pub mod outbox;
pub mod secret;
pub mod sigv4;
pub mod sink;
pub mod sse;
pub mod worker;

pub use event::{Event, EventName};
pub use matcher::Target;
pub use notification::{FilterRule, NotificationConfiguration, NotificationRule, TargetKind};
pub use outbox::{DlqRecord, Outbox, OutboxRecord};
pub use secret::Secret;
pub use sink::{Sink, SinkAuth, SinkConfig, SinkError, WebhookSink};
pub use sse::{SseBroadcast, sse_router};
pub use worker::{DeliveryWorker, EventMetrics, NoopMetrics, WorkerOptions};

/// Errors from the events subsystem.
#[derive(Debug, thiserror::Error)]
pub enum EventsError {
    /// Metadata store failure.
    #[error(transparent)]
    Meta(#[from] cairn_meta::MetaError),
    /// Malformed notification configuration XML.
    #[error("malformed notification configuration: {0}")]
    MalformedXml(String),
    /// Semantically invalid notification configuration.
    #[error("invalid notification configuration: {0}")]
    InvalidArgument(String),
    /// Invalid sink configuration.
    #[error("invalid sink configuration: {0}")]
    Sink(String),
}

impl From<EventsError> for cairn_core::S3Error {
    fn from(e: EventsError) -> Self {
        use cairn_core::{S3Error, S3ErrorCode};
        match e {
            EventsError::MalformedXml(m) => S3Error::new(S3ErrorCode::MalformedXML, m),
            EventsError::InvalidArgument(m) => S3Error::new(S3ErrorCode::InvalidArgument, m),
            other => S3Error::internal(other),
        }
    }
}
