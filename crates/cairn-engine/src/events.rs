//! Event emission from inside commit closures (DESIGN §10) and the per-request context
//! (request id, source IP) the S3 layer provides through a task-local.

use crate::util::s3_version_id;
use cairn_core::{PrincipalId, S3Result};
use cairn_events::{Event, EventName, Outbox};
use cairn_meta::{BucketRecord, VersionRecord, WriteTxn};

pub use cairn_events;

/// Facts about the request that caused a mutation, carried into emitted events.
#[derive(Debug, Clone, Default)]
pub struct RequestCtx {
    /// Request id (`x-amz-request-id`).
    pub request_id: String,
    /// Client address.
    pub source_ip: Option<String>,
}

tokio::task_local! {
    /// Request context of the task currently calling the engine.
    pub static REQUEST_CTX: RequestCtx;
}

/// Run `fut` with `ctx` as the request context of every engine call it makes.
pub async fn with_request_ctx<F: Future>(ctx: RequestCtx, fut: F) -> F::Output {
    REQUEST_CTX.scope(ctx, fut).await
}

/// The current request context (empty outside [`with_request_ctx`]).
pub fn current_ctx() -> RequestCtx {
    REQUEST_CTX.try_with(|c| c.clone()).unwrap_or_default()
}

/// Everything needed to build events inside a write job (cloned into the closure).
#[derive(Clone)]
pub(crate) struct Emitter {
    pub outbox: Outbox,
    pub region: String,
    pub ctx: RequestCtx,
    pub principal: String,
}

impl Emitter {
    /// Build and append one event for `key` (and its new or affected version, if any).
    pub fn emit(
        &self,
        txn: &WriteTxn,
        b: &BucketRecord,
        name: EventName,
        key: &str,
        v: Option<&VersionRecord>,
        extra: Vec<(String, String)>,
    ) -> S3Result<()> {
        let mut e = Event::new(name, b.name.clone(), key);
        e.region = self.region.clone();
        e.principal = self.principal.clone();
        e.source_ip = self.ctx.source_ip.clone();
        e.request_id = self.ctx.request_id.clone();
        e.extra = extra;
        if let Some(v) = v {
            e.time = v.created_at;
            e.version_id = s3_version_id(v, b.versioning);
            if let Some(body) = v.body() {
                e.size = Some(body.size);
                e.etag = Some(body.etag.clone());
            }
        }
        self.outbox.append(txn, b.id, &e)?;
        Ok(())
    }
}

impl crate::CairnEngine {
    pub(crate) fn emitter(&self, by: &PrincipalId) -> Emitter {
        Emitter {
            outbox: self.inner.outbox.clone(),
            region: self.inner.region.clone(),
            ctx: current_ctx(),
            principal: by.as_str().to_string(),
        }
    }

    /// Wake event delivery workers after a committed write.
    pub(crate) fn notify(&self) {
        self.inner.outbox.notify();
    }

    /// The outbox this engine appends to.
    pub fn outbox(&self) -> &Outbox {
        &self.inner.outbox
    }
}
