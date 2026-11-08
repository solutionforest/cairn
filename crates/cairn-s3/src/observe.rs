//! Request observation for metrics and audit: an [`S3Access`] wrapper that records the s3s
//! operation name, target and authorisation outcome into an [`OpSlot`] the HTTP layer placed
//! in the request extensions (the HTTP layer cannot see the operation s3s routed to).

use s3s::access::{S3Access, S3AccessContext};
use s3s::dto::DeleteObjectsInput;
use s3s::{S3Request, S3Result};
use std::sync::{Arc, Mutex};

/// What the access hook learned about a request.
#[derive(Debug, Clone, Default)]
pub struct OpInfo {
    /// s3s operation name, e.g. `PutObject`.
    pub op: Option<String>,
    /// Bucket from the path.
    pub bucket: Option<String>,
    /// Key from the path.
    pub key: Option<String>,
    /// Principal id once resolved (`anonymous` for unsigned requests).
    pub principal: Option<String>,
    /// Access key id that signed the request.
    pub access_key: Option<String>,
    /// The policy check refused the request.
    pub denied: bool,
}

/// Shared slot in request extensions; cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct OpSlot(pub Arc<Mutex<OpInfo>>);

impl OpSlot {
    /// Snapshot of the recorded facts.
    pub fn get(&self) -> OpInfo {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn update(&self, f: impl FnOnce(&mut OpInfo)) {
        f(&mut self.0.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

/// Wraps an [`S3Access`] (normally `cairn_auth::CairnS3Access`) and records into [`OpSlot`].
/// Forwards `check` and `delete_objects`, the hooks Cairn's access checker implements.
pub struct ObservedAccess<A>(pub A);

fn caller_id(ext: &http::Extensions) -> Option<String> {
    ext.get::<cairn_auth::AuthenticatedCaller>().map(|c| {
        c.principal
            .as_ref()
            .map_or_else(|| "anonymous".to_string(), |p| p.id.as_str().to_string())
    })
}

#[async_trait::async_trait]
impl<A: S3Access> S3Access for ObservedAccess<A> {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        let slot = cx.extensions_mut().get::<OpSlot>().cloned();
        if let Some(s) = &slot {
            let path = cx.s3_path();
            let (op, b, k, ak) = (
                cx.s3_op().name().to_string(),
                path.get_bucket_name().map(str::to_string),
                path.get_object_key().map(str::to_string),
                cx.credentials().map(|c| c.access_key.clone()),
            );
            s.update(|i| {
                i.op = Some(op);
                i.bucket = b;
                i.key = k;
                i.access_key = ak;
            });
        }
        let r = self.0.check(cx).await;
        if let Some(s) = &slot {
            let who = caller_id(cx.extensions_mut());
            let denied = r.is_err();
            s.update(|i| {
                i.principal = who;
                i.denied = denied;
            });
        }
        r
    }

    async fn delete_objects(&self, req: &mut S3Request<DeleteObjectsInput>) -> S3Result<()> {
        let r = self.0.delete_objects(req).await;
        if r.is_err()
            && let Some(s) = req.extensions.get::<OpSlot>()
        {
            s.update(|i| i.denied = true);
        }
        r
    }
}
