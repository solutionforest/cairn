//! Upload scanning: every new object is streamed to a [`Scanner`] before it is committed.
//! Infected uploads are committed into the quarantine bucket instead of their target and the
//! client gets `VirusDetected`. The scanner itself (ClamAV, an HTTP endpoint) lives in the server
//! crate; the engine only decides what happens with the verdict.

use crate::TidemarkEngine;
use crate::types::BodyStream;
use std::sync::Arc;
use tidemark_core::{BucketId, S3Error, S3ErrorCode, S3Result};
use tidemark_meta::ObjectBody;

/// User metadata keys stamped on a quarantined object (`x-amz-meta-…`).
pub const META_SIGNATURE: &str = "tidemark-scan-signature";
/// Bucket the upload was meant for.
pub const META_SOURCE_BUCKET: &str = "tidemark-source-bucket";
/// Key the upload was meant for.
pub const META_SOURCE_KEY: &str = "tidemark-source-key";

/// What the scanner is told about an object besides its bytes.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    /// Target bucket.
    pub bucket: String,
    /// Target key.
    pub key: String,
    /// Exact byte length of the stream.
    pub size: u64,
}

/// Scanner verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing found.
    Clean,
    /// Infected; the signature name the scanner reported.
    Infected(String),
}

/// A malware scanner the engine streams new objects to.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync {
    /// Scan one object. `Err` means the scanner could not give a verdict (down, timeout,
    /// protocol error); [`OnError`] decides what happens then.
    async fn scan(&self, req: ScanRequest, body: BodyStream) -> Result<Verdict, String>;
}

/// What to do when no verdict is available (scanner error, or object over `max_size`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    /// Refuse the upload (`503 ServiceUnavailable`; over-size: `400 EntityTooLarge`).
    Reject,
    /// Store it unscanned (logged).
    Allow,
}

/// Engine-side scan configuration.
#[derive(Clone)]
pub struct ScanGate {
    /// The scanner.
    pub scanner: Arc<dyn Scanner>,
    /// Bucket infected uploads are committed into (never scanned itself).
    pub quarantine_bucket: String,
    /// Objects larger than this are not scanned; `on_oversize` decides.
    pub max_size: u64,
    /// Scanner unavailable.
    pub on_error: OnError,
    /// Object over `max_size`.
    pub on_oversize: OnError,
}

/// Where a scanned upload goes.
pub(crate) enum ScanOutcome {
    /// Commit to the requested bucket and key.
    Store,
    /// Commit into quarantine, then answer `VirusDetected`.
    Quarantine(Quarantine),
}

/// Quarantine target for an infected upload.
pub(crate) struct Quarantine {
    pub bucket_id: BucketId,
    pub bucket: String,
    pub key: String,
    pub signature: String,
}

impl Quarantine {
    /// Stamp the verdict and original location onto the body.
    pub fn stamp(&self, body: &mut ObjectBody, src_bucket: &str, src_key: &str) {
        let m = &mut body.user_metadata;
        m.insert(META_SIGNATURE.into(), self.signature.clone());
        m.insert(META_SOURCE_BUCKET.into(), src_bucket.into());
        m.insert(META_SOURCE_KEY.into(), src_key.into());
    }

    /// The error the client sees after the object was quarantined.
    pub fn error(&self) -> S3Error {
        virus_detected(&self.signature)
    }
}

pub(crate) fn virus_detected(signature: &str) -> S3Error {
    S3Error::new(
        S3ErrorCode::VirusDetected,
        format!("The upload was rejected by the malware scanner: {signature}"),
    )
}

impl TidemarkEngine {
    /// The configured scan gate, if any.
    pub fn scan_gate(&self) -> Option<&ScanGate> {
        self.inner.scan.as_ref()
    }

    /// Create the quarantine bucket (versioned) if it does not exist yet. Called once at startup.
    pub async fn ensure_quarantine_bucket(
        &self,
        owner: &tidemark_core::PrincipalId,
    ) -> S3Result<()> {
        let Some(g) = &self.inner.scan else {
            return Ok(());
        };
        match self.bucket(&g.quarantine_bucket) {
            Ok(_) => Ok(()),
            Err(e) if e.code == S3ErrorCode::NoSuchBucket => {
                match self
                    .create_bucket(&g.quarantine_bucket, owner, false, None)
                    .await
                {
                    Ok(_)
                    | Err(S3Error {
                        code: S3ErrorCode::BucketAlreadyOwnedByYou,
                        ..
                    }) => {}
                    Err(e) => return Err(e),
                }
                self.put_bucket_versioning(&g.quarantine_bucket, true).await
            }
            Err(e) => Err(e),
        }
    }

    /// Scan an assembled (not yet committed) object bound for `bucket`/`key`.
    pub(crate) async fn scan_upload(
        &self,
        bucket: &str,
        key: &str,
        body: &ObjectBody,
    ) -> S3Result<ScanOutcome> {
        let Some(verdict) = self.verdict(bucket, key, body).await? else {
            return Ok(ScanOutcome::Store);
        };
        match verdict {
            Verdict::Clean => Ok(ScanOutcome::Store),
            Verdict::Infected(signature) => {
                let g = self.inner.scan.as_ref().expect("verdict implies a gate");
                let q = self.bucket(&g.quarantine_bucket).map_err(|e| {
                    tracing::error!(bucket = %g.quarantine_bucket, error = %e, "quarantine bucket missing");
                    S3Error::code(S3ErrorCode::ServiceUnavailable)
                })?;
                tracing::warn!(%bucket, %key, %signature, quarantine = %q.name, "infected upload quarantined");
                Ok(ScanOutcome::Quarantine(Quarantine {
                    bucket_id: q.id,
                    bucket: q.name,
                    key: format!("{bucket}/{key}"),
                    signature,
                }))
            }
        }
    }

    /// Scan without quarantining (CopyObject: the source stays where it is).
    pub(crate) async fn scan_copy(
        &self,
        bucket: &str,
        key: &str,
        body: &ObjectBody,
    ) -> S3Result<()> {
        match self.verdict(bucket, key, body).await? {
            Some(Verdict::Infected(sig)) => {
                tracing::warn!(%bucket, %key, signature = %sig, "infected copy refused");
                Err(virus_detected(&sig))
            }
            _ => Ok(()),
        }
    }

    /// `None`: not scanned (no gate, quarantine target, or allowed without a verdict).
    async fn verdict(
        &self,
        bucket: &str,
        key: &str,
        body: &ObjectBody,
    ) -> S3Result<Option<Verdict>> {
        let Some(g) = &self.inner.scan else {
            return Ok(None);
        };
        if bucket == g.quarantine_bucket {
            return Ok(None);
        }
        if body.size > g.max_size {
            return match g.on_oversize {
                OnError::Allow => {
                    tracing::info!(%bucket, %key, size = body.size, "object over scan max_size stored unscanned");
                    Ok(None)
                }
                OnError::Reject => Err(S3Error::new(
                    S3ErrorCode::EntityTooLarge,
                    "The object is larger than the malware scanner accepts.",
                )),
            };
        }
        let req = ScanRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            size: body.size,
        };
        match g
            .scanner
            .scan(req, self.stream_object(body, 0, body.size))
            .await
        {
            Ok(v) => Ok(Some(v)),
            Err(e) => match g.on_error {
                OnError::Allow => {
                    tracing::warn!(%bucket, %key, error = %e, "scanner unavailable; stored unscanned");
                    Ok(None)
                }
                OnError::Reject => {
                    tracing::error!(%bucket, %key, error = %e, "scanner unavailable; upload refused");
                    Err(S3Error::new(
                        S3ErrorCode::ServiceUnavailable,
                        "The malware scanner is unavailable. Try again later.",
                    ))
                }
            },
        }
    }
}
