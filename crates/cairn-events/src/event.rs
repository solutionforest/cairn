//! Event types and their S3 event-message (schema 2.1) JSON rendering.

use cairn_core::Ts;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Every event Cairn emits. S3 names keep their AWS spelling; Cairn extensions use `cairn:`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventName {
    /// `s3:ObjectCreated:Put`
    ObjectCreatedPut,
    /// `s3:ObjectCreated:Post`
    ObjectCreatedPost,
    /// `s3:ObjectCreated:Copy`
    ObjectCreatedCopy,
    /// `s3:ObjectCreated:CompleteMultipartUpload`
    ObjectCreatedCompleteMultipartUpload,
    /// `s3:ObjectRemoved:Delete`
    ObjectRemovedDelete,
    /// `s3:ObjectRemoved:DeleteMarkerCreated`
    ObjectRemovedDeleteMarkerCreated,
    /// `s3:ObjectRestore:Post`
    ObjectRestorePost,
    /// `s3:ObjectRestore:Completed`
    ObjectRestoreCompleted,
    /// `s3:ObjectRestore:Delete`
    ObjectRestoreDelete,
    /// `s3:LifecycleExpiration:Delete`
    LifecycleExpirationDelete,
    /// `s3:LifecycleExpiration:DeleteMarkerCreated`
    LifecycleExpirationDeleteMarkerCreated,
    /// `s3:ObjectTagging:Put`
    ObjectTaggingPut,
    /// `s3:ObjectTagging:Delete`
    ObjectTaggingDelete,
    /// `cairn:TrashRestored` — a soft-deleted version was restored from trash.
    CairnTrashRestored,
    /// `cairn:PitrRestore` — a key or bucket was restored to a point in time.
    CairnPitrRestore,
    /// `cairn:BucketDeleted` — a bucket was (soft-)deleted.
    CairnBucketDeleted,
}

impl EventName {
    /// Every event name.
    pub const ALL: &'static [EventName] = &[
        EventName::ObjectCreatedPut,
        EventName::ObjectCreatedPost,
        EventName::ObjectCreatedCopy,
        EventName::ObjectCreatedCompleteMultipartUpload,
        EventName::ObjectRemovedDelete,
        EventName::ObjectRemovedDeleteMarkerCreated,
        EventName::ObjectRestorePost,
        EventName::ObjectRestoreCompleted,
        EventName::ObjectRestoreDelete,
        EventName::LifecycleExpirationDelete,
        EventName::LifecycleExpirationDeleteMarkerCreated,
        EventName::ObjectTaggingPut,
        EventName::ObjectTaggingDelete,
        EventName::CairnTrashRestored,
        EventName::CairnPitrRestore,
        EventName::CairnBucketDeleted,
    ];

    /// Full name as used in notification configurations, e.g. `s3:ObjectCreated:Put`.
    pub fn as_str(self) -> &'static str {
        use EventName::*;
        match self {
            ObjectCreatedPut => "s3:ObjectCreated:Put",
            ObjectCreatedPost => "s3:ObjectCreated:Post",
            ObjectCreatedCopy => "s3:ObjectCreated:Copy",
            ObjectCreatedCompleteMultipartUpload => "s3:ObjectCreated:CompleteMultipartUpload",
            ObjectRemovedDelete => "s3:ObjectRemoved:Delete",
            ObjectRemovedDeleteMarkerCreated => "s3:ObjectRemoved:DeleteMarkerCreated",
            ObjectRestorePost => "s3:ObjectRestore:Post",
            ObjectRestoreCompleted => "s3:ObjectRestore:Completed",
            ObjectRestoreDelete => "s3:ObjectRestore:Delete",
            LifecycleExpirationDelete => "s3:LifecycleExpiration:Delete",
            LifecycleExpirationDeleteMarkerCreated => "s3:LifecycleExpiration:DeleteMarkerCreated",
            ObjectTaggingPut => "s3:ObjectTagging:Put",
            ObjectTaggingDelete => "s3:ObjectTagging:Delete",
            CairnTrashRestored => "cairn:TrashRestored",
            CairnPitrRestore => "cairn:PitrRestore",
            CairnBucketDeleted => "cairn:BucketDeleted",
        }
    }

    /// The `eventName` field of an event record: S3 events drop the `s3:` prefix.
    pub fn record_name(self) -> &'static str {
        let s = self.as_str();
        s.strip_prefix("s3:").unwrap_or(s)
    }

    /// Whether this is a Cairn extension event.
    pub fn is_cairn(self) -> bool {
        self.as_str().starts_with("cairn:")
    }

    /// Parse a full name (`s3:ObjectCreated:Put`).
    pub fn parse(s: &str) -> Option<EventName> {
        EventName::ALL.iter().copied().find(|e| e.as_str() == s)
    }
}

impl std::fmt::Display for EventName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One committed mutation. Plain fields only so it encodes with postcard in the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// What happened.
    pub name: EventName,
    /// Commit time.
    pub time: Ts,
    /// Region name reported to clients.
    pub region: String,
    /// Bucket name.
    pub bucket: String,
    /// Object key (empty for bucket-level events).
    pub key: String,
    /// Object size in bytes.
    pub size: Option<u64>,
    /// ETag without quotes.
    pub etag: Option<String>,
    /// Version id (40-hex form) or `null`.
    pub version_id: Option<String>,
    /// Principal that caused the event (`PrincipalId` string form).
    pub principal: String,
    /// Client IP address.
    pub source_ip: Option<String>,
    /// Request id of the causing request.
    pub request_id: String,
    /// Cairn-specific details (e.g. `as_of`, `restored_version_id`), rendered under `cairn`.
    pub extra: Vec<(String, String)>,
}

impl Event {
    /// A minimal event; fill optional fields with struct update syntax.
    pub fn new(name: EventName, bucket: impl Into<String>, key: impl Into<String>) -> Event {
        Event {
            name,
            time: Ts::now(),
            region: "us-east-1".into(),
            bucket: bucket.into(),
            key: key.into(),
            size: None,
            etag: None,
            version_id: None,
            principal: "anonymous".into(),
            source_ip: None,
            request_id: String::new(),
            extra: Vec::new(),
        }
    }

    /// Render as one S3 event-message record (schema 2.1). `seq` is the outbox sequence (used
    /// for `s3.object.sequencer` and the idempotency key); `configuration_id` is the matching
    /// notification rule id.
    pub fn to_record(&self, seq: u64, configuration_id: &str) -> Value {
        let time = jiff::Timestamp::from_nanosecond(self.time.nanos())
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
            .strftime("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let mut object = serde_json::Map::new();
        if !self.key.is_empty() {
            object.insert("key".into(), json!(encode_key(&self.key)));
        }
        if let Some(s) = self.size {
            object.insert("size".into(), json!(s));
        }
        if let Some(e) = &self.etag {
            object.insert("eTag".into(), json!(e));
        }
        if let Some(v) = &self.version_id {
            object.insert("versionId".into(), json!(v));
        }
        object.insert("sequencer".into(), json!(sequencer(seq)));
        let extra: serde_json::Map<String, Value> = self
            .extra
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        json!({
            "eventVersion": "2.1",
            "eventSource": if self.name.is_cairn() { "cairn:s3" } else { "aws:s3" },
            "awsRegion": self.region,
            "eventTime": time,
            "eventName": self.name.record_name(),
            "userIdentity": { "principalId": self.principal },
            "requestParameters": { "sourceIPAddress": self.source_ip.as_deref().unwrap_or("") },
            "responseElements": {
                "x-amz-request-id": self.request_id,
                "x-amz-id-2": self.request_id,
            },
            "s3": {
                "s3SchemaVersion": "1.0",
                "configurationId": configuration_id,
                "bucket": {
                    "name": self.bucket,
                    "ownerIdentity": { "principalId": self.principal },
                    "arn": format!("arn:aws:s3:::{}", self.bucket),
                },
                "object": object,
            },
            "cairn": {
                "id": idempotency_key(seq),
                "extra": extra,
            },
        })
    }
}

/// Wrap records in the S3 notification envelope `{"Records": [...]}`.
pub fn envelope(records: Vec<Value>) -> Value {
    json!({ "Records": records })
}

/// The stable idempotency key of the event at outbox sequence `seq`. Receivers dedupe on it.
pub fn idempotency_key(seq: u64) -> String {
    format!("{seq:016x}")
}

/// S3-style sequencer: uppercase hex, lexicographically ordered for one key.
pub fn sequencer(seq: u64) -> String {
    format!("{seq:016X}")
}

/// S3 event keys are form-URL-encoded (space becomes `+`) with `/` left as is, matching AWS.
pub fn encode_key(key: &str) -> String {
    key.split('/')
        .map(|seg| url::form_urlencoded::byte_serialize(seg.as_bytes()).collect::<String>())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for n in EventName::ALL {
            assert_eq!(EventName::parse(n.as_str()), Some(*n));
        }
        assert_eq!(
            EventName::ObjectCreatedPut.record_name(),
            "ObjectCreated:Put"
        );
        assert_eq!(
            EventName::CairnPitrRestore.record_name(),
            "cairn:PitrRestore"
        );
        assert_eq!(EventName::parse("s3:ObjectCreated:*"), None);
    }

    #[test]
    fn record_shape() {
        let mut e = Event::new(EventName::ObjectCreatedPut, "photos", "a dir/ü.jpg");
        e.time = Ts::from_secs(1_700_000_000);
        e.size = Some(42);
        e.etag = Some("abc".into());
        e.principal = "root".into();
        let r = e.to_record(255, "cfg-1");
        assert_eq!(r["eventVersion"], "2.1");
        assert_eq!(r["eventSource"], "aws:s3");
        assert_eq!(r["eventName"], "ObjectCreated:Put");
        assert_eq!(r["eventTime"], "2023-11-14T22:13:20.000Z");
        assert_eq!(r["s3"]["configurationId"], "cfg-1");
        assert_eq!(r["s3"]["bucket"]["arn"], "arn:aws:s3:::photos");
        assert_eq!(r["s3"]["object"]["key"], "a+dir/%C3%BC.jpg");
        assert_eq!(r["s3"]["object"]["size"], 42);
        assert_eq!(r["s3"]["object"]["sequencer"], "00000000000000FF");
        assert_eq!(r["cairn"]["id"], "00000000000000ff");
        let c = Event::new(EventName::CairnBucketDeleted, "photos", "").to_record(1, "x");
        assert_eq!(c["eventSource"], "cairn:s3");
        assert!(c["s3"]["object"].get("key").is_none());
    }
}
