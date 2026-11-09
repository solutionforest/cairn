//! `NotificationConfiguration` model, AWS XML (de)serialisation, validation and per-bucket
//! persistence in the `kv` table.

use crate::EventsError;
use crate::event::EventName;
use quick_xml::events::Event as X;
use serde::{Deserialize, Serialize};
use tidemark_core::BucketId;
use tidemark_meta::{Reader, Table, WriteTxn, decode, encode};

/// S3 XML namespace.
pub const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Which configuration element a rule came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    /// `TopicConfiguration` / `Topic`.
    Topic,
    /// `QueueConfiguration` / `Queue`.
    Queue,
    /// `CloudFunctionConfiguration` / `CloudFunction` (the SDK's `LambdaFunctionConfigurations`).
    Lambda,
}

impl TargetKind {
    fn element(self) -> &'static str {
        match self {
            TargetKind::Topic => "TopicConfiguration",
            TargetKind::Queue => "QueueConfiguration",
            TargetKind::Lambda => "CloudFunctionConfiguration",
        }
    }

    fn arn_element(self) -> &'static str {
        match self {
            TargetKind::Topic => "Topic",
            TargetKind::Queue => "Queue",
            TargetKind::Lambda => "CloudFunction",
        }
    }
}

/// One `FilterRule` under `Filter/S3Key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterRule {
    /// `prefix` or `suffix` (stored lowercase).
    pub name: String,
    /// Value to match.
    pub value: String,
}

/// One topic/queue/function configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRule {
    /// `Id` (optional in requests; becomes the record's `configurationId`).
    pub id: Option<String>,
    /// Element kind.
    pub kind: TargetKind,
    /// Destination ARN (`arn:tidemark:sink::<sink-id>` or an alias configured on a sink).
    pub arn: String,
    /// Event names or globs, e.g. `s3:ObjectCreated:*`.
    pub events: Vec<String>,
    /// Key filter rules.
    pub filter: Vec<FilterRule>,
    /// `InvocationRole` (CloudFunction only, legacy; round-tripped, unused).
    pub invocation_role: Option<String>,
}

/// A bucket's notification configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NotificationConfiguration {
    /// All rules in document order.
    pub rules: Vec<NotificationRule>,
    /// `EventBridgeConfiguration` present (accepted and round-tripped; no EventBridge sink).
    pub event_bridge: bool,
}

#[derive(Debug, Default)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    fn text_of(&self, name: &str) -> Option<String> {
        self.child(name).map(|c| c.text.trim().to_string())
    }
}

fn malformed(e: impl std::fmt::Display) -> EventsError {
    EventsError::MalformedXml(e.to_string())
}

fn parse_tree(xml: &str) -> Result<Node, EventsError> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack: Vec<Node> = vec![Node::default()];
    loop {
        match reader.read_event().map_err(malformed)? {
            X::Start(s) => stack.push(Node {
                name: s.local_name().as_ref().to_string(),
                ..Node::default()
            }),
            X::Empty(s) => {
                let n = Node {
                    name: s.local_name().as_ref().to_string(),
                    ..Node::default()
                };
                stack.last_mut().expect("root").children.push(n);
            }
            X::End(_) => {
                let n = stack.pop().expect("balanced");
                let parent = stack
                    .last_mut()
                    .ok_or_else(|| malformed("unbalanced end tag"))?;
                parent.children.push(n);
            }
            X::Text(t) => stack
                .last_mut()
                .expect("root")
                .text
                .push_str(&t.xml10_content()),
            X::CData(c) => stack
                .last_mut()
                .expect("root")
                .text
                .push_str(&c.into_inner()),
            X::GeneralRef(r) => {
                let ch = if r.is_char_ref() {
                    r.resolve_char_ref().map_err(malformed)?
                } else {
                    match r.xml10_content().as_ref() {
                        "amp" => Some('&'),
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        other => return Err(malformed(format!("unknown entity &{other};"))),
                    }
                };
                let ch = ch.ok_or_else(|| malformed("invalid character reference"))?;
                stack.last_mut().expect("root").text.push(ch);
            }
            X::DocType(_) => return Err(malformed("DOCTYPE is not allowed")),
            X::Eof => break,
            _ => {}
        }
        if stack.len() > 16 {
            return Err(malformed("document nested too deeply"));
        }
    }
    if stack.len() != 1 {
        return Err(malformed("unexpected end of document"));
    }
    let root = stack.pop().expect("root");
    let mut elems = root.children.into_iter();
    match (elems.next(), elems.next()) {
        (Some(n), None) => Ok(n),
        _ => Err(malformed("expected exactly one root element")),
    }
}

impl NotificationConfiguration {
    /// Parse the AWS XML body of `PutBucketNotificationConfiguration`. Accepts both
    /// `CloudFunctionConfiguration`/`CloudFunction` (wire form) and
    /// `LambdaFunctionConfiguration`/`LambdaFunctionArn` (SDK member names).
    pub fn from_xml(xml: &str) -> Result<NotificationConfiguration, EventsError> {
        let root = parse_tree(xml)?;
        if root.name != "NotificationConfiguration" {
            return Err(malformed(format!("unexpected root element {}", root.name)));
        }
        let mut cfg = NotificationConfiguration::default();
        for el in &root.children {
            let (kind, arn_names): (TargetKind, &[&str]) = match el.name.as_str() {
                "TopicConfiguration" => (TargetKind::Topic, &["Topic", "TopicArn"]),
                "QueueConfiguration" => (TargetKind::Queue, &["Queue", "QueueArn"]),
                "CloudFunctionConfiguration" | "LambdaFunctionConfiguration" => (
                    TargetKind::Lambda,
                    &["CloudFunction", "LambdaFunctionArn", "Function"],
                ),
                "EventBridgeConfiguration" => {
                    cfg.event_bridge = true;
                    continue;
                }
                other => return Err(malformed(format!("unexpected element {other}"))),
            };
            let arn = arn_names
                .iter()
                .find_map(|n| el.text_of(n))
                .ok_or_else(|| malformed(format!("{} without destination ARN", el.name)))?;
            let events: Vec<String> = el
                .children_named("Event")
                .map(|e| e.text.trim().to_string())
                .collect();
            let mut filter = Vec::new();
            if let Some(f) = el.child("Filter") {
                let key = f.child("S3Key");
                for r in key.into_iter().flat_map(|k| k.children_named("FilterRule")) {
                    filter.push(FilterRule {
                        name: r.text_of("Name").unwrap_or_default().to_ascii_lowercase(),
                        value: r.child("Value").map(|v| v.text.clone()).unwrap_or_default(),
                    });
                }
            }
            cfg.rules.push(NotificationRule {
                id: el.text_of("Id").filter(|s| !s.is_empty()),
                kind,
                arn,
                events,
                filter,
                invocation_role: el.text_of("InvocationRole"),
            });
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Serialise to the AWS wire XML (what `GetBucketNotificationConfiguration` returns), rules in
    /// document order.
    pub fn to_xml(&self) -> String {
        use quick_xml::escape::escape;
        let mut out = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        out.push_str(&format!(
            r#"<NotificationConfiguration xmlns="{S3_XMLNS}">"#
        ));
        for r in &self.rules {
            let kind = r.kind;
            out.push_str(&format!("<{}>", kind.element()));
            if let Some(id) = &r.id {
                out.push_str(&format!("<Id>{}</Id>", escape(id.as_str())));
            }
            out.push_str(&format!(
                "<{0}>{1}</{0}>",
                kind.arn_element(),
                escape(r.arn.as_str())
            ));
            if let Some(role) = &r.invocation_role {
                out.push_str(&format!(
                    "<InvocationRole>{}</InvocationRole>",
                    escape(role.as_str())
                ));
            }
            for e in &r.events {
                out.push_str(&format!("<Event>{}</Event>", escape(e.as_str())));
            }
            if !r.filter.is_empty() {
                out.push_str("<Filter><S3Key>");
                for f in &r.filter {
                    out.push_str(&format!(
                        "<FilterRule><Name>{}</Name><Value>{}</Value></FilterRule>",
                        escape(f.name.as_str()),
                        escape(f.value.as_str())
                    ));
                }
                out.push_str("</S3Key></Filter>");
            }
            out.push_str(&format!("</{}>", kind.element()));
        }
        if self.event_bridge {
            out.push_str("<EventBridgeConfiguration></EventBridgeConfiguration>");
        }
        out.push_str("</NotificationConfiguration>");
        out
    }

    /// Check event names, filter rules and id uniqueness the way S3 does.
    pub fn validate(&self) -> Result<(), EventsError> {
        let bad = |m: String| Err(EventsError::InvalidArgument(m));
        let mut ids = std::collections::HashSet::new();
        for r in &self.rules {
            if r.arn.is_empty() {
                return bad("empty destination ARN".into());
            }
            if let Some(id) = &r.id
                && !ids.insert(id.as_str())
            {
                return bad(format!("duplicate configuration id {id}"));
            }
            if r.events.is_empty() {
                return bad("a configuration must name at least one Event".into());
            }
            for e in &r.events {
                if !valid_event_pattern(e) {
                    return bad(format!("unsupported event {e}"));
                }
            }
            let mut seen = std::collections::HashSet::new();
            for f in &r.filter {
                if f.name != "prefix" && f.name != "suffix" {
                    return bad(format!(
                        "filter rule name must be prefix or suffix, got {:?}",
                        f.name
                    ));
                }
                if !seen.insert(f.name.as_str()) {
                    return bad(format!("duplicate filter rule {}", f.name));
                }
                if f.value.len() > 1024 {
                    return bad("filter rule value longer than 1024 bytes".into());
                }
            }
        }
        Ok(())
    }

    /// Every distinct destination ARN referenced, for destination validation.
    pub fn destination_arns(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.rules.iter().map(|r| r.arn.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Fail with S3's "Unable to validate the following destination configurations" unless
    /// `known(arn)` holds for every destination.
    pub fn validate_destinations(&self, known: impl Fn(&str) -> bool) -> Result<(), EventsError> {
        let unknown: Vec<&str> = self
            .destination_arns()
            .into_iter()
            .filter(|a| !known(a))
            .collect();
        if unknown.is_empty() {
            Ok(())
        } else {
            Err(EventsError::InvalidArgument(format!(
                "Unable to validate the following destination configurations: {}",
                unknown.join(", ")
            )))
        }
    }
}

/// S3 event types accepted in configurations for compatibility that Tidemark never emits.
pub const ACCEPTED_NOT_EMITTED: &[&str] = &[
    "s3:ReducedRedundancyLostObject",
    "s3:ObjectAcl:Put",
    "s3:LifecycleTransition",
    "s3:IntelligentTiering",
    "s3:Replication:OperationFailedReplication",
    "s3:Replication:OperationMissedThreshold",
    "s3:Replication:OperationReplicatedAfterThreshold",
    "s3:Replication:OperationNotTracked",
];

/// Whether `p` is an event name or a `*` glob that matches at least one known event.
pub fn valid_event_pattern(p: &str) -> bool {
    EventName::ALL
        .iter()
        .any(|e| crate::matcher::event_matches(p, *e))
        || ACCEPTED_NOT_EMITTED
            .iter()
            .any(|n| crate::matcher::glob_str(p, n))
}

const KV_PREFIX: &[u8] = b"events/notification/";

fn kv_key(bucket: BucketId) -> Vec<u8> {
    let mut k = KV_PREFIX.to_vec();
    k.extend_from_slice(&bucket.to_bytes());
    k
}

/// Load a bucket's notification configuration (absent = no notifications).
pub fn load(
    r: &(impl Reader + ?Sized),
    bucket: BucketId,
) -> Result<Option<NotificationConfiguration>, EventsError> {
    Ok(r.get(Table::Kv, &kv_key(bucket))?
        .map(|v| decode(&v))
        .transpose()?)
}

/// Store a bucket's notification configuration; an empty configuration deletes it (S3 semantics).
pub fn store(
    txn: &WriteTxn,
    bucket: BucketId,
    cfg: &NotificationConfiguration,
) -> Result<(), EventsError> {
    cfg.validate()?;
    if cfg.rules.is_empty() && !cfg.event_bridge {
        txn.del(Table::Kv, &kv_key(bucket))?;
    } else {
        txn.put(Table::Kv, &kv_key(bucket), &encode(cfg))?;
    }
    Ok(())
}

/// Remove a bucket's notification configuration (bucket purge).
pub fn remove(txn: &WriteTxn, bucket: BucketId) -> Result<(), EventsError> {
    txn.del(Table::Kv, &kv_key(bucket))?;
    Ok(())
}
