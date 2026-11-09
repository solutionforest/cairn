//! Matching events against notification rules (event-name glob + key prefix/suffix filter).

use crate::event::{Event, EventName};
use crate::notification::{FilterRule, NotificationConfiguration, NotificationRule};
use serde::{Deserialize, Serialize};

/// A destination selected for an event: the rule's ARN and its `configurationId`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Destination ARN as written in the configuration.
    pub arn: String,
    /// The rule's `Id` (empty when the rule had none).
    pub configuration_id: String,
}

/// Whether the event-name pattern `pattern` (`*` matches any run of characters) matches `name`.
pub fn event_matches(pattern: &str, name: EventName) -> bool {
    glob(pattern.as_bytes(), name.as_str().as_bytes())
}

/// `*`-glob match over plain strings.
pub fn glob_str(pattern: &str, s: &str) -> bool {
    glob(pattern.as_bytes(), s.as_bytes())
}

fn glob(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, si));
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// Whether `key` satisfies every prefix/suffix rule (an empty filter matches everything).
pub fn key_matches(filter: &[FilterRule], key: &str) -> bool {
    filter.iter().all(|f| match f.name.as_str() {
        "prefix" => key.starts_with(f.value.as_str()),
        "suffix" => key.ends_with(f.value.as_str()),
        _ => false,
    })
}

impl NotificationRule {
    /// Whether this rule selects `event`.
    pub fn matches(&self, event: &Event) -> bool {
        self.events.iter().any(|p| event_matches(p, event.name))
            && key_matches(&self.filter, &event.key)
    }
}

impl NotificationConfiguration {
    /// Destinations for `event`, in rule order, one per matching rule.
    pub fn targets(&self, event: &Event) -> Vec<Target> {
        self.rules
            .iter()
            .filter(|r| r.matches(event))
            .map(|r| Target {
                arn: r.arn.clone(),
                configuration_id: r.id.clone().unwrap_or_default(),
            })
            .collect()
    }

    /// Sink ids selected by `event`, resolving each destination ARN with `resolve`
    /// (unresolvable ARNs are skipped); deduplicated, in first-match order.
    pub fn sink_ids(&self, event: &Event, resolve: impl Fn(&str) -> Option<String>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for t in self.targets(event) {
            if let Some(id) = resolve(&t.arn)
                && !out.contains(&id)
            {
                out.push(id);
            }
        }
        out
    }
}

/// Parse `arn:tidemark:sink::<id>` into the sink id.
pub fn tidemark_sink_id(arn: &str) -> Option<&str> {
    arn.strip_prefix("arn:tidemark:sink::")
        .filter(|s| !s.is_empty())
}
