//! Small shared types. TODO(agent-a): move to cairn-core once it exports them.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Account id used in every Cairn ARN (single-account server).
pub const ACCOUNT_ID: &str = "000000000000";

/// Stable principal identifier: `root`, `user:<name>`, `role:<name>/<session>`, `anonymous`.
// TODO(agent-a): move to cairn-core
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PrincipalId(pub String);

impl PrincipalId {
    /// The root principal id.
    pub fn root() -> Self {
        Self("root".into())
    }
    /// The anonymous principal id.
    pub fn anonymous() -> Self {
        Self("anonymous".into())
    }
    /// A user principal id.
    pub fn user(name: &str) -> Self {
        Self(format!("user:{name}"))
    }
    /// An assumed-role session principal id.
    pub fn role_session(role: &str, session: &str) -> Self {
        Self(format!("role:{role}/{session}"))
    }
    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Timestamp in unix nanoseconds.
// TODO(agent-a): move to cairn-core
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ts(pub i128);

impl Ts {
    /// Current wall-clock time.
    pub fn now() -> Self {
        Self(jiff::Timestamp::now().as_nanosecond())
    }
    /// From whole unix seconds.
    pub fn from_secs(s: i64) -> Self {
        Self(i128::from(s) * 1_000_000_000)
    }
    /// Whole unix seconds (floored).
    pub fn as_secs(self) -> i64 {
        self.0.div_euclid(1_000_000_000) as i64
    }
    /// Add a duration (saturating).
    pub fn plus(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.as_nanos() as i128))
    }
    /// Convert to a jiff timestamp (clamped to jiff's range).
    pub fn to_jiff(self) -> jiff::Timestamp {
        jiff::Timestamp::from_nanosecond(self.0).unwrap_or(if self.0 < 0 {
            jiff::Timestamp::MIN
        } else {
            jiff::Timestamp::MAX
        })
    }
    /// From a jiff timestamp.
    pub fn from_jiff(t: jiff::Timestamp) -> Self {
        Self(t.as_nanosecond())
    }
    /// RFC 3339 rendering in UTC with second precision.
    pub fn to_rfc3339(self) -> String {
        Ts::from_secs(self.as_secs()).to_jiff().to_string()
    }
}

/// Source of time, injectable for tests.
pub trait Clock: Send + Sync {
    /// Current time.
    fn now(&self) -> Ts;
}

/// The system wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Ts {
        Ts::now()
    }
}

/// A manually advanced clock for tests.
#[derive(Debug)]
pub struct ManualClock(std::sync::atomic::AtomicI64);

impl ManualClock {
    /// Start at the given unix seconds.
    pub fn new(secs: i64) -> Self {
        Self(std::sync::atomic::AtomicI64::new(secs))
    }
    /// Move forward by a duration (second resolution).
    pub fn advance(&self, d: Duration) {
        self.0
            .fetch_add(d.as_secs() as i64, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Ts {
        Ts::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}
