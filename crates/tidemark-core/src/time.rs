//! Timestamps as signed unix nanoseconds.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unix timestamp in nanoseconds (UTC).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Ts(pub i128);

impl Ts {
    /// The unix epoch.
    pub const EPOCH: Ts = Ts(0);

    /// Current wall-clock time.
    pub fn now() -> Ts {
        Ts(jiff::Timestamp::now().as_nanosecond())
    }

    /// Construct from unix seconds.
    pub fn from_secs(s: i64) -> Ts {
        Ts(i128::from(s) * 1_000_000_000)
    }

    /// Unix nanoseconds.
    pub fn nanos(self) -> i128 {
        self.0
    }

    /// Whole unix seconds (floor).
    pub fn secs(self) -> i64 {
        self.0.div_euclid(1_000_000_000) as i64
    }

    /// Add a duration (saturating).
    pub fn plus(self, d: std::time::Duration) -> Ts {
        Ts(self.0.saturating_add(d.as_nanos() as i128))
    }

    /// Subtract a duration (saturating).
    pub fn minus(self, d: std::time::Duration) -> Ts {
        Ts(self.0.saturating_sub(d.as_nanos() as i128))
    }

    /// Convert to a `jiff::Timestamp` (clamped to jiff's range).
    pub fn to_jiff(self) -> jiff::Timestamp {
        jiff::Timestamp::from_nanosecond(self.0).unwrap_or(if self.0 < 0 {
            jiff::Timestamp::MIN
        } else {
            jiff::Timestamp::MAX
        })
    }

    /// Convert to `SystemTime`.
    pub fn to_system_time(self) -> std::time::SystemTime {
        let base = std::time::UNIX_EPOCH;
        if self.0 >= 0 {
            base + std::time::Duration::from_nanos(self.0.min(u64::MAX as i128) as u64)
        } else {
            base - std::time::Duration::from_nanos((-self.0).min(u64::MAX as i128) as u64)
        }
    }

    /// Convert from `SystemTime`.
    pub fn from_system_time(t: std::time::SystemTime) -> Ts {
        match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => Ts(d.as_nanos() as i128),
            Err(e) => Ts(-(e.duration().as_nanos() as i128)),
        }
    }

    /// Parse RFC 3339 (`2026-11-08T10:00:00Z`) or a bare integer of unix nanoseconds.
    pub fn parse(s: &str) -> Option<Ts> {
        let s = s.trim();
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
            return s.parse::<i128>().ok().map(Ts);
        }
        s.parse::<jiff::Timestamp>()
            .ok()
            .map(|t| Ts(t.as_nanosecond()))
    }

    /// RFC 3339 rendering with nanosecond precision.
    pub fn to_rfc3339(self) -> String {
        self.to_jiff().to_string()
    }
}

impl fmt::Display for Ts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_forms() {
        assert_eq!(Ts::parse("1000"), Some(Ts(1000)));
        let t = Ts::parse("2026-11-08T00:00:00Z").unwrap();
        assert_eq!(t.secs(), 1_794_096_000);
        assert_eq!(Ts::parse(&t.to_rfc3339()), Some(t));
        assert_eq!(Ts::parse("garbage"), None);
    }

    #[test]
    fn system_time_round_trip() {
        let t = Ts(1_700_000_000_123_456_789);
        assert_eq!(Ts::from_system_time(t.to_system_time()), t);
    }
}
