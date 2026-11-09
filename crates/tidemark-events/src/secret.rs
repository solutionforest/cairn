//! A string secret that is zeroized on drop and never printed.

use serde::{Deserialize, Deserializer};
use std::fmt;
use zeroize::Zeroizing;

/// A secret value (HMAC key, bearer token, AWS secret key); `Debug`/`Display` print `[REDACTED]`.
/// Deserialize-only on purpose: there is no way to serialise it back out by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap a secret string.
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(Zeroizing::new(s.into()))
    }

    /// Borrow the secret; never log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Secret {
        Secret::new(s)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Secret, D::Error> {
        String::deserialize(d).map(Secret::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?} {s}"), "[REDACTED] [REDACTED]");
        assert_eq!(s.expose(), "hunter2");
    }
}
