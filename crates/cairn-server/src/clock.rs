//! Wall clock used by background workers, replaceable in tests.

use cairn_core::Ts;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

/// Source of "now" for the GC and lifecycle workers.
pub trait Clock: Send + Sync {
    /// Current time.
    fn now(&self) -> Ts;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Ts {
        Ts::now()
    }
}

/// A clock offset from the system clock by an adjustable amount (tests jump forward in time
/// while request timestamps stay real).
#[derive(Debug, Default)]
pub struct OffsetClock(AtomicI64);

impl OffsetClock {
    /// No offset.
    pub fn new() -> OffsetClock {
        OffsetClock::default()
    }

    /// Move the clock forward by `d`.
    pub fn advance(&self, d: Duration) {
        self.0.fetch_add(d.as_secs() as i64, Ordering::SeqCst);
    }
}

impl Clock for OffsetClock {
    fn now(&self) -> Ts {
        Ts::now().plus(Duration::from_secs(
            self.0.load(Ordering::SeqCst).max(0) as u64
        ))
    }
}
