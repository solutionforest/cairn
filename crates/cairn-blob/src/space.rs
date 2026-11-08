//! Free-space guard for the data directory (PRODUCTION-READINESS C8): refuse new blob writes
//! with [`StorageFull`] (HTTP 507) once free space would drop below a configured reserve, so
//! metadata commits, deletes and GC keep working on a nearly full disk.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Default reserve kept free under the data directory: 1 GiB.
pub const DEFAULT_RESERVE: u64 = 1 << 30;

/// Reports the bytes available to unprivileged writers on the filesystem holding `path`.
pub trait SpaceProbe: Send + Sync {
    /// Available bytes.
    fn available(&self, path: &Path) -> io::Result<u64>;
}

/// [`SpaceProbe`] backed by `statvfs(2)` (`f_bavail * f_frsize`), pure Rust via `rustix`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatvfsProbe;

impl SpaceProbe for StatvfsProbe {
    fn available(&self, path: &Path) -> io::Result<u64> {
        let s = rustix::fs::statvfs(path).map_err(io::Error::from)?;
        let unit = if s.f_frsize > 0 {
            s.f_frsize
        } else {
            s.f_bsize
        };
        Ok(s.f_bavail.saturating_mul(unit))
    }
}

/// The write would eat into the free-space reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "insufficient storage: {available} bytes free, {reserve} bytes reserved, {needed} bytes needed"
)]
pub struct StorageFull {
    /// Bytes available when checked.
    pub available: u64,
    /// Configured reserve.
    pub reserve: u64,
    /// Bytes the write declared (0 when unknown).
    pub needed: u64,
}

impl From<StorageFull> for cairn_core::S3Error {
    fn from(_: StorageFull) -> Self {
        use cairn_core::{S3Error, S3ErrorCode};
        let code = S3ErrorCode::parse("InsufficientStorage").unwrap_or(S3ErrorCode::QuotaExceeded);
        S3Error::new(
            code,
            "Insufficient storage space on the server; retry later or free space.",
        )
        .with_header("retry-after", "60")
        .with_header("x-cairn-storage-full", "true")
    }
}

/// Checks free space under one directory against a reserve.
#[derive(Clone)]
pub struct SpaceGuard {
    dir: PathBuf,
    reserve: u64,
    probe: Arc<dyn SpaceProbe>,
}

impl std::fmt::Debug for SpaceGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpaceGuard")
            .field("dir", &self.dir)
            .field("reserve", &self.reserve)
            .finish()
    }
}

impl SpaceGuard {
    /// Guard `dir` with `reserve` bytes kept free, using `statvfs`.
    pub fn new(dir: &Path, reserve: u64) -> SpaceGuard {
        SpaceGuard::with_probe(dir, reserve, Arc::new(StatvfsProbe))
    }

    /// Guard with an explicit probe (tests, other platforms).
    pub fn with_probe(dir: &Path, reserve: u64, probe: Arc<dyn SpaceProbe>) -> SpaceGuard {
        SpaceGuard {
            dir: dir.to_path_buf(),
            reserve,
            probe,
        }
    }

    /// Configured reserve.
    pub fn reserve(&self) -> u64 {
        self.reserve
    }

    /// Bytes currently available.
    pub fn available(&self) -> io::Result<u64> {
        self.probe.available(&self.dir)
    }

    /// `Ok` if a write of `needed` bytes (0 = unknown length) keeps at least `reserve` bytes
    /// free. A failing probe is treated as "has space" (logged) so a broken `statvfs` never takes
    /// writes down; the write itself will still fail with `ENOSPC` if the disk is really full.
    pub fn check(&self, needed: u64) -> Result<(), StorageFull> {
        let available = match self.available() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, dir = %self.dir.display(), "free-space probe failed");
                return Ok(());
            }
        };
        if available < self.reserve.saturating_add(needed) {
            return Err(StorageFull {
                available,
                reserve: self.reserve,
                needed,
            });
        }
        Ok(())
    }
}

/// Whether an I/O error is "no space left on device" / "quota exceeded" (map to [`StorageFull`]).
pub fn is_enospc(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded
    )
}
