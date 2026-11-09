//! Free-space guard (PRODUCTION-READINESS C8) with a fake probe.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tidemark_blob::space::{SpaceGuard, SpaceProbe, StatvfsProbe, StorageFull, is_enospc};

struct Fake(AtomicU64);

impl SpaceProbe for Fake {
    fn available(&self, _: &Path) -> std::io::Result<u64> {
        match self.0.load(Ordering::SeqCst) {
            u64::MAX => Err(std::io::Error::other("probe broke")),
            n => Ok(n),
        }
    }
}

#[test]
fn reserve_is_enforced() {
    let probe = Arc::new(Fake(AtomicU64::new(10_000)));
    let g = SpaceGuard::with_probe(Path::new("/data"), 4_000, probe.clone());
    assert!(g.check(0).is_ok());
    assert!(g.check(6_000).is_ok());
    assert_eq!(
        g.check(6_001),
        Err(StorageFull {
            available: 10_000,
            reserve: 4_000,
            needed: 6_001
        })
    );
    probe.0.store(3_999, Ordering::SeqCst);
    assert!(
        g.check(0).is_err(),
        "unknown-length writes refused below the reserve"
    );
    probe.0.store(u64::MAX, Ordering::SeqCst);
    assert!(
        g.check(1 << 40).is_ok(),
        "a broken probe never blocks writes"
    );
}

#[test]
fn maps_to_507() {
    let e: tidemark_core::S3Error = StorageFull {
        available: 1,
        reserve: 2,
        needed: 3,
    }
    .into();
    assert_eq!(e.http_status(), 507);
    assert!(e.headers.iter().any(|(k, _)| k == "retry-after"));
    assert!(!e.message.contains('1'), "no disk figures leak to clients");
}

#[test]
fn statvfs_probe_reads_tempdir() {
    let d = tempfile::tempdir().unwrap();
    let free = StatvfsProbe.available(d.path()).unwrap();
    assert!(free > 0);
    let g = SpaceGuard::new(d.path(), 0);
    assert!(g.check(1).is_ok());
    assert!(SpaceGuard::new(d.path(), u64::MAX).check(0).is_err());
}

#[test]
fn enospc_detection() {
    assert!(is_enospc(&std::io::Error::from(
        std::io::ErrorKind::StorageFull
    )));
    assert!(is_enospc(&std::io::Error::from_raw_os_error(28)));
    assert!(!is_enospc(&std::io::Error::other("x")));
}
