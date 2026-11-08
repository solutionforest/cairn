//! `cairn scrub`: IO budget with a fake clock, resumable cursor, injected corruption.

mod support3b;

use cairn_core::Ts;
use cairn_engine::cairn_meta::MetaStore;
use cairn_engine::fsck::{DamageKind, FsckOptions, blob_damage};
use cairn_engine::scrub::{Clock, ScrubConfig, Scrubber, last_verified, load_cursor};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use support3b::*;

/// Virtual time: `sleep` advances it instantly and records the total.
#[derive(Default)]
struct FakeClock {
    nanos: AtomicU64,
    slept: AtomicU64,
}

impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::SeqCst))
    }
    fn now(&self) -> Ts {
        Ts(1_800_000_000_000_000_000 + self.nanos.load(Ordering::SeqCst) as i128)
    }
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.nanos.fetch_add(d.as_nanos() as u64, Ordering::SeqCst);
        self.slept.fetch_add(d.as_nanos() as u64, Ordering::SeqCst);
        Box::pin(async {})
    }
}

#[tokio::test]
async fn budget_cursor_and_corruption() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    bucket(&e, "bkt", true).await;
    let mut blobs = Vec::new();
    for i in 0..5u8 {
        let v = put(&e, "bkt", &format!("k{i}"), &data(10_000, i)).await;
        blobs.push(v.version.blobs()[0]);
    }
    let victim = blobs[3];
    let p = e.blobs().plain_path(&victim);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[100] ^= 1;
    std::fs::write(&p, bytes).unwrap();

    let clock = Arc::new(FakeClock::default());
    let cfg = ScrubConfig {
        bytes_per_sec: 10_000,
        max_concurrent: 2,
        batch: 2,
        reverify_after: Duration::from_secs(3600),
    };
    let s = Scrubber::with_clock(e.clone(), cfg.clone(), clock.clone());
    let first = s.step().await.unwrap();
    assert_eq!(first.blobs_verified, 2);
    assert!(!first.pass_completed);
    let cur = load_cursor(&e.meta().read().unwrap()).unwrap();
    assert!(cur.after.is_some(), "cursor persisted after a partial pass");

    // A fresh scrubber (as after a restart) resumes from the cursor.
    let s2 = Scrubber::with_clock(e.clone(), cfg, clock.clone());
    let rest = s2.run_pass().await.unwrap();
    assert!(rest.pass_completed);
    assert_eq!(
        first.blobs_verified + rest.blobs_verified,
        5,
        "each blob once"
    );
    assert_eq!(rest.corrupt.len() + first.corrupt.len(), 1);
    let slept = Duration::from_nanos(clock.slept.load(Ordering::SeqCst));
    assert!(
        slept >= Duration::from_millis(4_900) && slept <= Duration::from_millis(5_100),
        "50 000 bytes at 10 000 B/s ≈ 5 s of budget waits, got {slept:?}"
    );
    let rd = e.meta().read().unwrap();
    let dmg = blob_damage(&rd, &victim).unwrap().unwrap();
    assert_eq!(dmg.kind, DamageKind::Corrupt);
    assert_eq!(dmg.source, "scrub");
    assert!(last_verified(&rd, &victim).unwrap().is_none());
    assert!(last_verified(&rd, &blobs[0]).unwrap().is_some());
    assert_eq!(load_cursor(&rd).unwrap().passes, 1);
    drop(rd);

    let again = s2.run_pass().await.unwrap();
    assert_eq!(
        again.skipped_recent, 4,
        "recently verified blobs are skipped"
    );
    assert_eq!(again.corrupt, vec![victim], "damaged blobs are re-checked");

    let report = e.fsck(FsckOptions::default()).await.unwrap();
    assert_eq!(report.damaged.len(), 1, "scrub findings surface in fsck");
    assert_eq!(report.damaged[0].blob, victim);
}

#[tokio::test]
async fn missing_blob_and_unthrottled_mode() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    bucket(&e, "bkt", false).await;
    let v = put(&e, "bkt", "gone", b"bytes").await;
    put(&e, "bkt", "kept", b"other bytes").await;
    let blob = v.version.blobs()[0];
    std::fs::remove_file(e.blobs().plain_path(&blob)).unwrap();
    let clock = Arc::new(FakeClock::default());
    let s = Scrubber::with_clock(
        e.clone(),
        ScrubConfig {
            bytes_per_sec: 0,
            ..Default::default()
        },
        clock.clone(),
    );
    let r = s.run_pass().await.unwrap();
    assert_eq!(r.missing, vec![blob]);
    assert_eq!(r.blobs_verified, 1);
    assert_eq!(clock.slept.load(Ordering::SeqCst), 0);
    let rd = e.meta().read().unwrap();
    assert_eq!(
        blob_damage(&rd, &blob).unwrap().unwrap().kind,
        DamageKind::Missing
    );
}
