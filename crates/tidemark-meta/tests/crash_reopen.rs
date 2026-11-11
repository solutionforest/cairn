//! Reopening after a crash must not walk the whole metadata file.
//!
//! A child process (this test binary, re-run with `CRASH_CHILD_DB` set) commits through the
//! store and then aborts without closing it. The parent reopens the file with a redb repair
//! callback: redb calls it only when it has to do a full repair, so it must stay silent.

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tidemark_meta::*;

const KEYS: usize = 2_000;
const CHILD_ENV: &str = "CRASH_CHILD_DB";

fn key(i: usize) -> Vec<u8> {
    format!("key-{i:06}").into_bytes()
}

fn child(db: &str) -> ! {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let store = RedbMetaStore::open(std::path::Path::new(db)).unwrap();
    rt.block_on(async {
        for chunk in (0..KEYS).collect::<Vec<_>>().chunks(100) {
            let chunk = chunk.to_vec();
            store
                .write(move |t| {
                    for &i in &chunk {
                        t.put(Table::Kv, &key(i), &[7u8; 64])?;
                    }
                    Ok::<_, MetaError>(())
                })
                .await
                .unwrap();
        }
    });
    std::process::abort();
}

#[test]
fn reopen_after_abort_needs_no_full_repair() {
    if let Ok(db) = std::env::var(CHILD_ENV) {
        child(&db);
    }
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("meta/tidemark.redb");
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "reopen_after_abort_needs_no_full_repair",
            "--nocapture",
        ])
        .env(CHILD_ENV, &db)
        .status()
        .unwrap();
    assert!(!status.success(), "child must die by abort, got {status}");

    let repaired = Arc::new(AtomicBool::new(false));
    let flag = repaired.clone();
    let raw = redb::Builder::new()
        .set_repair_callback(move |_| flag.store(true, Ordering::SeqCst))
        .open(&db)
        .unwrap();
    assert!(
        !repaired.load(Ordering::SeqCst),
        "reopen after a crash ran a full repair (quick-repair not recorded on commit)"
    );
    drop(raw);

    let store = RedbMetaStore::open(&db).unwrap();
    let r = store.read().unwrap();
    for i in 0..KEYS {
        assert_eq!(
            r.get(Table::Kv, &key(i)).unwrap().as_deref(),
            Some(&[7u8; 64][..]),
            "key {i} lost"
        );
    }
}
