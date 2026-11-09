//! Tiered blob store: hot `FsBlobStore` + cold `DirColdStore` (the object-store fake).

use futures::StreamExt;
use std::time::{Duration, SystemTime};
use tidemark_blob::tiered::{ColdStore, DirColdStore, TierPolicy, TieredBlobStore, cold_name};
use tidemark_blob::{BlobStore, DataKey, FsBlobStore, WriteOpts};
use tidemark_core::BlobId;
use tokio::io::AsyncWriteExt;

struct Env {
    _dir: tempfile::TempDir,
    store: TieredBlobStore<DirColdStore>,
    cold_dir: std::path::PathBuf,
}

fn env(policy: TierPolicy) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let hot = FsBlobStore::open(&dir.path().join("data"), false).unwrap();
    let cold_dir = dir.path().join("cold");
    let cold = DirColdStore::open(&cold_dir).unwrap();
    Env {
        store: TieredBlobStore::new(hot, cold, policy),
        cold_dir,
        _dir: dir,
    }
}

fn size_policy(min: u64) -> TierPolicy {
    TierPolicy {
        min_idle: None,
        min_size: Some(min),
        ..Default::default()
    }
}

fn data(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31) ^ seed).collect()
}

async fn put<C: ColdStore>(s: &TieredBlobStore<C>, d: &[u8], key: Option<DataKey>) -> BlobId {
    let mut w = s
        .begin_write(WriteOpts {
            key,
            ..Default::default()
        })
        .await
        .unwrap();
    w.write_all(d).await.unwrap();
    w.finish().await.unwrap().blob_id
}

async fn read<C: ColdStore>(
    s: &TieredBlobStore<C>,
    id: &BlobId,
    r: std::ops::Range<u64>,
    key: Option<&DataKey>,
) -> Vec<u8> {
    let mut rd = s.open(id, r, key).await.unwrap();
    let mut out = Vec::new();
    while let Some(c) = rd.next().await {
        out.extend_from_slice(&c.unwrap());
    }
    out
}

#[tokio::test]
async fn cold_get_and_range_read_through() {
    let e = env(size_policy(1000));
    let big = data(200_000, 1);
    let small = data(10, 2);
    let b = put(&e.store, &big, None).await;
    let s = put(&e.store, &small, None).await;
    let st = e
        .store
        .tier_tick(SystemTime::now(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(st.moved, 1);
    assert_eq!(st.bytes_moved, big.len() as u64);
    assert!(e.store.is_cold(&b));
    assert!(!e.store.is_cold(&s));
    assert!(!e.store.hot().plain_path(&b).exists());
    assert!(e.cold_dir.join(cold_name(&b, false)).exists());
    assert!(e.store.exists(&b).await);
    assert_eq!(e.store.size(&b).await.unwrap(), big.len() as u64);
    assert_eq!(read(&e.store, &b, 0..big.len() as u64, None).await, big);
    assert_eq!(
        read(&e.store, &b, 70_000..70_100, None).await,
        &big[70_000..70_100]
    );
    assert!(
        e.store
            .open(&b, 0..big.len() as u64 + 1, None)
            .await
            .is_err()
    );
    assert!(e.store.verify(&b, None).await.unwrap());
    assert!(e.store.is_cold(&b), "plain read-through does not rehydrate");
    let again = e
        .store
        .tier_tick(SystemTime::now(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(again.moved, 0);
}

#[tokio::test]
async fn encrypted_cold_blob_range_and_verify() {
    let e = env(size_policy(1));
    let key = DataKey::random();
    let d = data(150_000, 3);
    let id = put(&e.store, &d, Some(key.clone())).await;
    e.store
        .tier_tick(SystemTime::now(), usize::MAX)
        .await
        .unwrap();
    assert!(e.store.is_cold(&id));
    assert!(e.cold_dir.join(cold_name(&id, true)).exists());
    assert_eq!(e.store.size(&id).await.unwrap(), d.len() as u64);
    assert_eq!(
        read(&e.store, &id, 65_000..131_100, Some(&key)).await,
        &d[65_000..131_100]
    );
    assert!(
        e.store.open(&id, 0..10, None).await.is_err(),
        "key required"
    );
    assert!(e.store.verify(&id, Some(&key)).await.unwrap());
    assert!(!e.store.verify(&id, Some(&DataKey::random())).await.unwrap());
}

#[tokio::test]
async fn delete_across_tiers() {
    let e = env(size_policy(1));
    let a = put(&e.store, &data(5000, 4), None).await;
    let b = put(&e.store, &data(5000, 5), None).await;
    e.store.tier_tick(SystemTime::now(), 1).await.unwrap();
    let (cold, hot) = if e.store.is_cold(&a) { (a, b) } else { (b, a) };
    assert!(e.store.is_cold(&cold) && !e.store.is_cold(&hot));
    e.store.delete(&cold).await.unwrap();
    e.store.delete(&hot).await.unwrap();
    for id in [cold, hot] {
        assert!(!e.store.exists(&id).await);
        assert!(!e.store.stub_path(&id).exists());
        assert!(!e.cold_dir.join(cold_name(&id, false)).exists());
        assert!(e.store.open(&id, 0..1, None).await.is_err());
    }
    e.store.delete(&cold).await.unwrap();
}

#[tokio::test]
async fn idle_rule_and_rehydrate_on_read() {
    let policy = TierPolicy {
        min_idle: Some(Duration::from_secs(3600)),
        min_size: None,
        rehydrate_on_read: true,
        touch_interval: Duration::from_secs(60),
    };
    let e = env(policy);
    let d = data(4096, 6);
    let id = put(&e.store, &d, None).await;
    let st = e
        .store
        .tier_tick(SystemTime::now(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(st.moved, 0, "fresh blob stays hot");
    let later = SystemTime::now() + Duration::from_secs(7200);
    assert_eq!(e.store.tier_tick(later, usize::MAX).await.unwrap().moved, 1);
    assert!(e.store.is_cold(&id));
    assert_eq!(read(&e.store, &id, 100..200, None).await, &d[100..200]);
    assert!(!e.store.is_cold(&id), "read rehydrated the blob");
    assert!(e.store.hot().plain_path(&id).exists());
    assert!(!e.store.stub_path(&id).exists());
    assert!(!e.cold_dir.join(cold_name(&id, false)).exists());
    assert!(e.store.verify(&id, None).await.unwrap());
}

#[tokio::test]
async fn rewrite_of_cold_blob_drops_stale_stub() {
    let e = env(TierPolicy {
        min_idle: Some(Duration::from_secs(3600)),
        min_size: None,
        rehydrate_on_read: false,
        touch_interval: Duration::from_secs(60),
    });
    let d = data(3000, 7);
    let id = put(&e.store, &d, None).await;
    let later = SystemTime::now() + Duration::from_secs(7200);
    e.store.tier_tick(later, usize::MAX).await.unwrap();
    assert!(e.store.is_cold(&id));
    assert_eq!(put(&e.store, &d, None).await, id);
    assert!(!e.store.is_cold(&id));
    let st = e
        .store
        .tier_tick(SystemTime::now(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(st.stale_stubs_removed, 1);
    assert!(!e.store.stub_path(&id).exists());
    assert_eq!(read(&e.store, &id, 0..3000, None).await, d);
}

#[tokio::test]
async fn corrupt_cold_copy_fails_verify_and_rehydrate() {
    let e = env(size_policy(1));
    let d = data(2048, 8);
    let id = put(&e.store, &d, None).await;
    e.store
        .tier_tick(SystemTime::now(), usize::MAX)
        .await
        .unwrap();
    let p = e.cold_dir.join(cold_name(&id, false));
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[10] ^= 0xFF;
    std::fs::write(&p, bytes).unwrap();
    assert!(!e.store.verify(&id, None).await.unwrap());
    assert!(e.store.rehydrate(&id).await.is_err());
    assert!(
        e.store.is_cold(&id),
        "failed rehydrate leaves the stub in place"
    );
}

#[test]
fn policy_eligibility() {
    let p = TierPolicy {
        min_idle: Some(Duration::from_secs(10)),
        min_size: Some(100),
        ..Default::default()
    };
    assert!(p.eligible(100, Duration::from_secs(10)));
    assert!(!p.eligible(99, Duration::from_secs(100)));
    assert!(!p.eligible(1000, Duration::from_secs(9)));
    let none = TierPolicy {
        min_idle: None,
        min_size: None,
        ..Default::default()
    };
    assert!(!none.eligible(u64::MAX, Duration::MAX));
}
