use futures::StreamExt;
use proptest::prelude::*;
use tidemark_blob::*;
use tidemark_core::ChecksumAlgo;
use tokio::io::AsyncWriteExt;

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

async fn put(s: &FsBlobStore, d: &[u8], opts: WriteOpts) -> BlobDigest {
    let mut w = s.begin_write(opts).await.unwrap();
    for c in d.chunks(10_000) {
        w.write_all(c).await.unwrap();
    }
    w.finish().await.unwrap()
}

async fn get(
    s: &FsBlobStore,
    id: &tidemark_core::BlobId,
    r: std::ops::Range<u64>,
    k: Option<&DataKey>,
) -> Vec<u8> {
    let mut rd = s.open(id, r, k).await.unwrap();
    let mut out = Vec::new();
    while let Some(c) = rd.next().await {
        out.extend_from_slice(&c.unwrap());
    }
    out
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[tokio::test]
async fn plain_round_trip_dedup_and_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let s = FsBlobStore::open(dir.path(), true).unwrap();
    let d = data(200_000);
    let dg = put(
        &s,
        &d,
        WriteOpts {
            sha256: true,
            checksum: Some(ChecksumAlgo::Crc32c),
            key: None,
        },
    )
    .await;
    assert_eq!(dg.blob_id.0, *blake3::hash(&d).as_bytes());
    assert_eq!(dg.size, 200_000);
    assert!(!dg.deduped);
    assert_eq!(
        dg.checksum.as_ref().unwrap().1,
        tidemark_blob::hash::checksum(ChecksumAlgo::Crc32c, &d)
    );
    assert!(dg.sha256.is_some());
    let h = dg.blob_id.to_hex();
    assert!(
        dir.path()
            .join("blobs")
            .join(&h[..2])
            .join(&h[2..4])
            .join(&h)
            .exists()
    );
    assert_eq!(get(&s, &dg.blob_id, 0..200_000, None).await, d);
    assert_eq!(get(&s, &dg.blob_id, 5..70_000, None).await, &d[5..70_000]);
    assert_eq!(get(&s, &dg.blob_id, 10..10, None).await, b"");
    assert!(s.open(&dg.blob_id, 0..200_001, None).await.is_err());
    let again = put(&s, &d, WriteOpts::default()).await;
    assert!(again.deduped);
    assert_eq!(again.blob_id, dg.blob_id);
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0,
        "tmp cleaned after dedup"
    );
    assert!(s.verify(&dg.blob_id, None).await.unwrap());
    assert_eq!(s.size(&dg.blob_id).await.unwrap(), 200_000);
    s.delete(&dg.blob_id).await.unwrap();
    assert!(!s.exists(&dg.blob_id).await);
    s.delete(&dg.blob_id).await.unwrap();
}

#[tokio::test]
async fn empty_blob_and_abandoned_writer() {
    let dir = tempfile::tempdir().unwrap();
    let s = FsBlobStore::open(dir.path(), false).unwrap();
    let dg = put(&s, b"", WriteOpts::default()).await;
    assert_eq!(dg.size, 0);
    assert_eq!(hex::encode(dg.md5), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(get(&s, &dg.blob_id, 0..0, None).await, b"");
    {
        let mut w = s.begin_write(WriteOpts::default()).await.unwrap();
        w.write_all(b"partial").await.unwrap();
    }
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0
    );
}

#[tokio::test]
async fn encrypted_round_trip_and_tamper() {
    let dir = tempfile::tempdir().unwrap();
    let s = FsBlobStore::open(dir.path(), true).unwrap();
    let key = DataKey::derive(&[9; 32], "sse-s3");
    let d = data(3 * 64 * 1024 + 123);
    let dg = put(
        &s,
        &d,
        WriteOpts {
            key: Some(key.clone()),
            ..Default::default()
        },
    )
    .await;
    let path = s.enc_path(&dg.blob_id);
    assert!(path.exists());
    assert!(!s.plain_path(&dg.blob_id).exists());
    let raw = std::fs::read(&path).unwrap();
    assert_eq!(raw.len() as u64, encrypted_file_len(d.len() as u64));
    assert!(
        !raw.windows(64).any(|w| w == &d[1000..1064]),
        "plaintext must not appear on disk"
    );
    assert_eq!(get(&s, &dg.blob_id, 0..d.len() as u64, Some(&key)).await, d);
    assert_eq!(
        get(&s, &dg.blob_id, 65_530..131_080, Some(&key)).await,
        &d[65_530..131_080]
    );
    assert!(matches!(
        s.open(&dg.blob_id, 0..1, None).await,
        Err(BlobError::KeyRequired(_))
    ));
    assert_eq!(s.size(&dg.blob_id).await.unwrap(), d.len() as u64);
    assert!(s.verify(&dg.blob_id, Some(&key)).await.unwrap());
    let wrong = DataKey::derive(&[8; 32], "sse-s3");
    let mut rd = s.open(&dg.blob_id, 0..10, Some(&wrong)).await.unwrap();
    assert!(rd.next().await.unwrap().is_err());
    let mut bad = raw.clone();
    bad[100] ^= 0xff;
    std::fs::write(&path, &bad).unwrap();
    assert!(!s.verify(&dg.blob_id, Some(&key)).await.unwrap());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]
    #[test]
    fn ranges_match_slices(len in 0usize..200_000, a in 0usize..200_001, b in 0usize..200_001, enc in any::<bool>()) {
        let rt = rt();
        let dir = tempfile::tempdir().unwrap();
        let s = FsBlobStore::open(dir.path(), false).unwrap();
        let d = data(len);
        let key = enc.then(DataKey::random);
        let dg = rt.block_on(put(&s, &d, WriteOpts { key: key.clone(), ..Default::default() }));
        let (lo, hi) = (a.min(b).min(len), a.max(b).min(len));
        let got = rt.block_on(get(&s, &dg.blob_id, lo as u64..hi as u64, key.as_ref()));
        prop_assert_eq!(&got[..], &d[lo..hi]);
    }
}
