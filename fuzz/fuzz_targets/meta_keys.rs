//! Metadata key encoding (DESIGN §4.3): `BucketId ‖ key ‖ 0x00 ‖ VersionId`.
//! Properties: split(version_key) round-trips; the version prefix of one key never matches
//! another key's versions (keys cannot contain NUL, ObjectKey rejects it); `ts_bytes` round-trips
//! and preserves order.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tidemark_core::{BucketId, ObjectKey, Ts, VersionId};
use tidemark_meta::keys::{
    bucket_key, split_latest_key, split_version_key, ts_bytes, ts_from_bytes, version_key,
    versions_of,
};

#[derive(Arbitrary, Debug)]
struct In {
    bucket: u128,
    a: String,
    b: String,
    vid: [u8; 20],
    t1: i128,
    t2: i128,
}

fuzz_target!(|i: In| {
    let b = BucketId(i.bucket);
    let vid = VersionId::from_slice(&i.vid).expect("20 bytes");
    // Only keys the server accepts reach the encoding.
    let (Ok(a), Ok(k2)) = (
        ObjectKey::try_from(i.a.as_str()),
        ObjectKey::try_from(i.b.as_str()),
    ) else {
        return;
    };
    let (a, k2) = (a.as_str(), k2.as_str());

    let vk = version_key(b, a, &vid);
    let (key, v) = split_version_key(&vk).expect("own encoding splits");
    assert_eq!(key, a);
    assert_eq!(v.as_bytes(), vid.as_bytes());
    assert_eq!(split_latest_key(&bucket_key(b, a)), Some(a));

    let other = version_key(b, k2, &vid);
    assert_eq!(
        other.starts_with(&versions_of(b, a)),
        a == k2,
        "versions_of({a:?}) must not cover versions of {k2:?}"
    );

    let (t1, t2) = (Ts(i.t1), Ts(i.t2));
    assert_eq!(ts_from_bytes(&ts_bytes(t1)), t1);
    assert_eq!(
        ts_bytes(t1).cmp(&ts_bytes(t2)),
        t1.cmp(&t2),
        "byte order = time order"
    );
});
