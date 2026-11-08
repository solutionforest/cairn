//! Big-endian key layouts (DESIGN §4.3).

use cairn_core::{BlobId, BucketId, Ts, VersionId};

/// Separator between key bytes and version id in `versions`.
pub const KEY_SEP: u8 = 0x00;

/// Order-preserving encoding of a signed timestamp (sign bit flipped).
pub fn ts_bytes(t: Ts) -> [u8; 16] {
    ((t.0 as u128) ^ (1u128 << 127)).to_be_bytes()
}

/// Inverse of [`ts_bytes`].
pub fn ts_from_bytes(b: &[u8]) -> Ts {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    Ts((u128::from_be_bytes(a) ^ (1u128 << 127)) as i128)
}

/// `BucketId ‖ key`.
pub fn bucket_key(b: BucketId, key: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + key.len());
    v.extend_from_slice(&b.to_bytes());
    v.extend_from_slice(key.as_bytes());
    v
}

/// `BucketId ‖ key ‖ 0x00` (prefix of all versions of `key`).
pub fn versions_of(b: BucketId, key: &str) -> Vec<u8> {
    let mut v = bucket_key(b, key);
    v.push(KEY_SEP);
    v
}

/// `BucketId ‖ key ‖ 0x00 ‖ VersionId`.
pub fn version_key(b: BucketId, key: &str, vid: &VersionId) -> Vec<u8> {
    let mut v = versions_of(b, key);
    v.extend_from_slice(vid.as_bytes());
    v
}

/// Split a `versions` table key into (object key, version id). The bucket prefix is skipped.
pub fn split_version_key(k: &[u8]) -> Option<(&str, VersionId)> {
    if k.len() < 16 + 1 + 20 {
        return None;
    }
    let vid = VersionId::from_slice(&k[k.len() - 20..])?;
    let key = std::str::from_utf8(&k[16..k.len() - 21]).ok()?;
    Some((key, vid))
}

/// Object key of a `latest` table key.
pub fn split_latest_key(k: &[u8]) -> Option<&str> {
    std::str::from_utf8(k.get(16..)?).ok()
}

/// `BucketId ‖ upload_id`.
pub fn upload_key(b: BucketId, upload_id: &str) -> Vec<u8> {
    bucket_key(b, upload_id)
}

/// `BucketId ‖ key ‖ 0x00 ‖ upload_id`.
pub fn upload_by_key(b: BucketId, key: &str, upload_id: &str) -> Vec<u8> {
    let mut v = versions_of(b, key);
    v.extend_from_slice(upload_id.as_bytes());
    v
}

/// Split an `uploads_by_key` key into (object key, upload id). Upload ids contain no NUL.
pub fn split_upload_by_key(k: &[u8]) -> Option<(&str, &str)> {
    let rest = k.get(16..)?;
    let pos = rest.iter().rposition(|&c| c == KEY_SEP)?;
    Some((
        std::str::from_utf8(&rest[..pos]).ok()?,
        std::str::from_utf8(&rest[pos + 1..]).ok()?,
    ))
}

/// `expires_at ‖ BucketId ‖ key ‖ 0x00 ‖ VersionId`.
pub fn trash_key(expires: Ts, b: BucketId, key: &str, vid: &VersionId) -> Vec<u8> {
    let mut v = ts_bytes(expires).to_vec();
    v.extend(version_key(b, key, vid));
    v
}

/// Split a `trash_idx` key into (expires_at, bucket, object key, version id).
pub fn split_trash_key(k: &[u8]) -> Option<(Ts, BucketId, String, VersionId)> {
    if k.len() < 16 + 16 + 21 {
        return None;
    }
    let ts = ts_from_bytes(&k[..16]);
    let rest = &k[16..];
    let mut bid = [0u8; 16];
    bid.copy_from_slice(&rest[..16]);
    let (key, vid) = split_version_key(rest)?;
    Some((ts, BucketId::from_bytes(bid), key.to_string(), vid))
}

/// `unref_at ‖ BlobId` (blob GC index).
pub fn blob_gc_key(at: Ts, blob: &BlobId) -> Vec<u8> {
    let mut v = ts_bytes(at).to_vec();
    v.extend_from_slice(blob.as_bytes());
    v
}

/// `BucketId ‖ config_seq`.
pub fn bucket_history_key(b: BucketId, seq: u64) -> Vec<u8> {
    let mut v = b.to_bytes().to_vec();
    v.extend_from_slice(&seq.to_be_bytes());
    v
}

/// Smallest byte string greater than every string with prefix `p` (None if `p` is all 0xFF).
pub fn prefix_successor(p: &[u8]) -> Option<Vec<u8>> {
    let mut v = p.to_vec();
    while let Some(last) = v.pop() {
        if last != 0xFF {
            v.push(last + 1);
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn version_key_round_trip() {
        let b = BucketId(42);
        let vid = VersionId::new(Ts(7));
        let k = version_key(b, "dir/file", &vid);
        assert_eq!(split_version_key(&k), Some(("dir/file", vid)));
        let t = trash_key(Ts(-5), b, "x", &vid);
        assert_eq!(split_trash_key(&t), Some((Ts(-5), b, "x".to_string(), vid)));
        let u = upload_by_key(b, "a/b", "018f-up");
        assert_eq!(split_upload_by_key(&u), Some(("a/b", "018f-up")));
    }

    #[test]
    fn successor() {
        assert_eq!(prefix_successor(b"ab"), Some(b"ac".to_vec()));
        assert_eq!(prefix_successor(b"a\xff"), Some(b"b".to_vec()));
        assert_eq!(prefix_successor(b"\xff\xff"), None);
    }

    proptest! {
        #[test]
        fn ts_order_preserved(a in any::<i64>(), b in any::<i64>()) {
            let (a, b) = (Ts(a as i128 * 1000), Ts(b as i128 * 1000));
            prop_assert_eq!(a.cmp(&b), ts_bytes(a).cmp(&ts_bytes(b)));
            prop_assert_eq!(ts_from_bytes(&ts_bytes(a)), a);
        }

        #[test]
        fn versions_sort_by_key_then_newest(k1 in "[a-c/]{1,4}", k2 in "[a-c/]{1,4}", t1 in 0i64..1000, t2 in 0i64..1000) {
            let b = BucketId(1);
            let v1 = VersionId::new(Ts(t1 as i128));
            let v2 = VersionId::new(Ts(t2 as i128));
            let a = version_key(b, &k1, &v1);
            let c = version_key(b, &k2, &v2);
            if k1 != k2 {
                prop_assert_eq!(k1.as_bytes().cmp(k2.as_bytes()), a.cmp(&c));
            } else if t1 != t2 {
                prop_assert_eq!(t2.cmp(&t1), a.cmp(&c));
            }
        }
    }
}
