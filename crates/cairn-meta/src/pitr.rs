//! Point-in-time queries (DESIGN §7.4).

use crate::keys;
use crate::records::{VersionRecord, decode};
use crate::store::{Flow, Reader};
use crate::{MetaError, Table};
use cairn_core::{BucketId, Ts, VersionId};
use std::ops::Bound;

/// `head_at(key, T)` = newest version `v` with `v.created_at <= T` that was not Superseded or
/// SoftDeleted at or before `T`; a delete marker head means the key is absent at `T`.
pub fn head_at<R: Reader + ?Sized>(
    r: &R,
    bucket: BucketId,
    key: &str,
    at: Ts,
) -> Result<Option<VersionRecord>, MetaError> {
    Ok(visible_at(r, bucket, key, at)?.filter(|v| !v.is_delete_marker()))
}

/// Like [`head_at`] but returns a delete-marker head instead of `None`.
pub fn visible_at<R: Reader + ?Sized>(
    r: &R,
    bucket: BucketId,
    key: &str,
    at: Ts,
) -> Result<Option<VersionRecord>, MetaError> {
    let start = keys::version_key(bucket, key, &VersionId::seek_at(at));
    let end = keys::prefix_successor(&keys::versions_of(bucket, key))
        .expect("bucket key prefix has a successor");
    let mut found = None;
    r.scan(
        Table::Versions,
        Bound::Included(&start),
        Bound::Excluded(&end),
        &mut |_, v| {
            let rec: VersionRecord = decode(v)?;
            if rec.created_at > at || rec.state.hidden_at(at) {
                return Ok(Flow::Continue);
            }
            found = Some(rec);
            Ok(Flow::Stop)
        },
    )?;
    Ok(found)
}

/// Every distinct key with at least one stored version under `prefix`, in order.
pub fn keys_with_history<R: Reader + ?Sized>(
    r: &R,
    bucket: BucketId,
    prefix: &str,
    mut f: impl FnMut(&str) -> Result<bool, MetaError>,
) -> Result<(), MetaError> {
    let start = keys::bucket_key(bucket, prefix);
    r.scan_prefix(Table::Versions, &start, &mut |k, _| {
        let Some((key, _)) = keys::split_version_key(k) else {
            return Ok(Flow::Continue);
        };
        if !f(key)? {
            return Ok(Flow::Stop);
        }
        let next = keys::prefix_successor(&keys::versions_of(bucket, key)).expect("successor");
        Ok(Flow::Seek(next))
    })
}
