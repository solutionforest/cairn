//! Prefix/delimiter listing over `latest` and `versions` with common-prefix skipping.

use crate::keys;
use crate::pitr;
use crate::records::{VersionRecord, decode};
use crate::store::{Flow, Reader};
use crate::{MetaError, Table};
use std::ops::Bound;
use tidemark_core::{BucketId, Ts, VersionId};

/// One listing entry.
#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    /// An object (or, for version listings, a version / delete marker).
    Object {
        /// The version record.
        version: Box<VersionRecord>,
        /// Whether it is the key's current head.
        is_latest: bool,
    },
    /// A rolled-up common prefix.
    Prefix(String),
}

impl Entry {
    fn marker_key(&self) -> &str {
        match self {
            Entry::Object { version, .. } => &version.key,
            Entry::Prefix(p) => p,
        }
    }
}

/// A page of results.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Page {
    /// Entries in key order.
    pub entries: Vec<Entry>,
    /// More entries exist.
    pub truncated: bool,
    /// Key (or prefix) of the last entry when truncated.
    pub next_key: Option<String>,
    /// Version id of the last entry when truncated (version listings).
    pub next_version: Option<VersionId>,
}

/// Listing parameters.
#[derive(Debug, Clone, Default)]
pub struct ListParams<'a> {
    /// Key prefix filter.
    pub prefix: &'a str,
    /// Delimiter for rolling up common prefixes.
    pub delimiter: Option<&'a str>,
    /// Exclusive start key (V1 marker / V2 start-after or continuation).
    pub after: Option<&'a str>,
    /// Max entries (objects + prefixes); 0 returns an empty, possibly truncated page.
    pub max: usize,
}

fn common_prefix<'k>(key: &'k str, prefix: &str, delimiter: Option<&str>) -> Option<&'k str> {
    let d = delimiter.filter(|d| !d.is_empty())?;
    let rest = key.get(prefix.len()..)?;
    rest.find(d).map(|i| &key[..prefix.len() + i + d.len()])
}

fn bounds(bucket: BucketId, prefix: &str, after: Option<&[u8]>) -> (Vec<u8>, bool, Vec<u8>) {
    let pfx = keys::bucket_key(bucket, prefix);
    let end = keys::prefix_successor(&pfx).expect("bucket prefix has successor");
    match after {
        Some(a) if a >= pfx.as_slice() => (a.to_vec(), false, end),
        _ => (pfx, true, end),
    }
}

struct Collector<'a> {
    p: &'a ListParams<'a>,
    page: Page,
}

impl Collector<'_> {
    /// Returns false when the page is full (and marks truncation).
    fn push(&mut self, e: Entry) -> bool {
        if self.page.entries.len() >= self.p.max {
            self.page.truncated = true;
            if let Some(last) = self.page.entries.last() {
                self.page.next_key = Some(last.marker_key().to_string());
                if let Entry::Object { version, .. } = last {
                    self.page.next_version = Some(version.version_id);
                }
            }
            return false;
        }
        self.page.entries.push(e);
        true
    }

    fn skip_prefix(&self, cp: &str) -> bool {
        self.p.after.is_some_and(|a| cp <= a)
    }
}

/// List current objects (ListObjects / ListObjectsV2). Delete-marker heads are skipped.
pub fn list_latest<R: Reader + ?Sized>(
    r: &R,
    bucket: BucketId,
    p: &ListParams<'_>,
) -> Result<Page, MetaError> {
    let after = p.after.map(|a| keys::bucket_key(bucket, a));
    let (start, incl, end) = bounds(bucket, p.prefix, after.as_deref());
    let mut c = Collector {
        p,
        page: Page::default(),
    };
    let sb = if incl {
        Bound::Included(start.as_slice())
    } else {
        Bound::Excluded(start.as_slice())
    };
    r.scan(Table::Latest, sb, Bound::Excluded(&end), &mut |k, v| {
        let Some(key) = keys::split_latest_key(k) else {
            return Ok(Flow::Continue);
        };
        if let Some(cp) = common_prefix(key, p.prefix, p.delimiter) {
            let next = keys::prefix_successor(&keys::bucket_key(bucket, cp)).expect("successor");
            if !c.skip_prefix(cp) && !c.push(Entry::Prefix(cp.to_string())) {
                return Ok(Flow::Stop);
            }
            return Ok(Flow::Seek(next));
        }
        let rec: VersionRecord = decode(v)?;
        if rec.is_delete_marker() {
            return Ok(Flow::Continue);
        }
        if !c.push(Entry::Object {
            version: Box::new(rec),
            is_latest: true,
        }) {
            return Ok(Flow::Stop);
        }
        Ok(Flow::Continue)
    })?;
    Ok(c.page)
}

/// List objects as they were at `at` (time travel). Common prefixes are emitted only if some key
/// beneath them was visible at `at`.
pub fn list_as_of<R: Reader + ?Sized>(
    r: &R,
    bucket: BucketId,
    p: &ListParams<'_>,
    at: Ts,
) -> Result<Page, MetaError> {
    let after = p
        .after
        .map(|a| keys::prefix_successor(&keys::versions_of(bucket, a)).expect("successor"));
    let (start, _, end) = bounds(bucket, p.prefix, after.as_deref());
    let mut c = Collector {
        p,
        page: Page::default(),
    };
    let mut err = None;
    r.scan(
        Table::Versions,
        Bound::Included(&start),
        Bound::Excluded(&end),
        &mut |k, _| {
            let Some((key, _)) = keys::split_version_key(k) else {
                return Ok(Flow::Continue);
            };
            if let Some(cp) = common_prefix(key, p.prefix, p.delimiter) {
                let next =
                    keys::prefix_successor(&keys::bucket_key(bucket, cp)).expect("successor");
                if !c.skip_prefix(cp) {
                    let mut visible = false;
                    pitr::keys_with_history(r, bucket, cp, |k2| {
                        visible = pitr::head_at(r, bucket, k2, at)?.is_some();
                        Ok(!visible)
                    })?;
                    if visible && !c.push(Entry::Prefix(cp.to_string())) {
                        return Ok(Flow::Stop);
                    }
                }
                return Ok(Flow::Seek(next));
            }
            let next = keys::prefix_successor(&keys::versions_of(bucket, key)).expect("successor");
            match pitr::head_at(r, bucket, key, at) {
                Ok(Some(v)) => {
                    if !c.push(Entry::Object {
                        version: Box::new(v),
                        is_latest: true,
                    }) {
                        return Ok(Flow::Stop);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    err = Some(e);
                    return Ok(Flow::Stop);
                }
            }
            Ok(Flow::Seek(next))
        },
    )?;
    if let Some(e) = err {
        return Err(e);
    }
    Ok(c.page)
}

/// Version listing parameters.
#[derive(Debug, Clone, Default)]
pub struct VersionParams<'a> {
    /// Prefix/delimiter/max; `after` is the key marker.
    pub list: ListParams<'a>,
    /// Version-id marker (resolved; requires a key marker).
    pub version_after: Option<VersionId>,
    /// Include Superseded/SoftDeleted versions (`x-tidemark-include-trash`).
    pub include_trash: bool,
}

/// List versions and delete markers (ListObjectVersions), newest first within a key.
pub fn list_versions<R: Reader + ?Sized>(
    r: &R,
    bucket: BucketId,
    vp: &VersionParams<'_>,
) -> Result<Page, MetaError> {
    let p = &vp.list;
    let after = match (p.after, vp.version_after) {
        (Some(k), Some(v)) => Some((keys::version_key(bucket, k, &v), false)),
        (Some(k), None) => Some((
            keys::prefix_successor(&keys::versions_of(bucket, k)).expect("successor"),
            true,
        )),
        _ => None,
    };
    let (start, incl, end) = bounds(bucket, p.prefix, after.as_ref().map(|(a, _)| a.as_slice()));
    let incl = incl || after.as_ref().is_some_and(|(_, i)| *i);
    let mut c = Collector {
        p,
        page: Page::default(),
    };
    let mut cur_key: Option<(String, Option<VersionId>)> = None;
    let sb = if incl {
        Bound::Included(start.as_slice())
    } else {
        Bound::Excluded(start.as_slice())
    };
    r.scan(Table::Versions, sb, Bound::Excluded(&end), &mut |k, v| {
        let Some((key, _)) = keys::split_version_key(k) else {
            return Ok(Flow::Continue);
        };
        if let Some(cp) = common_prefix(key, p.prefix, p.delimiter) {
            let next = keys::prefix_successor(&keys::bucket_key(bucket, cp)).expect("successor");
            if !c.skip_prefix(cp) {
                let mut visible = vp.include_trash;
                if !visible {
                    r.scan_prefix(Table::Latest, &keys::bucket_key(bucket, cp), &mut |_, _| {
                        visible = true;
                        Ok(Flow::Stop)
                    })?;
                }
                if visible && !c.push(Entry::Prefix(cp.to_string())) {
                    return Ok(Flow::Stop);
                }
            }
            return Ok(Flow::Seek(next));
        }
        let rec: VersionRecord = decode(v)?;
        if !vp.include_trash && !rec.is_live() {
            return Ok(Flow::Continue);
        }
        if cur_key.as_ref().is_none_or(|(k, _)| k != key) {
            let head = r.get(Table::Latest, &keys::bucket_key(bucket, key))?;
            let head_vid = head
                .map(|h| decode::<VersionRecord>(&h))
                .transpose()?
                .map(|h| h.version_id);
            cur_key = Some((key.to_string(), head_vid));
        }
        let is_latest = cur_key.as_ref().and_then(|(_, h)| *h) == Some(rec.version_id);
        if !c.push(Entry::Object {
            version: Box::new(rec),
            is_latest,
        }) {
            return Ok(Flow::Stop);
        }
        Ok(Flow::Continue)
    })?;
    Ok(c.page)
}
