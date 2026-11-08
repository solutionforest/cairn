//! Listing: ListObjects (v1/v2, with time travel) and ListObjectVersions.

use crate::types::*;
use crate::util::display_vid;
use crate::{CairnEngine, resolve_bucket};
use cairn_core::{S3Error, S3ErrorCode, S3Result, VersionId};
use cairn_meta::ReadExt;
use cairn_meta::list::{
    Entry, ListParams, Page, VersionParams, list_as_of, list_latest, list_versions,
};

/// Hard cap on one listing page (S3 semantics).
pub const MAX_LIST_KEYS: usize = 1000;

fn into_res(page: Page) -> ListRes {
    let mut res = ListRes {
        truncated: page.truncated,
        next_key: page.next_key,
        ..Default::default()
    };
    let mut last_vid = None;
    for e in page.entries {
        match e {
            Entry::Prefix(p) => res.prefixes.push(p),
            Entry::Object { version, is_latest } => {
                let vid = display_vid(&version);
                last_vid = Some(vid.clone());
                res.objects.push(ListedVersion {
                    version: *version,
                    version_id: vid,
                    is_latest,
                });
            }
        }
    }
    if res.truncated && page.next_version.is_some() {
        res.next_version = last_vid;
    }
    res
}

impl CairnEngine {
    /// ListObjects / ListObjectsV2: current objects (or as of `req.as_of`), keys strictly after
    /// `req.after`.
    pub fn list_objects(&self, bucket: &str, req: &ListReq) -> S3Result<ListRes> {
        let r = self.read()?;
        let b = resolve_bucket(&r, bucket)?;
        let max = req.max.min(MAX_LIST_KEYS);
        if max == 0 {
            return Ok(ListRes::default());
        }
        let p = ListParams {
            prefix: &req.prefix,
            delimiter: req.delimiter.as_deref(),
            after: req.after.as_deref(),
            max,
        };
        let page = match req.as_of {
            Some(at) => list_as_of(&r, b.id, &p, at)?,
            None => list_latest(&r, b.id, &p)?,
        };
        Ok(into_res(page))
    }

    /// ListObjectVersions (versions and delete markers, newest first per key).
    pub fn list_object_versions(&self, bucket: &str, req: &ListVersionsReq) -> S3Result<ListRes> {
        let r = self.read()?;
        let b = resolve_bucket(&r, bucket)?;
        let max = req.list.max.min(MAX_LIST_KEYS);
        if max == 0 {
            return Ok(ListRes::default());
        }
        let version_after = match (&req.list.after, req.version_marker.as_deref()) {
            (Some(_), None) | (None, _) => None,
            (Some(k), Some("null")) => Some(
                r.null_version(b.id, k, true)?
                    .map(|v| v.version_id)
                    .ok_or_else(|| {
                        S3Error::new(S3ErrorCode::InvalidArgument, "Invalid version id specified")
                    })?,
            ),
            (Some(_), Some(v)) => Some(v.parse::<VersionId>().map_err(|_| {
                S3Error::new(S3ErrorCode::InvalidArgument, "Invalid version id specified")
            })?),
        };
        let vp = VersionParams {
            list: ListParams {
                prefix: &req.list.prefix,
                delimiter: req.list.delimiter.as_deref(),
                after: req.list.after.as_deref(),
                max,
            },
            version_after,
            include_trash: req.include_trash,
        };
        let page = list_versions(&r, b.id, &vp)?;
        Ok(into_res(page))
    }
}
