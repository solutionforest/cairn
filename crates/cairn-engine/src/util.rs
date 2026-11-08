//! Shared helpers: conditions, ranges, checksums, version-id strings.

use crate::types::*;
use base64::Engine as _;
use cairn_core::{ChecksumAlgo, S3Error, S3ErrorCode, S3Result, Ts, VersionId};
use cairn_meta::{ReadExt, VersionRecord, Versioning};

pub(crate) fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
}

/// Strip quotes / weak prefix from an ETag as clients send it.
pub(crate) fn norm_etag(s: &str) -> &str {
    let s = s.trim();
    let s = s.strip_prefix("W/").unwrap_or(s);
    s.trim_matches('"')
}

fn etag_list_matches(list: &str, etag: &str) -> bool {
    list.split(',').any(|e| {
        let e = e.trim();
        e == "*" || norm_etag(e) == etag
    })
}

/// Evaluate GET/HEAD preconditions per RFC 7232 / S3 rules.
pub(crate) fn check_read_conditions(
    c: &ReadConditions,
    etag: &str,
    last_modified: Ts,
) -> S3Result<()> {
    let lm = last_modified.secs();
    if let Some(m) = &c.if_match {
        if !etag_list_matches(m, etag) {
            return Err(S3Error::code(S3ErrorCode::PreconditionFailed));
        }
    } else if let Some(t) = c.if_unmodified_since
        && lm > t.secs()
    {
        return Err(S3Error::code(S3ErrorCode::PreconditionFailed));
    }
    if let Some(n) = &c.if_none_match {
        if etag_list_matches(n, etag) {
            return Err(not_modified(etag));
        }
    } else if let Some(t) = c.if_modified_since
        && lm <= t.secs()
    {
        return Err(not_modified(etag));
    }
    Ok(())
}

fn not_modified(etag: &str) -> S3Error {
    S3Error::code(S3ErrorCode::NotModified).with_header("etag", format!("\"{etag}\""))
}

/// Copy-source preconditions: every failure is 412.
pub(crate) fn check_copy_source_conditions(
    c: &ReadConditions,
    etag: &str,
    last_modified: Ts,
) -> S3Result<()> {
    check_read_conditions(c, etag, last_modified).map_err(|e| {
        if e.code == S3ErrorCode::NotModified {
            S3Error::code(S3ErrorCode::PreconditionFailed)
        } else {
            e
        }
    })
}

/// Evaluate PUT/Complete preconditions against the current head.
pub(crate) fn check_write_conditions(
    c: &WriteConditions,
    head: Option<&VersionRecord>,
) -> S3Result<()> {
    let cur = head.and_then(|v| v.body()).map(|b| b.etag.as_str());
    if let Some(m) = &c.if_match {
        match cur {
            None => return Err(S3Error::code(S3ErrorCode::NoSuchKey)),
            Some(e) if !etag_list_matches(m, e) => {
                return Err(S3Error::code(S3ErrorCode::PreconditionFailed));
            }
            _ => {}
        }
    }
    if let Some(n) = &c.if_none_match
        && let Some(e) = cur
        && etag_list_matches(n, e)
    {
        return Err(S3Error::code(S3ErrorCode::PreconditionFailed));
    }
    Ok(())
}

/// Resolve a range request against an object size into `start..end`.
pub(crate) fn resolve_range(r: RangeSpec, size: u64) -> S3Result<(u64, u64)> {
    let bad = || {
        S3Error::code(S3ErrorCode::InvalidRange)
            .with_header("content-range", format!("bytes */{size}"))
    };
    match r {
        RangeSpec::Int { first, last } => {
            if first >= size {
                return Err(bad());
            }
            let end = last.map_or(size, |l| l.saturating_add(1).min(size));
            if end <= first {
                return Err(bad());
            }
            Ok((first, end))
        }
        RangeSpec::Suffix(n) => {
            if n == 0 || size == 0 {
                return Err(bad());
            }
            Ok((size.saturating_sub(n), size))
        }
    }
}

/// The version id S3 should report for a version, given the bucket's versioning.
pub(crate) fn s3_version_id(v: &VersionRecord, versioning: Versioning) -> Option<String> {
    match versioning {
        Versioning::Off => None,
        _ => Some(display_vid(v)),
    }
}

/// `null` or hex.
pub(crate) fn display_vid(v: &VersionRecord) -> String {
    if v.is_null {
        "null".to_string()
    } else {
        v.version_id.to_string()
    }
}

/// Resolve a client-supplied version id to a Live version.
pub(crate) fn resolve_version<R: ReadExt + ?Sized>(
    r: &R,
    bucket: cairn_core::BucketId,
    key: &str,
    vid: &str,
) -> S3Result<VersionRecord> {
    let found = if vid == "null" {
        r.null_version(bucket, key, false)?
    } else {
        let id: VersionId = vid.parse()?;
        r.version(bucket, key, &id)?.filter(|v| v.is_live())
    };
    found.ok_or_else(|| S3Error::code(S3ErrorCode::NoSuchVersion).with_resource(key))
}

pub(crate) fn verify_checksum(
    algo: ChecksumAlgo,
    computed: &[u8],
    expected_b64: &str,
) -> S3Result<()> {
    match unb64(expected_b64) {
        Some(e) if e == computed => Ok(()),
        Some(_) => Err(S3Error::new(
            S3ErrorCode::BadDigest,
            format!(
                "The {} you specified did not match the calculated checksum.",
                algo.as_str()
            ),
        )),
        None => Err(S3Error::new(
            S3ErrorCode::BadDigest,
            format!(
                "Value for x-amz-checksum-{} header is invalid.",
                algo.as_str().to_lowercase()
            ),
        )),
    }
}

/// Validate a tag set (S3 limits).
pub(crate) fn validate_tags(
    tags: &std::collections::BTreeMap<String, String>,
    max: usize,
) -> S3Result<()> {
    if tags.len() > max {
        return Err(S3Error::new(
            S3ErrorCode::InvalidTag,
            "Object tags cannot be greater than 10",
        ));
    }
    for (k, v) in tags {
        if k.is_empty() || k.chars().count() > 128 || v.chars().count() > 256 {
            return Err(S3Error::new(
                S3ErrorCode::InvalidTag,
                "The TagKey/TagValue you have provided is invalid",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(
            resolve_range(
                RangeSpec::Int {
                    first: 0,
                    last: Some(9)
                },
                100
            )
            .unwrap(),
            (0, 10)
        );
        assert_eq!(
            resolve_range(
                RangeSpec::Int {
                    first: 90,
                    last: None
                },
                100
            )
            .unwrap(),
            (90, 100)
        );
        assert_eq!(
            resolve_range(
                RangeSpec::Int {
                    first: 90,
                    last: Some(500)
                },
                100
            )
            .unwrap(),
            (90, 100)
        );
        assert_eq!(
            resolve_range(RangeSpec::Suffix(10), 100).unwrap(),
            (90, 100)
        );
        assert_eq!(
            resolve_range(RangeSpec::Suffix(1000), 100).unwrap(),
            (0, 100)
        );
        let e = resolve_range(
            RangeSpec::Int {
                first: 100,
                last: None,
            },
            100,
        )
        .unwrap_err();
        assert_eq!(e.code, S3ErrorCode::InvalidRange);
        assert!(
            e.headers
                .iter()
                .any(|(k, v)| k == "content-range" && v == "bytes */100")
        );
        assert!(resolve_range(RangeSpec::Suffix(5), 0).is_err());
    }

    #[test]
    fn conditions() {
        let t = Ts::from_secs(1000);
        let ok = |c: ReadConditions| check_read_conditions(&c, "abc", t).map_err(|e| e.code);
        assert_eq!(
            ok(ReadConditions {
                if_match: Some("\"abc\"".into()),
                ..Default::default()
            }),
            Ok(())
        );
        assert_eq!(
            ok(ReadConditions {
                if_match: Some("\"x\"".into()),
                ..Default::default()
            }),
            Err(S3ErrorCode::PreconditionFailed)
        );
        assert_eq!(
            ok(ReadConditions {
                if_none_match: Some("*".into()),
                ..Default::default()
            }),
            Err(S3ErrorCode::NotModified)
        );
        assert_eq!(
            ok(ReadConditions {
                if_modified_since: Some(Ts::from_secs(1000)),
                ..Default::default()
            }),
            Err(S3ErrorCode::NotModified)
        );
        assert_eq!(
            ok(ReadConditions {
                if_modified_since: Some(Ts::from_secs(999)),
                ..Default::default()
            }),
            Ok(())
        );
        assert_eq!(
            ok(ReadConditions {
                if_unmodified_since: Some(Ts::from_secs(999)),
                ..Default::default()
            }),
            Err(S3ErrorCode::PreconditionFailed)
        );
        assert_eq!(
            ok(ReadConditions {
                if_match: Some("abc".into()),
                if_unmodified_since: Some(Ts::from_secs(1)),
                ..Default::default()
            }),
            Ok(())
        );
    }
}
