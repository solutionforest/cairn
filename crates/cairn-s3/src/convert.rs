//! Conversions between `s3s` DTOs and engine types.

use bytes::Bytes;
use cairn_core::{ChecksumAlgo, S3ErrorCode as Code, Ts};
use cairn_engine::cairn_meta::ObjectBody;
use cairn_engine::{Body, ChecksumInput, ObjectMeta, ReadConditions, WriteConditions};
use futures::StreamExt;
use http::HeaderMap;
use s3s::dto::{ETag, ETagCondition, StreamingBlob, Timestamp, TimestampFormat};
use s3s::{S3Error, S3ErrorCode};
use std::collections::BTreeMap;

/// Request id placed in request extensions by the HTTP layer.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Convert an engine error into an `s3s` error (code, message, status, extra headers).
pub fn to_s3s(e: cairn_core::S3Error, req_id: Option<&RequestId>) -> S3Error {
    let code: S3ErrorCode = e
        .code
        .as_str()
        .parse()
        .unwrap_or(S3ErrorCode::InternalError);
    if e.code == Code::InternalError {
        tracing::error!(error = %e.message, "internal error");
    }
    let mut out = S3Error::with_message(code, e.message);
    if let Ok(s) = http::StatusCode::from_u16(e.code.http_status()) {
        out.set_status_code(s);
    }
    if let Some(id) = req_id {
        out.set_request_id(id.0.clone());
    }
    if !e.headers.is_empty() {
        let mut h = HeaderMap::new();
        if e.code != Code::NotModified {
            h.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/xml"),
            );
        }
        for (k, v) in e.headers {
            if let (Ok(k), Ok(v)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(&v),
            ) {
                h.append(k, v);
            }
        }
        out.set_headers(h);
    }
    out
}

/// Shorthand for an engine-style error.
pub fn err(code: Code, msg: impl Into<String>) -> cairn_core::S3Error {
    cairn_core::S3Error::new(code, msg)
}

/// `s3s` timestamp from an engine timestamp.
pub fn ts_out(t: Ts) -> Timestamp {
    Timestamp::from(t.to_system_time())
}

/// Engine timestamp from an `s3s` timestamp (second precision is all HTTP dates carry).
pub fn ts_in(t: &Timestamp) -> Option<Ts> {
    let mut buf = Vec::new();
    t.format(TimestampFormat::EpochSeconds, &mut buf).ok()?;
    let s = std::str::from_utf8(&buf).ok()?;
    let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 = secs.parse().ok()?;
    let mut nanos = 0i128;
    if !frac.is_empty() {
        let f = format!("{frac:0<9}");
        nanos = f.get(..9)?.parse().ok()?;
    }
    Some(Ts(i128::from(secs) * 1_000_000_000 + nanos))
}

/// Strong ETag DTO from a stored (unquoted) ETag.
pub fn etag_out(e: &str) -> ETag {
    ETag::Strong(e.to_string())
}

/// ETag condition → string the engine understands.
pub fn cond_str(c: &ETagCondition) -> String {
    match c {
        ETagCondition::Any => "*".to_string(),
        ETagCondition::ETag(e) => format!("\"{}\"", e.value()),
    }
}

/// Read preconditions from GET/HEAD-style inputs.
pub fn read_conditions(
    if_match: Option<&ETagCondition>,
    if_none_match: Option<&ETagCondition>,
    if_modified_since: Option<&Timestamp>,
    if_unmodified_since: Option<&Timestamp>,
) -> ReadConditions {
    ReadConditions {
        if_match: if_match.map(cond_str),
        if_none_match: if_none_match.map(cond_str),
        if_modified_since: if_modified_since.and_then(ts_in),
        if_unmodified_since: if_unmodified_since.and_then(ts_in),
    }
}

/// Write preconditions (PUT / Complete / Copy destination).
pub fn write_conditions(
    if_match: Option<&ETagCondition>,
    if_none_match: Option<&ETagCondition>,
) -> WriteConditions {
    WriteConditions {
        if_match: if_match.map(cond_str),
        if_none_match: if_none_match.map(cond_str),
    }
}

/// Adapt an `s3s` request body to an engine body.
pub fn body_in(b: Option<StreamingBlob>) -> Body {
    match b {
        None => cairn_engine::body_from_bytes(Bytes::new()),
        Some(s) => Box::pin(s.map(|r| {
            r.map_err(|e| {
                if e.is::<s3s::BodySizeLimitExceeded>() {
                    cairn_core::S3Error::code(Code::EntityTooLarge)
                } else {
                    err(
                        Code::IncompleteBody,
                        format!("error reading request body: {e}"),
                    )
                }
            })
        })),
    }
}

/// Parse an `x-amz-tagging` header (URL query encoded).
pub fn parse_tagging(h: Option<&str>) -> Result<BTreeMap<String, String>, cairn_core::S3Error> {
    let mut out = BTreeMap::new();
    let Some(h) = h.filter(|s| !s.is_empty()) else {
        return Ok(out);
    };
    for (k, v) in url::form_urlencoded::parse(h.as_bytes()) {
        if out.insert(k.into_owned(), v.into_owned()).is_some() {
            return Err(err(
                Code::InvalidTag,
                "Cannot provide multiple Tags with the same key",
            ));
        }
    }
    Ok(out)
}

/// Tag set DTO → map (duplicate keys rejected).
pub fn tags_in(set: &[s3s::dto::Tag]) -> Result<BTreeMap<String, String>, cairn_core::S3Error> {
    let mut out = BTreeMap::new();
    for t in set {
        let k = t.key.clone().unwrap_or_default();
        if out.insert(k, t.value.clone().unwrap_or_default()).is_some() {
            return Err(err(
                Code::InvalidTag,
                "Cannot provide multiple Tags with the same key",
            ));
        }
    }
    Ok(out)
}

/// Map → tag set DTO.
pub fn tags_out(m: &BTreeMap<String, String>) -> Vec<s3s::dto::Tag> {
    m.iter()
        .map(|(k, v)| s3s::dto::Tag {
            key: Some(k.clone()),
            value: Some(v.clone()),
        })
        .collect()
}

/// Validate and normalise user metadata (`x-amz-meta-*`).
pub fn user_meta(
    m: Option<&s3s::dto::Metadata>,
    max: usize,
) -> Result<BTreeMap<String, String>, cairn_core::S3Error> {
    let mut out = BTreeMap::new();
    let mut size = 0;
    for (k, v) in m.into_iter().flatten() {
        size += k.len() + v.len();
        out.insert(k.to_ascii_lowercase(), v.clone());
    }
    if size > max {
        return Err(err(
            Code::MetadataTooLarge,
            format!(
                "Your metadata headers exceed the maximum allowed metadata size of {max} bytes"
            ),
        ));
    }
    Ok(out)
}

/// Storage class accepted on writes (single class; `STANDARD` is the default).
pub fn storage_class_in(
    s: Option<&s3s::dto::StorageClass>,
) -> Result<Option<String>, cairn_core::S3Error> {
    const KNOWN: &[&str] = &[
        "STANDARD",
        "REDUCED_REDUNDANCY",
        "STANDARD_IA",
        "ONEZONE_IA",
        "INTELLIGENT_TIERING",
        "GLACIER",
        "DEEP_ARCHIVE",
        "GLACIER_IR",
        "OUTPOSTS",
        "SNOW",
        "EXPRESS_ONEZONE",
    ];
    match s.map(|s| s.as_str()) {
        None | Some("STANDARD") => Ok(None),
        Some(c) if KNOWN.contains(&c) => Ok(Some(c.to_string())),
        Some(_) => Err(cairn_core::S3Error::code(Code::InvalidStorageClass)),
    }
}

/// Stored storage class reported on listings.
pub fn storage_class_name(b: &ObjectBody) -> String {
    b.storage_class
        .clone()
        .unwrap_or_else(|| "STANDARD".to_string())
}

/// `aws-chunked` describes the request framing, not the object: S3 strips it before storing
/// `Content-Encoding`, so `gzip, aws-chunked` is stored as `gzip` and a lone `aws-chunked` as
/// nothing.
fn stored_encoding(e: &str) -> Option<String> {
    let kept: Vec<&str> = e
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("aws-chunked"))
        .collect();
    (!kept.is_empty()).then(|| kept.join(", "))
}

/// Collect HTTP metadata fields from a request.
#[allow(clippy::too_many_arguments)]
pub fn object_meta(
    content_type: Option<&String>,
    cache_control: Option<&String>,
    content_disposition: Option<&String>,
    content_encoding: Option<&String>,
    content_language: Option<&String>,
    expires: Option<String>,
    metadata: Option<&s3s::dto::Metadata>,
    storage_class: Option<&s3s::dto::StorageClass>,
    website_redirect: Option<&String>,
    max_meta: usize,
) -> Result<ObjectMeta, cairn_core::S3Error> {
    Ok(ObjectMeta {
        content_type: content_type.cloned(),
        cache_control: cache_control.cloned(),
        content_disposition: content_disposition.cloned(),
        content_encoding: content_encoding.and_then(|e| stored_encoding(e)),
        content_language: content_language.cloned(),
        expires,
        user_metadata: user_meta(metadata, max_meta)?,
        storage_class: storage_class_in(storage_class)?,
        website_redirect: website_redirect.cloned(),
    })
}

/// Checksum algorithm from the `s3s` enum.
pub fn algo_in(
    a: Option<&s3s::dto::ChecksumAlgorithm>,
) -> Result<Option<ChecksumAlgo>, cairn_core::S3Error> {
    match a {
        None => Ok(None),
        Some(a) => ChecksumAlgo::parse(a.as_str()).map(Some).ok_or_else(|| {
            err(
                Code::InvalidRequest,
                format!("Checksum algorithm {} is not supported", a.as_str()),
            )
        }),
    }
}

/// Explicit checksum values sent as headers.
pub struct ChecksumHeaders<'a> {
    /// `x-amz-sdk-checksum-algorithm`.
    pub algorithm: Option<&'a s3s::dto::ChecksumAlgorithm>,
    /// CRC32.
    pub crc32: Option<&'a String>,
    /// CRC32C.
    pub crc32c: Option<&'a String>,
    /// CRC64NVME.
    pub crc64nvme: Option<&'a String>,
    /// SHA1.
    pub sha1: Option<&'a String>,
    /// SHA256.
    pub sha256: Option<&'a String>,
    /// Any algorithm Cairn does not implement (SHA512, MD5, XXHASH*).
    pub unsupported: bool,
}

/// Build the engine checksum request from headers and (for aws-chunked uploads) trailers.
pub fn checksum_in(
    h: ChecksumHeaders<'_>,
    headers: &HeaderMap,
    trailers: Option<s3s::TrailingHeaders>,
) -> Result<ChecksumInput, cairn_core::S3Error> {
    if h.unsupported {
        return Err(err(
            Code::NotImplemented,
            "Only CRC32, CRC32C, CRC64NVME, SHA1 and SHA256 checksums are supported",
        ));
    }
    let given = [
        (ChecksumAlgo::Crc32, h.crc32),
        (ChecksumAlgo::Crc32c, h.crc32c),
        (ChecksumAlgo::Crc64Nvme, h.crc64nvme),
        (ChecksumAlgo::Sha1, h.sha1),
        (ChecksumAlgo::Sha256, h.sha256),
    ];
    let mut vals = given.iter().filter_map(|(a, v)| v.map(|v| (*a, v.clone())));
    let first = vals.next();
    if vals.next().is_some() {
        return Err(err(
            Code::InvalidRequest,
            "Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.",
        ));
    }
    if let Some((a, v)) = first {
        return Ok(ChecksumInput::Value(a, v));
    }
    if let Some(t) = headers.get("x-amz-trailer").and_then(|v| v.to_str().ok()) {
        let name = t.trim().to_ascii_lowercase();
        if let Some(algo) = name
            .strip_prefix("x-amz-checksum-")
            .and_then(ChecksumAlgo::parse)
        {
            let Some(handle) = trailers else {
                return Ok(ChecksumInput::Compute(algo));
            };
            return Ok(ChecksumInput::Trailer(
                algo,
                Box::new(move || {
                    handle.take().and_then(|m| {
                        m.get(&name)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string)
                    })
                }),
            ));
        }
    }
    Ok(algo_in(h.algorithm)?.map_or(ChecksumInput::None, ChecksumInput::Compute))
}

/// Percent-encode for `encoding-type=url` (RFC 3986 unreserved and `/` kept).
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Parse `x-cairn-as-of` (RFC 3339 or unix nanoseconds).
pub fn as_of(headers: &HeaderMap) -> Result<Option<Ts>, cairn_core::S3Error> {
    match headers.get("x-cairn-as-of") {
        None => Ok(None),
        Some(v) => v
            .to_str()
            .ok()
            .and_then(Ts::parse)
            .map(Some)
            .ok_or_else(|| {
                err(
                    Code::InvalidArgument,
                    "x-cairn-as-of must be an RFC 3339 timestamp or unix nanoseconds",
                )
            }),
    }
}

/// Parse an `x-amz-copy-source-range` header (`bytes=first-last`).
pub fn copy_range(s: &str) -> Result<(u64, u64), cairn_core::S3Error> {
    let bad = || {
        err(
            Code::InvalidArgument,
            "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
        )
    };
    let r = s.trim().strip_prefix("bytes=").ok_or_else(bad)?;
    let (a, b) = r.split_once('-').ok_or_else(bad)?;
    let first: u64 = a.trim().parse().map_err(|_| bad())?;
    let last: u64 = b.trim().parse().map_err(|_| bad())?;
    if last < first {
        return Err(bad());
    }
    Ok((first, last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagging_and_ranges() {
        let t = parse_tagging(Some("a=1&b=two%20words")).unwrap();
        assert_eq!(t.get("b").map(String::as_str), Some("two words"));
        assert!(parse_tagging(Some("a=1&a=2")).is_err());
        assert_eq!(copy_range("bytes=0-9").unwrap(), (0, 9));
        assert!(copy_range("bytes=9-0").is_err());
        assert!(copy_range("0-9").is_err());
        assert_eq!(url_encode("a b/ü"), "a%20b/%C3%BC");
    }

    #[test]
    fn timestamps_round_trip() {
        let t = Ts::from_secs(1_700_000_000);
        assert_eq!(ts_in(&ts_out(t)), Some(t));
    }

    #[test]
    fn error_mapping_keeps_status_and_headers() {
        let e =
            cairn_core::S3Error::code(Code::NoSuchKey).with_header("x-amz-delete-marker", "true");
        let s = to_s3s(e, Some(&RequestId("abc".into())));
        assert_eq!(*s.code(), S3ErrorCode::NoSuchKey);
        assert_eq!(s.status_code(), Some(http::StatusCode::NOT_FOUND));
        assert_eq!(s.request_id(), Some("abc"));
        assert_eq!(s.headers().unwrap()["x-amz-delete-marker"], "true");
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::stored_encoding;

    #[test]
    fn aws_chunked_is_not_stored() {
        assert_eq!(
            stored_encoding("gzip, aws-chunked").as_deref(),
            Some("gzip")
        );
        assert_eq!(stored_encoding("aws-chunked"), None);
        assert_eq!(stored_encoding("AWS-CHUNKED,gzip").as_deref(), Some("gzip"));
        assert_eq!(stored_encoding("br").as_deref(), Some("br"));
    }
}
