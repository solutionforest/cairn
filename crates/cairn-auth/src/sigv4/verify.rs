//! SigV4 request verification (header and query auth) and header signing, for Cairn's own
//! HTTP endpoints (STS, admin API). S3 requests are verified by `s3s`.

use super::{ALGORITHM, hmac, percent_decode, signing_key, uri_encode};
use crate::secret::SecretString;
use crate::types::Ts;
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;

/// Maximum allowed difference between the request time and the server clock.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(15 * 60);

/// SHA-256 of the empty string, hex.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Why a request failed SigV4 verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigV4Error {
    /// No `Authorization` header or `X-Amz-Signature` query parameter.
    #[error("request is not signed")]
    Missing,
    /// Malformed authorization data.
    #[error("malformed authorization: {0}")]
    Malformed(&'static str),
    /// Request time outside the allowed skew.
    #[error("request time too skewed")]
    Skewed,
    /// Presigned request past its expiry.
    #[error("request has expired")]
    Expired,
    /// Signature does not match.
    #[error("signature does not match")]
    Mismatch,
}

/// The parts of an HTTP request that SigV4 covers.
#[derive(Debug, Clone, Copy)]
pub struct HttpParts<'a> {
    /// Method, upper case.
    pub method: &'a str,
    /// Path as received (percent-encoded).
    pub raw_path: &'a str,
    /// Query string as received (without `?`), may be empty.
    pub raw_query: &'a str,
    /// Headers with lower-case names, in arrival order (duplicates allowed).
    pub headers: &'a [(String, String)],
    /// Hex SHA-256 of the request body as received.
    pub body_sha256: &'a str,
}

/// Parsed SigV4 authorization (before verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Auth {
    /// Access key id from the credential scope.
    pub access_key_id: String,
    /// `YYYYMMDD` from the scope.
    pub scope_date: String,
    /// Region from the scope.
    pub region: String,
    /// Service from the scope.
    pub service: String,
    /// Signed header names (lower case, as listed).
    pub signed_headers: Vec<String>,
    /// Hex signature.
    pub signature: String,
    /// `x-amz-date` / `X-Amz-Date`.
    pub amz_date: String,
    /// `X-Amz-Expires` for presigned requests.
    pub expires: Option<u64>,
    /// `x-amz-security-token` / `X-Amz-Security-Token`, if present.
    pub security_token: Option<String>,
}

fn header<'h>(h: &'h [(String, String)], name: &str) -> Option<&'h str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn decode_query(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let d = |s: &str| String::from_utf8_lossy(&percent_decode(s)).into_owned();
            (d(k), d(v))
        })
        .collect()
}

fn parse_scope(cred: &str) -> Result<(String, String, String, String), SigV4Error> {
    let parts: Vec<&str> = cred.rsplitn(5, '/').collect();
    match parts.as_slice() {
        [term, service, region, date, akid]
            if *term == "aws4_request" && date.len() == 8 && !akid.is_empty() =>
        {
            Ok((
                akid.to_string(),
                date.to_string(),
                region.to_string(),
                service.to_string(),
            ))
        }
        _ => Err(SigV4Error::Malformed("credential scope")),
    }
}

/// Extract SigV4 authorization from the `Authorization` header or the query string.
pub fn parse(req: &HttpParts<'_>) -> Result<SigV4Auth, SigV4Error> {
    if let Some(auth) = header(req.headers, "authorization") {
        let rest = auth
            .strip_prefix(ALGORITHM)
            .ok_or(SigV4Error::Malformed("algorithm"))?;
        let (mut cred, mut signed, mut sig) = (None, None, None);
        for item in rest.split(',') {
            let item = item.trim();
            if let Some(v) = item.strip_prefix("Credential=") {
                cred = Some(v);
            } else if let Some(v) = item.strip_prefix("SignedHeaders=") {
                signed = Some(v);
            } else if let Some(v) = item.strip_prefix("Signature=") {
                sig = Some(v);
            }
        }
        let (Some(cred), Some(signed), Some(sig)) = (cred, signed, sig) else {
            return Err(SigV4Error::Malformed("authorization header"));
        };
        let (access_key_id, scope_date, region, service) = parse_scope(cred)?;
        let amz_date = header(req.headers, "x-amz-date")
            .ok_or(SigV4Error::Malformed("missing x-amz-date"))?
            .to_string();
        return Ok(SigV4Auth {
            access_key_id,
            scope_date,
            region,
            service,
            signed_headers: signed.split(';').map(str::to_string).collect(),
            signature: sig.to_string(),
            amz_date,
            expires: None,
            security_token: header(req.headers, "x-amz-security-token").map(str::to_string),
        });
    }
    let q = decode_query(req.raw_query);
    let get = |n: &str| q.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    let Some(sig) = get("X-Amz-Signature") else {
        return Err(SigV4Error::Missing);
    };
    if get("X-Amz-Algorithm") != Some(ALGORITHM) {
        return Err(SigV4Error::Malformed("algorithm"));
    }
    let cred = get("X-Amz-Credential").ok_or(SigV4Error::Malformed("credential"))?;
    let (access_key_id, scope_date, region, service) = parse_scope(cred)?;
    let expires = get("X-Amz-Expires")
        .and_then(|e| e.parse::<u64>().ok())
        .ok_or(SigV4Error::Malformed("expires"))?;
    Ok(SigV4Auth {
        access_key_id,
        scope_date,
        region,
        service,
        signed_headers: get("X-Amz-SignedHeaders")
            .ok_or(SigV4Error::Malformed("signed headers"))?
            .split(';')
            .map(str::to_string)
            .collect(),
        signature: sig.to_string(),
        amz_date: get("X-Amz-Date")
            .ok_or(SigV4Error::Malformed("date"))?
            .to_string(),
        expires: Some(expires),
        security_token: get("X-Amz-Security-Token").map(str::to_string),
    })
}

/// Parse an ISO 8601 basic UTC timestamp (`YYYYMMDDTHHMMSSZ`).
pub fn parse_amz_date(s: &str) -> Result<Ts, SigV4Error> {
    jiff::fmt::strtime::parse("%Y%m%dT%H%M%SZ", s)
        .and_then(|t| t.to_datetime())
        .and_then(|dt| dt.to_zoned(jiff::tz::TimeZone::UTC))
        .map(|z| Ts::from_jiff(z.timestamp()))
        .map_err(|_| SigV4Error::Malformed("date"))
}

/// Canonical request for `req` covering `signed_headers` with payload line `payload`.
/// `drop_signature` removes `X-Amz-Signature` from the query (query auth).
pub fn canonical_request(
    req: &HttpParts<'_>,
    signed_headers: &[String],
    payload: &str,
    drop_signature: bool,
) -> String {
    let path = if req.raw_path.is_empty() {
        "/".to_string()
    } else {
        uri_encode(&percent_decode(req.raw_path), true)
    };
    let mut q: Vec<(String, String)> = req
        .raw_query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (
                uri_encode(&percent_decode(k), false),
                uri_encode(&percent_decode(v), false),
            )
        })
        .filter(|(k, _)| !(drop_signature && k == "X-Amz-Signature"))
        .collect();
    q.sort();
    let query = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut headers = String::new();
    for name in signed_headers {
        let vals: Vec<String> = req
            .headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        headers.push_str(&format!("{name}:{}\n", vals.join(",")));
    }
    format!(
        "{}\n{path}\n{query}\n{headers}\n{}\n{payload}",
        req.method,
        signed_headers.join(";")
    )
}

fn string_to_sign(amz_date: &str, scope: &str, canonical: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    )
}

/// Verify `auth` (from [`parse`]) against `req` with the caller's secret at time `now`.
/// Checks: `host` is signed, scope date matches, clock skew ±15 min (header auth) or
/// expiry ≤ 7 days and not passed (query auth), and the signature (constant time).
pub fn verify(
    req: &HttpParts<'_>,
    auth: &SigV4Auth,
    secret: &SecretString,
    now: Ts,
) -> Result<(), SigV4Error> {
    if !auth.signed_headers.iter().any(|h| h == "host") {
        return Err(SigV4Error::Malformed("host must be signed"));
    }
    if auth.signed_headers.iter().any(|h| h == "authorization") {
        return Err(SigV4Error::Malformed("authorization cannot be signed"));
    }
    if !auth.amz_date.starts_with(&auth.scope_date) {
        return Err(SigV4Error::Malformed("scope date"));
    }
    let t = parse_amz_date(&auth.amz_date)?;
    let skew = MAX_CLOCK_SKEW.as_nanos() as i128;
    match auth.expires {
        None => {
            if (now.0 - t.0).abs() > skew {
                return Err(SigV4Error::Skewed);
            }
        }
        Some(e) => {
            if e == 0 || e > super::MAX_PRESIGN_EXPIRY.as_secs() {
                return Err(SigV4Error::Malformed("expires"));
            }
            if t.0 - now.0 > skew {
                return Err(SigV4Error::Skewed);
            }
            if now > t.plus(Duration::from_secs(e)) {
                return Err(SigV4Error::Expired);
            }
        }
    }
    let scope = format!(
        "{}/{}/{}/aws4_request",
        auth.scope_date, auth.region, auth.service
    );
    let key = signing_key(
        secret.expose(),
        &auth.scope_date,
        &auth.region,
        &auth.service,
    );
    let presigned = auth.expires.is_some();
    let mut payloads = vec![req.body_sha256];
    if presigned && req.body_sha256 == EMPTY_SHA256 {
        payloads.push("UNSIGNED-PAYLOAD");
    }
    let presented = auth.signature.as_bytes();
    let mut ok = subtle::Choice::from(0u8);
    for p in payloads {
        let cr = canonical_request(req, &auth.signed_headers, p, presigned);
        let sig = hex::encode(hmac(
            &key,
            string_to_sign(&auth.amz_date, &scope, &cr).as_bytes(),
        ));
        ok |= sig.as_bytes().ct_eq(presented);
    }
    if bool::from(ok) {
        Ok(())
    } else {
        Err(SigV4Error::Mismatch)
    }
}

/// Hex SHA-256 of `body`.
pub fn sha256_hex(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Sign a request with header auth. `headers` must include `host` (lower-case names); returns
/// the headers to add: `x-amz-date`, `x-amz-content-sha256`, optional
/// `x-amz-security-token`, and `authorization`. Every header in `headers` is signed.
#[allow(clippy::too_many_arguments)]
pub fn sign_headers(
    method: &str,
    raw_path: &str,
    raw_query: &str,
    headers: &[(String, String)],
    body: &[u8],
    access_key_id: &str,
    secret: &SecretString,
    session_token: Option<&str>,
    now: Ts,
    region: &str,
    service: &str,
) -> Vec<(String, String)> {
    let amz_date = now.to_jiff().strftime("%Y%m%dT%H%M%SZ").to_string();
    let date = amz_date[..8].to_string();
    let body_sha = sha256_hex(body);
    let mut add = vec![
        ("x-amz-date".to_string(), amz_date.clone()),
        ("x-amz-content-sha256".to_string(), body_sha.clone()),
    ];
    if let Some(t) = session_token {
        add.push(("x-amz-security-token".into(), t.to_string()));
    }
    let mut all: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .chain(add.iter().cloned())
        .collect();
    all.sort_by(|a, b| a.0.cmp(&b.0));
    let mut names: Vec<String> = all.iter().map(|(k, _)| k.clone()).collect();
    names.dedup();
    let parts = HttpParts {
        method,
        raw_path,
        raw_query,
        headers: &all,
        body_sha256: &body_sha,
    };
    let cr = canonical_request(&parts, &names, &body_sha, false);
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let key = signing_key(secret.expose(), &date, region, service);
    let sig = hex::encode(hmac(
        &key,
        string_to_sign(&amz_date, &scope, &cr).as_bytes(),
    ));
    add.push((
        "authorization".into(),
        format!(
            "{ALGORITHM} Credential={access_key_id}/{scope}, SignedHeaders={}, Signature={sig}",
            names.join(";")
        ),
    ));
    add
}
