//! SigV4 query-string signing (presigned URLs), header signing and request verification.

mod verify;
pub use verify::{
    EMPTY_SHA256, HttpParts, MAX_CLOCK_SKEW, SigV4Auth, SigV4Error, canonical_request, parse,
    parse_amz_date, sha256_hex, sign_headers, verify,
};

use crate::error::PresignError;
use crate::secret::SecretString;
use crate::store::Credential;
use crate::types::Ts;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use url::Url;

/// Maximum presigned URL lifetime (7 days).
pub const MAX_PRESIGN_EXPIRY: Duration = Duration::from_secs(7 * 24 * 3600);

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const AUTH_PARAMS: &[&str] = &[
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-expires",
    "x-amz-signedheaders",
    "x-amz-signature",
    "x-amz-security-token",
];

/// RFC 3986 encoding as SigV4 requires: unreserved `A-Za-z0-9-_.~` kept, everything else
/// `%XX` (upper-case hex); `/` kept only when `keep_slash`.
pub fn uri_encode(input: &[u8], keep_slash: bool) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for &b in input {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && b == b'/')
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(crate) fn percent_decode(s: &str) -> Vec<u8> {
    fn hexval(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 3 <= b.len()
            && let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// SigV4 signing key: HMAC chain over date, region, service, "aws4_request".
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, service.as_bytes());
    hmac(&k, b"aws4_request")
}

/// Path-style object URL `endpoint/bucket/key` with the key correctly encoded.
pub fn object_url(endpoint: &Url, bucket: &str, key: &str) -> Url {
    let mut u = endpoint.clone();
    let base = u.path().trim_end_matches('/').to_string();
    u.set_path(&format!(
        "{base}/{}/{}",
        uri_encode(bucket.as_bytes(), false),
        uri_encode(key.as_bytes(), true)
    ));
    u.set_query(None);
    u
}

/// Intermediate results, exposed for tests and debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presigned {
    /// Final URL.
    pub url: Url,
    /// Canonical request that was signed.
    pub canonical_request: String,
    /// String to sign.
    pub string_to_sign: String,
    /// Hex signature.
    pub signature: String,
}

/// Presign a request using raw key material.
#[allow(clippy::too_many_arguments)]
pub fn presign_raw(
    access_key_id: &str,
    secret: &SecretString,
    session_token: Option<&str>,
    method: &str,
    url: &Url,
    extra_headers: &[(&str, &str)],
    expires: Duration,
    now: Ts,
    region: &str,
    service: &str,
) -> Result<Presigned, PresignError> {
    if expires < Duration::from_secs(1) || expires > MAX_PRESIGN_EXPIRY {
        return Err(PresignError::Expiry);
    }
    let host = url.host_str().ok_or(PresignError::NoHost)?;
    let host = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let t = now.to_jiff();
    let amz_date = t.strftime("%Y%m%dT%H%M%SZ").to_string();
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/{service}/aws4_request");

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("host".into(), host);
    for (k, v) in extra_headers {
        let name = k.trim().to_ascii_lowercase();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic() && b != b':') {
            return Err(PresignError::Header(name));
        }
        if v.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(PresignError::Header(name));
        }
        let val = v.split_whitespace().collect::<Vec<_>>().join(" ");
        headers
            .entry(name)
            .and_modify(|e| {
                e.push(',');
                e.push_str(&val);
            })
            .or_insert(val);
    }
    let signed_headers = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

    let mut query: Vec<(String, String)> = url
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (
                percent_decode(&k.replace('+', " ")),
                percent_decode(&v.replace('+', " ")),
            )
        })
        .filter(|(k, _)| {
            let k = k.to_ascii_lowercase();
            !AUTH_PARAMS.iter().any(|a| k == a.as_bytes())
        })
        .map(|(k, v)| (uri_encode(&k, false), uri_encode(&v, false)))
        .collect();
    let mut add = |k: &str, v: &str| {
        query.push((
            uri_encode(k.as_bytes(), false),
            uri_encode(v.as_bytes(), false),
        ))
    };
    add("X-Amz-Algorithm", ALGORITHM);
    add("X-Amz-Credential", &format!("{access_key_id}/{scope}"));
    add("X-Amz-Date", &amz_date);
    add("X-Amz-Expires", &expires.as_secs().to_string());
    add("X-Amz-SignedHeaders", &signed_headers);
    if let Some(tok) = session_token {
        add("X-Amz-Security-Token", tok);
    }
    query.sort();
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let path = url.path();
    let canonical_uri = if path.is_empty() {
        "/".to_string()
    } else {
        uri_encode(&percent_decode(path), true)
    };

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD"
    );
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let key = signing_key(secret.expose(), date, region, service);
    let signature = hex::encode(hmac(&key, string_to_sign.as_bytes()));

    let mut out = url.clone();
    out.set_path(&canonical_uri);
    out.set_query(Some(&format!(
        "{canonical_query}&X-Amz-Signature={signature}"
    )));
    Ok(Presigned {
        url: out,
        canonical_request,
        string_to_sign,
        signature,
    })
}

/// Presign `method url` for `cred` (adds `X-Amz-Security-Token` for STS sessions).
/// `extra_headers` become signed headers the client must send. Expiry 1 s ..= 7 days.
#[allow(clippy::too_many_arguments)]
pub fn presign(
    cred: &Credential,
    method: &str,
    url: &Url,
    extra_headers: &[(&str, &str)],
    expires: Duration,
    now: Ts,
    region: &str,
    service: &str,
) -> Result<Url, PresignError> {
    let mut expires = expires;
    if let Some(exp) = cred.expires_at {
        let left = Duration::from_secs((exp.as_secs() - now.as_secs()).max(0) as u64);
        expires = expires.min(left);
    }
    presign_raw(
        &cred.access_key_id,
        &cred.secret_key,
        cred.session.as_ref().map(|s| s.token.expose()),
        method,
        url,
        extra_headers,
        expires,
        now,
        region,
        service,
    )
    .map(|p| p.url)
}

#[cfg(test)]
mod tests;
