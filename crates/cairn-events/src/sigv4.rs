//! Minimal AWS Signature Version 4 *signing* for outbound requests (function sinks calling the
//! Lambda `Invoke` API). Verification of inbound requests lives in `s3s` / `cairn-auth`.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// SigV4 algorithm name.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// A request to sign. `path` and `query` are exactly as sent on the wire.
#[derive(Debug, Clone)]
pub struct SignableRequest<'a> {
    /// HTTP method.
    pub method: &'a str,
    /// Request path as sent (already percent-encoded once).
    pub path: &'a str,
    /// Raw query string without `?` (may be empty).
    pub query: &'a str,
    /// Headers to sign (must include `host` and `x-amz-date`).
    pub headers: &'a [(String, String)],
    /// Request body.
    pub payload: &'a [u8],
}

/// Signing scope.
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    /// `YYYYMMDD'T'HHMMSS'Z'`.
    pub amz_date: &'a str,
    /// Region, e.g. `us-east-1`.
    pub region: &'a str,
    /// Service, e.g. `lambda`.
    pub service: &'a str,
}

impl Scope<'_> {
    fn date(&self) -> &str {
        &self.amz_date[..8.min(self.amz_date.len())]
    }

    /// `date/region/service/aws4_request`.
    pub fn credential_scope(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date(),
            self.region,
            self.service
        )
    }
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Derive the signing key for `date` (`YYYYMMDD`), region and service.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let mut k = zeroize::Zeroizing::new(format!("AWS4{secret}").into_bytes());
    let k_date = hmac(&k, date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    let out = hmac(&k_service, b"aws4_request");
    zeroize::Zeroize::zeroize(&mut *k);
    out
}

/// RFC 3986 percent-encoding as SigV4 wants it (unreserved kept, uppercase hex).
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// Canonical URI for non-S3 services: each segment of the sent path is encoded again.
pub fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    uri_encode(path, false)
}

/// Canonical query string: decoded, re-encoded, sorted by name then value.
pub fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (
                uri_encode(&percent_decode(k), true),
                uri_encode(&percent_decode(v), true),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut map: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for (k, v) in headers {
        let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
        map.entry(k.to_ascii_lowercase()).or_default().push(v);
    }
    let canon = map
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.join(",")))
        .collect::<String>();
    let signed = map.keys().cloned().collect::<Vec<_>>().join(";");
    (canon, signed)
}

/// The canonical request and the signed-headers list.
pub fn canonical_request(req: &SignableRequest<'_>) -> (String, String) {
    let (canon_headers, signed) = canonical_headers(req.headers);
    let cr = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        canonical_uri(req.path),
        canonical_query(req.query),
        canon_headers,
        signed,
        sha256_hex(req.payload)
    );
    (cr, signed)
}

/// The string to sign for a canonical request.
pub fn string_to_sign(scope: &Scope<'_>, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{}\n{}\n{}",
        scope.amz_date,
        scope.credential_scope(),
        sha256_hex(canonical_request.as_bytes())
    )
}

/// Compute the `Authorization` header value.
pub fn authorization(
    req: &SignableRequest<'_>,
    scope: &Scope<'_>,
    access_key_id: &str,
    secret: &str,
) -> String {
    let (cr, signed) = canonical_request(req);
    let sts = string_to_sign(scope, &cr);
    let key = signing_key(secret, scope.date(), scope.region, scope.service);
    let sig = hex::encode(hmac(&key, sts.as_bytes()));
    format!(
        "{ALGORITHM} Credential={access_key_id}/{}, SignedHeaders={signed}, Signature={sig}",
        scope.credential_scope()
    )
}

/// Format a timestamp as `YYYYMMDD'T'HHMMSS'Z'`.
pub fn amz_date(t: jiff::Timestamp) -> String {
    t.strftime("%Y%m%dT%H%M%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const AK: &str = "AKIDEXAMPLE";
    const SK: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn h(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    // AWS docs, "Examples of how to derive a signing key for Signature Version 4".
    #[test]
    fn derive_signing_key() {
        let k = signing_key(SK, "20150830", "us-east-1", "iam");
        assert_eq!(
            hex::encode(k),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    // AWS docs, "Create a canonical request" / IAM ListUsers walkthrough.
    #[test]
    fn iam_list_users() {
        let headers = h(&[
            (
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
            ("Host", "iam.amazonaws.com"),
            ("X-Amz-Date", "20150830T123600Z"),
        ]);
        let req = SignableRequest {
            method: "GET",
            path: "/",
            query: "Action=ListUsers&Version=2010-05-08",
            headers: &headers,
            payload: b"",
        };
        let (cr, signed) = canonical_request(&req);
        assert_eq!(signed, "content-type;host;x-amz-date");
        assert_eq!(
            sha256_hex(cr.as_bytes()),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        let scope = Scope {
            amz_date: "20150830T123600Z",
            region: "us-east-1",
            service: "iam",
        };
        let auth = authorization(&req, &scope, AK, SK);
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    // aws-sig-v4-test-suite: get-vanilla and post-vanilla.
    #[test]
    fn test_suite_vanilla() {
        let headers = h(&[
            ("Host", "example.amazonaws.com"),
            ("X-Amz-Date", "20150830T123600Z"),
        ]);
        let scope = Scope {
            amz_date: "20150830T123600Z",
            region: "us-east-1",
            service: "service",
        };
        for (method, sig) in [
            (
                "GET",
                "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            ),
            (
                "POST",
                "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
            ),
        ] {
            let req = SignableRequest {
                method,
                path: "/",
                query: "",
                headers: &headers,
                payload: b"",
            };
            assert!(
                authorization(&req, &scope, AK, SK).ends_with(sig),
                "{method}"
            );
        }
    }

    // aws-sig-v4-test-suite: get-vanilla-query-order-key-case.
    #[test]
    fn test_suite_query_order() {
        let headers = h(&[
            ("Host", "example.amazonaws.com"),
            ("X-Amz-Date", "20150830T123600Z"),
        ]);
        let req = SignableRequest {
            method: "GET",
            path: "/",
            query: "Param2=value2&Param1=value1",
            headers: &headers,
            payload: b"",
        };
        let scope = Scope {
            amz_date: "20150830T123600Z",
            region: "us-east-1",
            service: "service",
        };
        assert!(
            authorization(&req, &scope, AK, SK)
                .ends_with("b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500")
        );
    }

    #[test]
    fn encoding() {
        assert_eq!(uri_encode("a b/c~", false), "a%20b/c~");
        assert_eq!(uri_encode("a:b", true), "a%3Ab");
        assert_eq!(
            canonical_uri("/2015-03-31/functions/arn%3Aaws%3Alambda/invocations"),
            "/2015-03-31/functions/arn%253Aaws%253Alambda/invocations"
        );
        assert_eq!(canonical_query("b=2&a=1&a=0"), "a=0&a=1&b=2");
    }
}
