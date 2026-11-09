//! SigV4 (our verifier guards admin, STS and MCP; the S3 path shares the credential lookup).
//! 1. Arbitrary requests: `parse` + `verify` never panic, and never accept a forged signature.
//! 2. Round trip: a URL presigned by our signer for any bucket/key/query verifies, and changing
//!    the secret or the clock past expiry rejects it (catches signer/verifier canonicalisation
//!    disagreements on odd keys).
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::time::Duration;
use tidemark_auth::SecretString;
use tidemark_auth::sigv4::{EMPTY_SHA256, HttpParts, object_url, parse, presign_raw, verify};
use tidemark_auth::types::Ts;

#[derive(Arbitrary, Debug)]
struct In {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    key: String,
    extra_query: Vec<(String, String)>,
    expires: u16,
}

const NOW: i64 = 1_790_000_000;

fuzz_target!(|i: In| {
    let secret = SecretString::new("fuzz-secret");
    let headers: Vec<(String, String)> = i
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    let req = HttpParts {
        method: &i.method,
        raw_path: &i.path,
        raw_query: &i.query,
        headers: &headers,
        body_sha256: EMPTY_SHA256,
    };
    if let Ok(auth) = parse(&req) {
        // Accepting arbitrary input would mean a 2^-256 HMAC collision.
        assert!(verify(&req, &auth, &secret, Ts::from_secs(NOW)).is_err());
    }

    let base = url::Url::parse("http://127.0.0.1:9000").unwrap();
    let mut url = object_url(&base, "fuzz-bucket", &i.key);
    for (k, v) in i.extra_query.iter().take(4) {
        if k.to_ascii_lowercase().starts_with("x-amz-") {
            continue;
        }
        url.query_pairs_mut().append_pair(k, v);
    }
    let expires = Duration::from_secs(u64::from(i.expires).clamp(1, 3600));
    let t0 = Ts::from_secs(NOW);
    let Ok(p) = presign_raw(
        "AKFUZZ",
        &secret,
        None,
        "GET",
        &url,
        &[],
        expires,
        t0,
        "us-east-1",
        "s3",
    ) else {
        return;
    };
    let host = vec![("host".to_string(), "127.0.0.1:9000".to_string())];
    let req = HttpParts {
        method: "GET",
        raw_path: p.url.path(),
        raw_query: p.url.query().unwrap_or(""),
        headers: &host,
        body_sha256: EMPTY_SHA256,
    };
    let auth = parse(&req).expect("our own presigned URL parses");
    verify(&req, &auth, &secret, t0.plus(Duration::from_secs(1))).unwrap_or_else(|e| {
        panic!(
            "our own presigned URL failed to verify: {e:?} url={}",
            p.url
        )
    });
    assert!(verify(&req, &auth, &SecretString::new("other"), t0).is_err());
    assert!(
        verify(
            &req,
            &auth,
            &secret,
            t0.plus(expires + Duration::from_secs(1))
        )
        .is_err()
    );
});
