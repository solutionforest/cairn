use super::*;
use crate::principal::Principal;
use crate::store::SessionInfo;

const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

#[test]
fn aws_signing_key_vector() {
    // AWS docs "Examples of how to derive a signing key for Signature Version 4".
    let k = signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20120215",
        "us-east-1",
        "iam",
    );
    assert_eq!(
        hex::encode(k),
        "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
    );
}

#[test]
fn aws_presigned_get_vector() {
    // AWS S3 docs "Authenticating Requests: Using Query Parameters" example.
    let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
    let p = presign_raw(
        "AKIAIOSFODNN7EXAMPLE",
        &SecretString::new(AWS_SECRET),
        None,
        "GET",
        &url,
        &[],
        Duration::from_secs(86400),
        Ts::from_secs(1_369_353_600),
        "us-east-1",
        "s3",
    )
    .unwrap();
    assert_eq!(
        p.canonical_request,
        "GET\n/test.txt\nX-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\nhost:examplebucket.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD"
    );
    assert_eq!(
        p.signature,
        "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
    assert_eq!(
        p.url.as_str(),
        "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
}

#[test]
fn tricky_keys_headers_and_session_token() {
    // Expected values computed independently (Python hmac/hashlib) from the canonical request.
    let url =
        Url::parse("http://localhost:9000/bucket/a b+c~d/été!'()*.txt?versionId=v%201").unwrap();
    let p = presign_raw(
        "CAIRNTESTKEY000000AB",
        &SecretString::new("secretsecretsecretsecretsecretsecret0000"),
        Some("tok/en+="),
        "PUT",
        &url,
        &[("Content-Type", "text/plain"), ("X-Amz-Meta-A", "  x   y ")],
        MAX_PRESIGN_EXPIRY,
        Ts::from_secs(1_794_139_200),
        "us-east-1",
        "s3",
    )
    .unwrap();
    let want_cr = "PUT\n/bucket/a%20b%2Bc~d/%C3%A9t%C3%A9%21%27%28%29%2A.txt\nX-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=CAIRNTESTKEY000000AB%2F20261108%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261108T120000Z&X-Amz-Expires=604800&X-Amz-Security-Token=tok%2Fen%2B%3D&X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-meta-a&versionId=v%201\ncontent-type:text/plain\nhost:localhost:9000\nx-amz-meta-a:x y\n\ncontent-type;host;x-amz-meta-a\nUNSIGNED-PAYLOAD";
    assert_eq!(p.canonical_request, want_cr);
    assert_eq!(
        p.signature,
        "bc9f09be24f528b34b15a589a9c63af5c13b0a1b9a1532528f7d88726f16f73f"
    );
    assert!(
        p.url.as_str().starts_with(
            "http://localhost:9000/bucket/a%20b%2Bc~d/%C3%A9t%C3%A9%21%27%28%29%2A.txt?"
        )
    );
    assert!(p.url.as_str().ends_with(
        "&X-Amz-Signature=bc9f09be24f528b34b15a589a9c63af5c13b0a1b9a1532528f7d88726f16f73f"
    ));
}

#[test]
fn uri_encoding_rules() {
    assert_eq!(uri_encode(b"a b+c~d-_.", true), "a%20b%2Bc~d-_.");
    assert_eq!(uri_encode("é/ü".as_bytes(), true), "%C3%A9/%C3%BC");
    assert_eq!(uri_encode(b"a/b", false), "a%2Fb");
    assert_eq!(uri_encode(b"%", true), "%25");
    assert_eq!(percent_decode("a%20b%zz%2"), b"a b%zz%2".to_vec());
    let u = object_url(&Url::parse("http://h:9000").unwrap(), "b", "dir/a b+%.txt");
    assert_eq!(u.as_str(), "http://h:9000/b/dir/a%20b%2B%25.txt");
}

#[test]
fn expiry_bounds() {
    let url = Url::parse("https://h/b/k").unwrap();
    let s = SecretString::new("s");
    let go = |d: Duration| {
        presign_raw(
            "AK",
            &s,
            None,
            "GET",
            &url,
            &[],
            d,
            Ts::from_secs(0),
            "us-east-1",
            "s3",
        )
    };
    assert_eq!(
        go(Duration::from_secs(0)).unwrap_err(),
        PresignError::Expiry
    );
    assert_eq!(
        go(MAX_PRESIGN_EXPIRY + Duration::from_secs(1)).unwrap_err(),
        PresignError::Expiry
    );
    go(MAX_PRESIGN_EXPIRY).unwrap();
    go(Duration::from_secs(1)).unwrap();
    let bad = presign_raw(
        "AK",
        &s,
        None,
        "GET",
        &url,
        &[("bad name", "v")],
        Duration::from_secs(5),
        Ts(0),
        "r",
        "s3",
    );
    assert!(matches!(bad, Err(PresignError::Header(_))));
    let bad = presign_raw(
        "AK",
        &s,
        None,
        "GET",
        &url,
        &[("x-a", "v\r\nx")],
        Duration::from_secs(5),
        Ts(0),
        "r",
        "s3",
    );
    assert!(matches!(bad, Err(PresignError::Header(_))));
}

#[test]
fn presign_with_credential_adds_token_and_clamps_to_session_expiry() {
    let now = Ts::from_secs(1_794_139_200);
    let cred = Credential {
        access_key_id: "CAIRNSESSION00000000".into(),
        secret_key: SecretString::new("sek"),
        principal: Principal::root(),
        session: Some(SessionInfo {
            token: SecretString::new("TOKEN"),
            expires_at: now.plus(Duration::from_secs(600)),
        }),
        expires_at: Some(now.plus(Duration::from_secs(600))),
    };
    let url = Url::parse("https://cairn.local/b/k").unwrap();
    let u = presign(
        &cred,
        "GET",
        &url,
        &[],
        Duration::from_secs(3600),
        now,
        "us-east-1",
        "s3",
    )
    .unwrap();
    let q: Vec<(String, String)> = u.query_pairs().map(|(a, b)| (a.into(), b.into())).collect();
    assert!(q.contains(&("X-Amz-Security-Token".into(), "TOKEN".into())));
    assert!(q.contains(&("X-Amz-Expires".into(), "600".into())));
    let late = now.plus(Duration::from_secs(601));
    assert_eq!(
        presign(
            &cred,
            "GET",
            &url,
            &[],
            Duration::from_secs(60),
            late,
            "us-east-1",
            "s3"
        )
        .unwrap_err(),
        PresignError::Expiry
    );
    // re-presigning an already presigned URL drops the old signature
    let again = presign(
        &cred,
        "GET",
        &u,
        &[],
        Duration::from_secs(60),
        now,
        "us-east-1",
        "s3",
    )
    .unwrap();
    for k in [
        "X-Amz-Signature=",
        "X-Amz-Credential=",
        "X-Amz-Security-Token=",
        "X-Amz-Expires=",
    ] {
        assert_eq!(again.as_str().matches(k).count(), 1, "{k}");
    }
}
