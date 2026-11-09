//! Range (incl. suffix) and conditional request matrix on GET/HEAD/PUT/Copy.

mod common;
use aws_sdk_s3::primitives::{ByteStream, DateTime};
use common::*;

#[tokio::test]
async fn range_matrix() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("bkt").await;
    env.put("bkt", "k", "0123456789").await;
    let cases: &[(&str, Option<&str>, Option<&str>)] = &[
        ("bytes=0-0", Some("0"), Some("bytes 0-0/10")),
        ("bytes=2-5", Some("2345"), Some("bytes 2-5/10")),
        ("bytes=7-", Some("789"), Some("bytes 7-9/10")),
        ("bytes=-3", Some("789"), Some("bytes 7-9/10")),
        ("bytes=-100", Some("0123456789"), Some("bytes 0-9/10")),
        ("bytes=5-100", Some("56789"), Some("bytes 5-9/10")),
        ("bytes=10-", None, None),
        ("bytes=20-30", None, None),
    ];
    for (range, body, content_range) in cases {
        let r = s3
            .get_object()
            .bucket("bkt")
            .key("k")
            .range(*range)
            .send()
            .await;
        match body {
            Some(b) => {
                let r = r.unwrap();
                assert_eq!(r.content_range(), *content_range, "{range}");
                assert_eq!(r.content_length(), Some(b.len() as i64), "{range}");
                assert_eq!(
                    r.body.collect().await.unwrap().into_bytes().as_ref(),
                    b.as_bytes(),
                    "{range}"
                );
            }
            None => {
                let e = r.unwrap_err();
                assert_eq!(e.raw_response().unwrap().status().as_u16(), 416, "{range}");
                assert_eq!(
                    aws_sdk_s3::error::ProvideErrorMetadata::code(&e),
                    Some("InvalidRange")
                );
            }
        }
    }
    // HEAD with a range reports the partial length.
    let h = s3
        .head_object()
        .bucket("bkt")
        .key("k")
        .range("bytes=1-3")
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_length(), Some(3));
    // Raw request: 206 status code.
    let g = s3
        .get_object()
        .bucket("bkt")
        .key("k")
        .range("bytes=-1")
        .send()
        .await
        .unwrap();
    assert_eq!(g.content_range(), Some("bytes 9-9/10"));
    env.stop().await;
}

#[tokio::test]
async fn conditional_matrix() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("bkt").await;
    let etag = env.put("bkt", "k", "payload").await;
    let lm = s3
        .head_object()
        .bucket("bkt")
        .key("k")
        .send()
        .await
        .unwrap()
        .last_modified
        .unwrap();
    let before = DateTime::from_secs(lm.secs() - 3600);
    let after = DateTime::from_secs(lm.secs() + 3600);

    // GET: If-Match / If-None-Match / If-Modified-Since / If-Unmodified-Since.
    assert!(
        s3.get_object()
            .bucket("bkt")
            .key("k")
            .if_match(&etag)
            .send()
            .await
            .is_ok()
    );
    assert!(
        s3.get_object()
            .bucket("bkt")
            .key("k")
            .if_match("*")
            .send()
            .await
            .is_ok()
    );
    assert_eq!(
        status(
            s3.get_object()
                .bucket("bkt")
                .key("k")
                .if_match("\"bad\"")
                .send()
                .await
        ),
        412
    );
    assert_eq!(
        status(
            s3.get_object()
                .bucket("bkt")
                .key("k")
                .if_none_match(&etag)
                .send()
                .await
        ),
        304
    );
    assert!(
        s3.get_object()
            .bucket("bkt")
            .key("k")
            .if_none_match("\"other\"")
            .send()
            .await
            .is_ok()
    );
    assert_eq!(
        status(
            s3.get_object()
                .bucket("bkt")
                .key("k")
                .if_modified_since(after)
                .send()
                .await
        ),
        304
    );
    assert!(
        s3.get_object()
            .bucket("bkt")
            .key("k")
            .if_modified_since(before)
            .send()
            .await
            .is_ok()
    );
    assert_eq!(
        status(
            s3.get_object()
                .bucket("bkt")
                .key("k")
                .if_unmodified_since(before)
                .send()
                .await
        ),
        412
    );
    assert!(
        s3.get_object()
            .bucket("bkt")
            .key("k")
            .if_unmodified_since(after)
            .send()
            .await
            .is_ok()
    );
    // If-Match wins over a failing If-Unmodified-Since; If-None-Match wins over If-Modified-Since.
    assert!(
        s3.get_object()
            .bucket("bkt")
            .key("k")
            .if_match(&etag)
            .if_unmodified_since(before)
            .send()
            .await
            .is_ok()
    );
    assert!(
        s3.get_object()
            .bucket("bkt")
            .key("k")
            .if_none_match("\"other\"")
            .if_modified_since(after)
            .send()
            .await
            .is_ok()
    );
    // HEAD follows the same rules.
    assert_eq!(
        status(
            s3.head_object()
                .bucket("bkt")
                .key("k")
                .if_match("\"bad\"")
                .send()
                .await
        ),
        412
    );
    assert_eq!(
        status(
            s3.head_object()
                .bucket("bkt")
                .key("k")
                .if_none_match(&etag)
                .send()
                .await
        ),
        304
    );

    // PUT: If-None-Match: * (create only) and If-Match (compare-and-swap).
    assert_eq!(
        status(
            s3.put_object()
                .bucket("bkt")
                .key("k")
                .if_none_match("*")
                .body(ByteStream::from_static(b"x"))
                .send()
                .await
        ),
        412
    );
    s3.put_object()
        .bucket("bkt")
        .key("fresh")
        .if_none_match("*")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        status(
            s3.put_object()
                .bucket("bkt")
                .key("k")
                .if_match("\"bad\"")
                .body(ByteStream::from_static(b"y"))
                .send()
                .await
        ),
        412
    );
    s3.put_object()
        .bucket("bkt")
        .key("k")
        .if_match(&etag)
        .body(ByteStream::from_static(b"swapped"))
        .send()
        .await
        .unwrap();
    assert_eq!(env.get("bkt", "k").await, b"swapped");

    // Copy-source conditions: every failure is 412.
    let etag2 = s3
        .head_object()
        .bucket("bkt")
        .key("k")
        .send()
        .await
        .unwrap()
        .e_tag
        .unwrap();
    assert_eq!(
        status(
            s3.copy_object()
                .bucket("bkt")
                .key("c")
                .copy_source("bkt/k")
                .copy_source_if_none_match(&etag2)
                .send()
                .await
        ),
        412
    );
    assert_eq!(
        status(
            s3.copy_object()
                .bucket("bkt")
                .key("c")
                .copy_source("bkt/k")
                .copy_source_if_modified_since(after)
                .send()
                .await
        ),
        412
    );
    s3.copy_object()
        .bucket("bkt")
        .key("c")
        .copy_source("bkt/k")
        .copy_source_if_match(&etag2)
        .copy_source_if_unmodified_since(after)
        .send()
        .await
        .unwrap();
    env.stop().await;
}
