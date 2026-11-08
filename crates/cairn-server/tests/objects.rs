//! Object operations: Put/Get/Head/Delete/DeleteObjects/CopyObject, object tagging, metadata,
//! content headers, storage class and checksums.

mod common;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    ChecksumAlgorithm, ChecksumMode, Delete, MetadataDirective, ObjectIdentifier, StorageClass,
    Tag, Tagging, TaggingDirective,
};
use base64::Engine as _;
use common::*;
use md5::{Digest, Md5};

#[tokio::test]
async fn put_get_head_delete_with_metadata() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("bkt").await;
    let body = b"hello cairn".to_vec();
    let put = s3
        .put_object()
        .bucket("bkt")
        .key("dir/file.txt")
        .body(ByteStream::from(body.clone()))
        .content_type("text/plain")
        .cache_control("max-age=60")
        .content_disposition("attachment; filename=\"f.txt\"")
        .content_encoding("identity")
        .content_language("en")
        .expires(aws_sdk_s3::primitives::DateTime::from_secs(2_000_000_000))
        .metadata("color", "blue")
        .metadata("Mixed-Case", "v")
        .storage_class(StorageClass::StandardIa)
        .tagging("a=1&b=two")
        .send()
        .await
        .unwrap();
    let etag = format!("\"{}\"", hex(&Md5::digest(&body)));
    assert_eq!(put.e_tag(), Some(etag.as_str()));
    assert!(put.version_id().is_none());

    let h = s3
        .head_object()
        .bucket("bkt")
        .key("dir/file.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_length(), Some(body.len() as i64));
    assert_eq!(h.e_tag(), Some(etag.as_str()));
    assert_eq!(h.content_type(), Some("text/plain"));
    assert_eq!(h.cache_control(), Some("max-age=60"));
    assert_eq!(
        h.content_disposition(),
        Some("attachment; filename=\"f.txt\"")
    );
    assert_eq!(h.content_encoding(), Some("identity"));
    assert_eq!(h.content_language(), Some("en"));
    assert_eq!(h.storage_class(), Some(&StorageClass::StandardIa));
    assert_eq!(h.accept_ranges(), Some("bytes"));
    let meta = h.metadata().unwrap();
    assert_eq!(meta.get("color").map(String::as_str), Some("blue"));
    assert_eq!(meta.get("mixed-case").map(String::as_str), Some("v"));
    assert!(h.last_modified().is_some());

    let g = s3
        .get_object()
        .bucket("bkt")
        .key("dir/file.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(g.tag_count(), Some(2));
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes().as_ref(),
        body.as_slice()
    );

    // response-* overrides.
    let g = s3
        .get_object()
        .bucket("bkt")
        .key("dir/file.txt")
        .response_content_type("application/x-override")
        .send()
        .await
        .unwrap();
    assert_eq!(g.content_type(), Some("application/x-override"));

    // Default content type and zero-byte objects.
    s3.put_object()
        .bucket("bkt")
        .key("empty")
        .body(ByteStream::from(Vec::new()))
        .send()
        .await
        .unwrap();
    let h = s3
        .head_object()
        .bucket("bkt")
        .key("empty")
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_length(), Some(0));
    assert!(h.content_type().is_some());
    assert_eq!(env.get("bkt", "empty").await, b"");

    assert_eq!(
        code(s3.get_object().bucket("bkt").key("nope").send().await),
        "NoSuchKey"
    );
    assert_eq!(
        status(s3.head_object().bucket("bkt").key("nope").send().await),
        404
    );
    assert_eq!(
        code(s3.put_object().bucket("nob").key("k").send().await),
        "NoSuchBucket"
    );

    // Content-MD5 is verified.
    let bad_md5 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
    assert_eq!(
        code(
            s3.put_object()
                .bucket("bkt")
                .key("md5")
                .content_md5(bad_md5)
                .body(ByteStream::from_static(b"data"))
                .send()
                .await
        ),
        "BadDigest"
    );

    s3.delete_object()
        .bucket("bkt")
        .key("dir/file.txt")
        .send()
        .await
        .unwrap();
    // Deleting a missing key succeeds (204).
    s3.delete_object()
        .bucket("bkt")
        .key("dir/file.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(
            s3.get_object()
                .bucket("bkt")
                .key("dir/file.txt")
                .send()
                .await
        ),
        "NoSuchKey"
    );
    env.stop().await;
}

#[tokio::test]
async fn checksums_on_put_and_get() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("bkt").await;
    for algo in [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32C,
        ChecksumAlgorithm::Crc64Nvme,
        ChecksumAlgorithm::Sha1,
        ChecksumAlgorithm::Sha256,
    ] {
        let key = format!("ck-{}", algo.as_str());
        let put = s3
            .put_object()
            .bucket("bkt")
            .key(&key)
            .checksum_algorithm(algo.clone())
            .body(ByteStream::from_static(b"checksum me"))
            .send()
            .await
            .unwrap();
        let sent = match algo {
            ChecksumAlgorithm::Crc32 => put.checksum_crc32(),
            ChecksumAlgorithm::Crc32C => put.checksum_crc32_c(),
            ChecksumAlgorithm::Crc64Nvme => put.checksum_crc64_nvme(),
            ChecksumAlgorithm::Sha1 => put.checksum_sha1(),
            _ => put.checksum_sha256(),
        }
        .map(str::to_string);
        assert!(sent.is_some(), "{algo:?} checksum echoed on PUT");
        let g = s3
            .get_object()
            .bucket("bkt")
            .key(&key)
            .checksum_mode(ChecksumMode::Enabled)
            .send()
            .await
            .unwrap();
        let got = match algo {
            ChecksumAlgorithm::Crc32 => g.checksum_crc32(),
            ChecksumAlgorithm::Crc32C => g.checksum_crc32_c(),
            ChecksumAlgorithm::Crc64Nvme => g.checksum_crc64_nvme(),
            ChecksumAlgorithm::Sha1 => g.checksum_sha1(),
            _ => g.checksum_sha256(),
        }
        .map(str::to_string);
        assert_eq!(got, sent, "{algo:?}");
        // The SDK validates the body against the returned checksum.
        assert_eq!(
            g.body.collect().await.unwrap().into_bytes().as_ref(),
            b"checksum me"
        );
    }
    // A wrong explicit checksum is rejected.
    let r = s3
        .put_object()
        .bucket("bkt")
        .key("bad")
        .checksum_sha256(base64::engine::general_purpose::STANDARD.encode([1u8; 32]))
        .body(ByteStream::from_static(b"payload"))
        .send()
        .await;
    assert_eq!(code(r), "BadDigest");
    env.stop().await;
}

#[tokio::test]
async fn delete_objects_copy_and_tagging() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("bkt").await;
    env.bucket("other").await;
    for k in ["a", "b", "c"] {
        env.put("bkt", k, format!("data-{k}")).await;
    }
    let del = s3
        .delete_objects()
        .bucket("bkt")
        .delete(
            Delete::builder()
                .objects(ObjectIdentifier::builder().key("a").build().unwrap())
                .objects(ObjectIdentifier::builder().key("missing").build().unwrap())
                .objects(
                    ObjectIdentifier::builder()
                        .key("b")
                        .version_id("not-a-version")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let deleted: Vec<_> = del.deleted().iter().map(|d| d.key().unwrap()).collect();
    assert_eq!(deleted, vec!["a", "missing"]);
    assert_eq!(del.errors().len(), 1);
    assert_eq!(del.errors()[0].key(), Some("b"));
    let quiet = s3
        .delete_objects()
        .bucket("bkt")
        .delete(
            Delete::builder()
                .quiet(true)
                .objects(ObjectIdentifier::builder().key("b").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert!(quiet.deleted().is_empty());

    // Copy with metadata COPY (default) and REPLACE, cross-bucket.
    s3.put_object()
        .bucket("bkt")
        .key("src")
        .content_type("text/x-src")
        .metadata("k", "v")
        .tagging("t=1")
        .body(ByteStream::from_static(b"copy source"))
        .send()
        .await
        .unwrap();
    let c = s3
        .copy_object()
        .bucket("other")
        .key("dst")
        .copy_source("bkt/src")
        .send()
        .await
        .unwrap();
    let src_etag = s3
        .head_object()
        .bucket("bkt")
        .key("src")
        .send()
        .await
        .unwrap()
        .e_tag
        .unwrap();
    assert_eq!(
        c.copy_object_result().unwrap().e_tag(),
        Some(src_etag.as_str())
    );
    let h = s3
        .head_object()
        .bucket("other")
        .key("dst")
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_type(), Some("text/x-src"));
    assert_eq!(
        h.metadata().unwrap().get("k").map(String::as_str),
        Some("v")
    );
    assert_eq!(env.get("other", "dst").await, b"copy source");
    let t = s3
        .get_object_tagging()
        .bucket("other")
        .key("dst")
        .send()
        .await
        .unwrap();
    assert_eq!(t.tag_set().len(), 1);

    s3.copy_object()
        .bucket("other")
        .key("dst2")
        .copy_source("bkt/src")
        .metadata_directive(MetadataDirective::Replace)
        .content_type("application/json")
        .metadata("new", "1")
        .tagging_directive(TaggingDirective::Replace)
        .tagging("x=y&z=w")
        .send()
        .await
        .unwrap();
    let h = s3
        .head_object()
        .bucket("other")
        .key("dst2")
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_type(), Some("application/json"));
    let m = h.metadata().unwrap();
    assert!(m.get("k").is_none());
    assert_eq!(m.get("new").map(String::as_str), Some("1"));
    let t = s3
        .get_object_tagging()
        .bucket("other")
        .key("dst2")
        .send()
        .await
        .unwrap();
    assert_eq!(t.tag_set().len(), 2);

    // Copying onto itself without changes is rejected; with REPLACE it updates metadata.
    assert_eq!(
        code(
            s3.copy_object()
                .bucket("bkt")
                .key("src")
                .copy_source("bkt/src")
                .send()
                .await
        ),
        "InvalidRequest"
    );
    s3.copy_object()
        .bucket("bkt")
        .key("src")
        .copy_source("bkt/src")
        .metadata_directive(MetadataDirective::Replace)
        .content_type("text/updated")
        .send()
        .await
        .unwrap();
    let h = s3
        .head_object()
        .bucket("bkt")
        .key("src")
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_type(), Some("text/updated"));
    // Copy-source conditions.
    assert_eq!(
        code(
            s3.copy_object()
                .bucket("bkt")
                .key("x")
                .copy_source("bkt/src")
                .copy_source_if_match("\"0000\"")
                .send()
                .await
        ),
        "PreconditionFailed"
    );
    assert_eq!(
        code(
            s3.copy_object()
                .bucket("bkt")
                .key("x")
                .copy_source("bkt/none")
                .send()
                .await
        ),
        "NoSuchKey"
    );
    // Keys needing URL encoding in x-amz-copy-source.
    env.put("bkt", "sp ace/ü+?", "odd").await;
    s3.copy_object()
        .bucket("bkt")
        .key("odd-copy")
        .copy_source("bkt/sp%20ace/%C3%BC%2B%3F")
        .send()
        .await
        .unwrap();
    assert_eq!(env.get("bkt", "odd-copy").await, b"odd");

    // Object tagging.
    s3.put_object_tagging()
        .bucket("bkt")
        .key("src")
        .tagging(
            Tagging::builder()
                .tag_set(Tag::builder().key("p").value("q").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let t = s3
        .get_object_tagging()
        .bucket("bkt")
        .key("src")
        .send()
        .await
        .unwrap();
    assert_eq!(t.tag_set()[0].key(), "p");
    s3.delete_object_tagging()
        .bucket("bkt")
        .key("src")
        .send()
        .await
        .unwrap();
    let t = s3
        .get_object_tagging()
        .bucket("bkt")
        .key("src")
        .send()
        .await
        .unwrap();
    assert!(t.tag_set().is_empty());
    assert_eq!(
        code(
            s3.get_object_tagging()
                .bucket("bkt")
                .key("missing")
                .send()
                .await
        ),
        "NoSuchKey"
    );
    env.stop().await;
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
