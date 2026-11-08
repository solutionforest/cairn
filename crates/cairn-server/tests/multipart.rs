//! Multipart: Create/UploadPart/UploadPartCopy/Complete/Abort/ListParts/ListMultipartUploads,
//! part validation, composite checksums.

mod common;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ChecksumAlgorithm, ChecksumMode, CompletedMultipartUpload, CompletedPart};
use common::*;
use md5::{Digest, Md5};

const MIB: usize = 1024 * 1024;

fn part(n: i32, etag: &str) -> CompletedPart {
    CompletedPart::builder().part_number(n).e_tag(etag).build()
}

#[tokio::test]
async fn three_part_upload_with_upload_part_copy() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("mpu").await;
    let p1: Vec<u8> = (0..5 * MIB).map(|i| (i % 251) as u8).collect();
    let src: Vec<u8> = (0..6 * MIB).map(|i| (i % 13) as u8).collect();
    let p3 = b"tail part".to_vec();
    env.put("mpu", "copy-src", src.clone()).await;

    let up = s3
        .create_multipart_upload()
        .bucket("mpu")
        .key("big")
        .content_type("application/x-big")
        .metadata("m", "1")
        .send()
        .await
        .unwrap();
    let uid = up.upload_id().unwrap().to_string();
    let r1 = s3
        .upload_part()
        .bucket("mpu")
        .key("big")
        .upload_id(&uid)
        .part_number(1)
        .body(ByteStream::from(p1.clone()))
        .send()
        .await
        .unwrap();
    let r2 = s3
        .upload_part_copy()
        .bucket("mpu")
        .key("big")
        .upload_id(&uid)
        .part_number(2)
        .copy_source("mpu/copy-src")
        .copy_source_range(format!("bytes=0-{}", 5 * MIB - 1))
        .send()
        .await
        .unwrap();
    let r3 = s3
        .upload_part()
        .bucket("mpu")
        .key("big")
        .upload_id(&uid)
        .part_number(3)
        .body(ByteStream::from(p3.clone()))
        .send()
        .await
        .unwrap();
    let e1 = r1.e_tag().unwrap().to_string();
    let e2 = r2.copy_part_result().unwrap().e_tag().unwrap().to_string();
    let e3 = r3.e_tag().unwrap().to_string();

    // ListParts with paging; ListMultipartUploads.
    let lp = s3
        .list_parts()
        .bucket("mpu")
        .key("big")
        .upload_id(&uid)
        .max_parts(2)
        .send()
        .await
        .unwrap();
    assert_eq!(lp.parts().len(), 2);
    assert_eq!(lp.is_truncated(), Some(true));
    let lp2 = s3
        .list_parts()
        .bucket("mpu")
        .key("big")
        .upload_id(&uid)
        .part_number_marker(lp.next_part_number_marker().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(lp2.parts().len(), 1);
    assert_eq!(lp2.parts()[0].part_number(), Some(3));
    assert_eq!(lp2.parts()[0].size(), Some(p3.len() as i64));
    let lu = s3
        .list_multipart_uploads()
        .bucket("mpu")
        .send()
        .await
        .unwrap();
    assert_eq!(lu.uploads().len(), 1);
    assert_eq!(lu.uploads()[0].upload_id(), Some(uid.as_str()));

    // Validation: wrong order, unknown etag, small non-final part.
    let bad_order = s3
        .complete_multipart_upload()
        .bucket("mpu")
        .key("big")
        .upload_id(&uid)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(part(2, &e2))
                .parts(part(1, &e1))
                .build(),
        )
        .send()
        .await;
    assert_eq!(code(bad_order), "InvalidPartOrder");
    let bad_part = s3
        .complete_multipart_upload()
        .bucket("mpu")
        .key("big")
        .upload_id(&uid)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(part(1, "\"ffff\""))
                .build(),
        )
        .send()
        .await;
    assert_eq!(code(bad_part), "InvalidPart");
    let too_small = s3
        .complete_multipart_upload()
        .bucket("mpu")
        .key("big")
        .upload_id(&uid)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(part(3, &e3))
                .parts(part(4, &e3))
                .build(),
        )
        .send()
        .await;
    assert!(matches!(
        code(too_small).as_str(),
        "EntityTooSmall" | "InvalidPart"
    ));

    let done = s3
        .complete_multipart_upload()
        .bucket("mpu")
        .key("big")
        .upload_id(&uid)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(part(1, &e1))
                .parts(part(2, &e2))
                .parts(part(3, &e3))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let mut md5s = Md5::new();
    for e in [&e1, &e2, &e3] {
        md5s.update(hex_decode(e.trim_matches('"')));
    }
    let want = format!("\"{}-3\"", hex(&md5s.finalize()));
    assert_eq!(done.e_tag(), Some(want.as_str()));

    let mut expected = p1.clone();
    expected.extend_from_slice(&src[..5 * MIB]);
    expected.extend_from_slice(&p3);
    let got = env.get("mpu", "big").await;
    assert_eq!(got.len(), expected.len());
    assert!(got == expected);
    let h = s3
        .head_object()
        .bucket("mpu")
        .key("big")
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_type(), Some("application/x-big"));
    assert_eq!(
        h.metadata().unwrap().get("m").map(String::as_str),
        Some("1")
    );
    // partNumber reads.
    let g = s3
        .get_object()
        .bucket("mpu")
        .key("big")
        .part_number(3)
        .send()
        .await
        .unwrap();
    assert_eq!(g.parts_count(), Some(3));
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes().as_ref(),
        p3.as_slice()
    );
    // Ranged read across the part boundary.
    let g = s3
        .get_object()
        .bucket("mpu")
        .key("big")
        .range(format!("bytes={}-{}", 5 * MIB - 2, 5 * MIB + 1))
        .send()
        .await
        .unwrap();
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes().as_ref(),
        &expected[5 * MIB - 2..5 * MIB + 2]
    );
    // The upload is gone.
    assert_eq!(
        code(
            s3.list_parts()
                .bucket("mpu")
                .key("big")
                .upload_id(&uid)
                .send()
                .await
        ),
        "NoSuchUpload"
    );
    assert!(
        s3.list_multipart_uploads()
            .bucket("mpu")
            .send()
            .await
            .unwrap()
            .uploads()
            .is_empty()
    );
    env.stop().await;
}

#[tokio::test]
async fn abort_and_checksummed_parts() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("mpu").await;
    let up = s3
        .create_multipart_upload()
        .bucket("mpu")
        .key("gone")
        .send()
        .await
        .unwrap();
    let uid = up.upload_id().unwrap();
    s3.upload_part()
        .bucket("mpu")
        .key("gone")
        .upload_id(uid)
        .part_number(1)
        .body(ByteStream::from_static(b"abandoned"))
        .send()
        .await
        .unwrap();
    for bad in [0, 10_001] {
        let r = s3
            .upload_part()
            .bucket("mpu")
            .key("gone")
            .upload_id(uid)
            .part_number(bad)
            .body(ByteStream::from_static(b"x"))
            .send()
            .await;
        assert_eq!(code(r), "InvalidArgument", "part number {bad}");
    }
    s3.abort_multipart_upload()
        .bucket("mpu")
        .key("gone")
        .upload_id(uid)
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(
            s3.abort_multipart_upload()
                .bucket("mpu")
                .key("gone")
                .upload_id(uid)
                .send()
                .await
        ),
        "NoSuchUpload"
    );
    assert_eq!(
        code(
            s3.upload_part()
                .bucket("mpu")
                .key("gone")
                .upload_id("does-not-exist")
                .part_number(1)
                .body(ByteStream::from_static(b"x"))
                .send()
                .await
        ),
        "NoSuchUpload"
    );

    // Composite SHA256 checksum across two parts.
    let up = s3
        .create_multipart_upload()
        .bucket("mpu")
        .key("ck")
        .checksum_algorithm(ChecksumAlgorithm::Sha256)
        .send()
        .await
        .unwrap();
    let uid = up.upload_id().unwrap();
    let a: Vec<u8> = vec![7u8; 5 * MIB];
    let mut parts = Vec::new();
    for (n, data) in [(1, a.clone()), (2, b"end".to_vec())] {
        let r = s3
            .upload_part()
            .bucket("mpu")
            .key("ck")
            .upload_id(uid)
            .part_number(n)
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
            .body(ByteStream::from(data))
            .send()
            .await
            .unwrap();
        parts.push(
            CompletedPart::builder()
                .part_number(n)
                .e_tag(r.e_tag().unwrap())
                .checksum_sha256(r.checksum_sha256().unwrap())
                .build(),
        );
    }
    let done = s3
        .complete_multipart_upload()
        .bucket("mpu")
        .key("ck")
        .upload_id(uid)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let ck = done.checksum_sha256().unwrap();
    assert!(ck.ends_with("-2"), "{ck}");
    let g = s3
        .get_object()
        .bucket("mpu")
        .key("ck")
        .checksum_mode(ChecksumMode::Enabled)
        .send()
        .await
        .unwrap();
    assert_eq!(g.checksum_sha256(), Some(ck));
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes().len(),
        5 * MIB + 3
    );
    env.stop().await;
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
