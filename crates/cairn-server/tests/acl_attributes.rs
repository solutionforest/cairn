//! ACLs in BucketOwnerEnforced mode (Get/Put Bucket/Object ACL, ownership controls) and
//! GetObjectAttributes.

mod common;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    AccessControlPolicy, BucketCannedAcl, ChecksumAlgorithm, CompletedMultipartUpload,
    CompletedPart, Grant, Grantee, ObjectAttributes, ObjectCannedAcl, ObjectOwnership,
    OwnershipControls, OwnershipControlsRule, Permission, Type,
};
use common::*;

const MIB: usize = 1024 * 1024;

#[tokio::test]
async fn acls_are_owner_only_and_wider_grants_are_refused() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("acl").await;
    env.put("acl", "k", "v").await;

    let ba = s3.get_bucket_acl().bucket("acl").send().await.unwrap();
    let owner = ba.owner().unwrap().id().unwrap().to_string();
    assert_eq!(ba.grants().len(), 1);
    let g = &ba.grants()[0];
    assert_eq!(g.permission(), Some(&Permission::FullControl));
    assert_eq!(g.grantee().unwrap().id(), Some(owner.as_str()));
    assert_eq!(g.grantee().unwrap().r#type(), &Type::CanonicalUser);

    let oa = s3
        .get_object_acl()
        .bucket("acl")
        .key("k")
        .send()
        .await
        .unwrap();
    assert_eq!(oa.owner().unwrap().id(), Some(owner.as_str()));
    assert_eq!(oa.grants().len(), 1);
    assert_eq!(
        code(
            s3.get_object_acl()
                .bucket("acl")
                .key("missing")
                .send()
                .await
        ),
        "NoSuchKey"
    );

    // Owner-only requests are accepted no-ops.
    s3.put_bucket_acl()
        .bucket("acl")
        .acl(BucketCannedAcl::Private)
        .send()
        .await
        .unwrap();
    s3.put_object_acl()
        .bucket("acl")
        .key("k")
        .acl(ObjectCannedAcl::BucketOwnerFullControl)
        .send()
        .await
        .unwrap();
    let owner_only = AccessControlPolicy::builder()
        .owner(ba.owner().unwrap().clone())
        .grants(g.clone())
        .build();
    s3.put_bucket_acl()
        .bucket("acl")
        .access_control_policy(owner_only)
        .send()
        .await
        .unwrap();

    // Anything granting someone else is refused, loudly.
    assert_eq!(
        code(
            s3.put_bucket_acl()
                .bucket("acl")
                .acl(BucketCannedAcl::PublicRead)
                .send()
                .await
        ),
        "AccessControlListNotSupported"
    );
    assert_eq!(
        code(
            s3.put_object_acl()
                .bucket("acl")
                .key("k")
                .grant_read("uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"")
                .send()
                .await
        ),
        "AccessControlListNotSupported"
    );
    let everyone = Grant::builder()
        .grantee(
            Grantee::builder()
                .r#type(Type::Group)
                .uri("http://acs.amazonaws.com/groups/global/AllUsers")
                .build()
                .unwrap(),
        )
        .permission(Permission::Read)
        .build();
    let wide = AccessControlPolicy::builder()
        .owner(ba.owner().unwrap().clone())
        .grants(g.clone())
        .grants(everyone)
        .build();
    assert_eq!(
        code(
            s3.put_object_acl()
                .bucket("acl")
                .key("k")
                .access_control_policy(wide)
                .send()
                .await
        ),
        "AccessControlListNotSupported"
    );

    // ACL headers riding on a write are ignored (apps send public-read on every upload) and
    // do not make the object public.
    s3.put_object()
        .bucket("acl")
        .key("pub")
        .acl(ObjectCannedAcl::PublicRead)
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    let anon = reqwest::get(env.url("/acl/pub")).await.unwrap();
    assert_eq!(anon.status().as_u16(), 403);
    let pa = s3
        .get_object_acl()
        .bucket("acl")
        .key("pub")
        .send()
        .await
        .unwrap();
    assert_eq!(pa.grants().len(), 1);

    // Ownership controls: always BucketOwnerEnforced.
    let oc = s3
        .get_bucket_ownership_controls()
        .bucket("acl")
        .send()
        .await
        .unwrap();
    assert_eq!(
        oc.ownership_controls().unwrap().rules()[0].object_ownership(),
        &ObjectOwnership::BucketOwnerEnforced
    );
    let rule = |o: ObjectOwnership| {
        OwnershipControls::builder()
            .rules(
                OwnershipControlsRule::builder()
                    .object_ownership(o)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    };
    s3.put_bucket_ownership_controls()
        .bucket("acl")
        .ownership_controls(rule(ObjectOwnership::BucketOwnerEnforced))
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(
            s3.put_bucket_ownership_controls()
                .bucket("acl")
                .ownership_controls(rule(ObjectOwnership::ObjectWriter))
                .send()
                .await
        ),
        "InvalidArgument"
    );
}

#[tokio::test]
async fn get_object_attributes_single_and_multipart() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("attrs").await;
    let etag = env.put("attrs", "one", "hello").await;

    let all = [
        ObjectAttributes::Etag,
        ObjectAttributes::ObjectSize,
        ObjectAttributes::StorageClass,
        ObjectAttributes::Checksum,
        ObjectAttributes::ObjectParts,
    ];
    let a = s3
        .get_object_attributes()
        .bucket("attrs")
        .key("one")
        .set_object_attributes(Some(all.to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(a.e_tag(), Some(etag.trim_matches('"')));
    assert_eq!(a.object_size(), Some(5));
    assert_eq!(a.storage_class().map(|s| s.as_str()), Some("STANDARD"));
    assert!(a.object_parts().is_none(), "single PUT has no parts");

    // Only what was asked for comes back.
    let only_size = s3
        .get_object_attributes()
        .bucket("attrs")
        .key("one")
        .object_attributes(ObjectAttributes::ObjectSize)
        .send()
        .await
        .unwrap();
    assert_eq!(only_size.object_size(), Some(5));
    assert!(only_size.e_tag().is_none());

    // Multipart with SHA256: parts, sizes, per-part checksums, pagination.
    let up = s3
        .create_multipart_upload()
        .bucket("attrs")
        .key("mp")
        .checksum_algorithm(ChecksumAlgorithm::Sha256)
        .send()
        .await
        .unwrap();
    let uid = up.upload_id().unwrap().to_string();
    let sizes = [5 * MIB, 5 * MIB, 1234];
    let mut done = CompletedMultipartUpload::builder();
    let mut sums = Vec::new();
    for (i, n) in sizes.iter().enumerate() {
        let p = s3
            .upload_part()
            .bucket("attrs")
            .key("mp")
            .upload_id(&uid)
            .part_number(i as i32 + 1)
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
            .body(ByteStream::from(vec![i as u8; *n]))
            .send()
            .await
            .unwrap();
        sums.push(p.checksum_sha256().unwrap().to_string());
        done = done.parts(
            CompletedPart::builder()
                .part_number(i as i32 + 1)
                .e_tag(p.e_tag().unwrap())
                .checksum_sha256(p.checksum_sha256().unwrap())
                .build(),
        );
    }
    let c = s3
        .complete_multipart_upload()
        .bucket("attrs")
        .key("mp")
        .upload_id(&uid)
        .multipart_upload(done.build())
        .send()
        .await
        .unwrap();

    let a = s3
        .get_object_attributes()
        .bucket("attrs")
        .key("mp")
        .set_object_attributes(Some(all.to_vec()))
        .max_parts(2)
        .send()
        .await
        .unwrap();
    assert_eq!(a.e_tag(), Some(c.e_tag().unwrap().trim_matches('"')));
    assert_eq!(a.object_size(), Some(sizes.iter().sum::<usize>() as i64));
    assert_eq!(a.checksum().unwrap().checksum_sha256(), c.checksum_sha256());
    let parts = a.object_parts().unwrap();
    assert_eq!(parts.total_parts_count(), Some(3));
    assert_eq!(parts.is_truncated(), Some(true));
    assert_eq!(parts.next_part_number_marker(), Some("2"));
    assert_eq!(parts.parts().len(), 2);
    assert_eq!(parts.parts()[1].size(), Some(5 * MIB as i64));
    assert_eq!(parts.parts()[1].checksum_sha256(), Some(sums[1].as_str()));

    let rest = s3
        .get_object_attributes()
        .bucket("attrs")
        .key("mp")
        .object_attributes(ObjectAttributes::ObjectParts)
        .part_number_marker("2")
        .send()
        .await
        .unwrap();
    let parts = rest.object_parts().unwrap();
    assert_eq!(parts.is_truncated(), Some(false));
    assert_eq!(parts.parts().len(), 1);
    assert_eq!(parts.parts()[0].part_number(), Some(3));
    assert_eq!(parts.parts()[0].size(), Some(1234));

    // A part read reports that part's checksum.
    let g = s3
        .get_object()
        .bucket("attrs")
        .key("mp")
        .part_number(2)
        .send()
        .await
        .unwrap();
    assert_eq!(g.checksum_sha256(), Some(sums[1].as_str()));

    assert_eq!(
        code(
            s3.get_object_attributes()
                .bucket("attrs")
                .key("missing")
                .object_attributes(ObjectAttributes::Etag)
                .send()
                .await
        ),
        "NoSuchKey"
    );
}
