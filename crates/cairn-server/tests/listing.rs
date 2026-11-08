//! ListObjects v1/v2 paging over 10k keys with prefix and delimiter.

mod common;
use common::*;
use futures::StreamExt;

#[tokio::test]
async fn ten_thousand_keys_paging_prefix_delimiter() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("many").await;
    let keys: Vec<String> = (0..10_000)
        .map(|i| format!("d{:02}/f{:05}", i % 50, i))
        .chain((0..20).map(|i| format!("top-{i:02}")))
        .collect();
    futures::stream::iter(keys.iter().cloned())
        .for_each_concurrent(64, |k| {
            let s3 = s3.clone();
            async move {
                s3.put_object()
                    .bucket("many")
                    .key(k)
                    .body(aws_sdk_s3::primitives::ByteStream::from_static(b"x"))
                    .send()
                    .await
                    .unwrap();
            }
        })
        .await;
    let mut sorted = keys.clone();
    sorted.sort();

    // V2 full scan with continuation tokens.
    let mut seen = Vec::new();
    let mut token = None;
    let mut pages = 0;
    loop {
        let r = s3
            .list_objects_v2()
            .bucket("many")
            .set_continuation_token(token.clone())
            .send()
            .await
            .unwrap();
        pages += 1;
        assert!(r.contents().len() <= 1000);
        seen.extend(r.contents().iter().map(|o| o.key().unwrap().to_string()));
        if r.is_truncated() != Some(true) {
            break;
        }
        token = r.next_continuation_token().map(str::to_string);
    }
    assert_eq!(pages, 11);
    assert_eq!(seen, sorted);

    // Delimiter at the root: 50 common prefixes + 20 top-level keys.
    let r = s3
        .list_objects_v2()
        .bucket("many")
        .delimiter("/")
        .send()
        .await
        .unwrap();
    assert_eq!(r.common_prefixes().len(), 50);
    assert_eq!(r.contents().len(), 20);
    assert_eq!(r.key_count(), Some(70));

    // Delimiter paging: common prefixes count against max-keys.
    let mut cps = Vec::new();
    let mut objs = 0;
    let mut token = None;
    loop {
        let r = s3
            .list_objects_v2()
            .bucket("many")
            .delimiter("/")
            .max_keys(7)
            .set_continuation_token(token.clone())
            .send()
            .await
            .unwrap();
        assert!(r.key_count().unwrap() <= 7);
        cps.extend(
            r.common_prefixes()
                .iter()
                .map(|p| p.prefix().unwrap().to_string()),
        );
        objs += r.contents().len();
        if r.is_truncated() != Some(true) {
            break;
        }
        token = r.next_continuation_token().map(str::to_string);
    }
    assert_eq!(cps.len(), 50);
    assert_eq!(objs, 20);

    // Prefix + start-after.
    let r = s3
        .list_objects_v2()
        .bucket("many")
        .prefix("d07/")
        .start_after("d07/f05000")
        .send()
        .await
        .unwrap();
    let want: Vec<_> = sorted
        .iter()
        .filter(|k| k.starts_with("d07/") && k.as_str() > "d07/f05000")
        .cloned()
        .collect();
    let got: Vec<_> = r
        .contents()
        .iter()
        .map(|o| o.key().unwrap().to_string())
        .collect();
    assert_eq!(got, want);
    assert_eq!(r.contents()[0].size(), Some(1));
    assert_eq!(
        r.contents()[0].storage_class().map(|s| s.as_str()),
        Some("STANDARD")
    );

    // V1 with marker paging under a prefix.
    let mut seen = Vec::new();
    let mut marker: Option<String> = None;
    loop {
        let r = s3
            .list_objects()
            .bucket("many")
            .prefix("d1")
            .max_keys(333)
            .set_marker(marker.clone())
            .send()
            .await
            .unwrap();
        seen.extend(r.contents().iter().map(|o| o.key().unwrap().to_string()));
        if r.is_truncated() != Some(true) {
            break;
        }
        marker = r
            .next_marker()
            .map(str::to_string)
            .or_else(|| seen.last().cloned());
    }
    let want: Vec<_> = sorted
        .iter()
        .filter(|k| k.starts_with("d1"))
        .cloned()
        .collect();
    assert_eq!(seen, want);

    // URL encoding-type.
    env.put("many", "sp ace+&", "x").await;
    let r = s3
        .list_objects_v2()
        .bucket("many")
        .prefix("sp")
        .encoding_type(aws_sdk_s3::types::EncodingType::Url)
        .send()
        .await
        .unwrap();
    assert_eq!(r.contents()[0].key(), Some("sp%20ace%2B%26"));
    env.stop().await;
}
