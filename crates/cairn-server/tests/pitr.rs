//! Soft delete, shadow versions and time travel via `x-cairn-as-of`.

mod common;
use common::*;

fn now_nanos() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    d.as_nanos().to_string()
}

#[tokio::test]
async fn soft_delete_then_time_travel_read() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("ttx").await;
    env.put("ttx", "doc", "version one").await;
    env.put("ttx", "other", "unrelated").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let t1 = now_nanos();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    env.put("ttx", "doc", "version two").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let t2 = now_nanos();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    s3.delete_object()
        .bucket("ttx")
        .key("doc")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(s3.get_object().bucket("ttx").key("doc").send().await),
        "NoSuchKey"
    );

    let as_of = |t: String| {
        move |req: &mut aws_sdk_s3::config::http::HttpRequest| {
            req.headers_mut().insert("x-cairn-as-of", t.clone());
        }
    };
    let read_at = |t: String| {
        let s3 = s3.clone();
        async move {
            s3.get_object()
                .bucket("ttx")
                .key("doc")
                .customize()
                .mutate_request(as_of(t))
                .send()
                .await
        }
    };
    let g = read_at(t1.clone()).await.unwrap();
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes().as_ref(),
        b"version one"
    );
    let g = read_at(t2.clone()).await.unwrap();
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes().as_ref(),
        b"version two"
    );
    assert_eq!(code(read_at(now_nanos()).await), "NoSuchKey");

    // HEAD and ListObjectsV2 honour the header too.
    let h = s3
        .head_object()
        .bucket("ttx")
        .key("doc")
        .customize()
        .mutate_request(as_of(t1.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_length(), Some(11));
    let l = s3
        .list_objects_v2()
        .bucket("ttx")
        .customize()
        .mutate_request(as_of(t2.clone()))
        .send()
        .await
        .unwrap();
    let keys: Vec<_> = l.contents().iter().map(|o| o.key().unwrap()).collect();
    assert_eq!(keys, vec!["doc", "other"]);
    let l = s3.list_objects_v2().bucket("ttx").send().await.unwrap();
    assert_eq!(l.contents().len(), 1);

    // RFC 3339 form is accepted; garbage is rejected.
    let g = read_at("2000-01-01T00:00:00Z".into()).await;
    assert_eq!(code(g), "NoSuchKey");
    assert_eq!(code(read_at("yesterday".into()).await), "InvalidArgument");

    // x-cairn-include-trash lists soft-deleted and superseded versions.
    let lv = s3
        .list_object_versions()
        .bucket("ttx")
        .prefix("doc")
        .customize()
        .mutate_request(|r| {
            r.headers_mut().insert("x-cairn-include-trash", "true");
        })
        .send()
        .await
        .unwrap();
    assert_eq!(lv.versions().len(), 2);
    let lv = s3
        .list_object_versions()
        .bucket("ttx")
        .prefix("doc")
        .send()
        .await
        .unwrap();
    assert!(lv.versions().is_empty());
    env.stop().await;
}
