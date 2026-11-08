//! Replication: XML model, engine → engine round trip (objects, multipart, delete markers,
//! metadata, tags, version ids), filters, durable cursor across restart, idempotent re-delivery,
//! backoff and permanent failures, target registry. The HTTP round trip between two in-process
//! servers is `two_server_http_round_trip` (ignored, see its doc comment).

mod support3b;

use async_trait::async_trait;
use cairn_blob::remote_s3::S3Endpoint;
use cairn_core::{S3ErrorCode, Ts};
use cairn_engine::cairn_meta::{MetaStore, Reader, Table, VersionRecord};
use cairn_engine::replication::*;
use cairn_engine::{CairnEngine, ListReq, ListVersionsReq, ObjectMeta};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support3b::*;

const DEST: &str = "arn:aws:s3:::dst";

fn all_rule(existing: bool) -> String {
    format!(
        r#"<ReplicationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Role>arn:aws:iam::123456789012:role/replication</Role>
  <Rule>
    <ID>everything</ID><Priority>1</Priority><Status>Enabled</Status>
    <Filter><Prefix></Prefix></Filter>
    <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication>
    <Destination><Bucket>{DEST}</Bucket></Destination>
    <ExistingObjectReplication><Status>{}</Status></ExistingObjectReplication>
  </Rule>
</ReplicationConfiguration>"#,
        if existing { "Enabled" } else { "Disabled" }
    )
}

#[test]
fn xml_round_trip_and_validation() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ReplicationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Role>arn:aws:iam::1:role/r</Role>
  <Rule>
    <ID>docs &amp; logs</ID>
    <Priority>2</Priority>
    <Status>Enabled</Status>
    <Filter><And><Prefix>docs/</Prefix><Tag><Key>team</Key><Value>a</Value></Tag><Tag><Key>tier</Key><Value>gold</Value></Tag></And></Filter>
    <DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>
    <Destination><Bucket>arn:aws:s3:::backup</Bucket><Account>2</Account><StorageClass>STANDARD_IA</StorageClass></Destination>
    <ExistingObjectReplication><Status>Enabled</Status></ExistingObjectReplication>
  </Rule>
  <Rule>
    <Status>Disabled</Status>
    <Prefix>legacy/</Prefix>
    <Destination><Bucket>arn:aws:s3:::old</Bucket></Destination>
  </Rule>
  <Rule>
    <ID>tagged</ID><Priority>1</Priority><Status>Enabled</Status>
    <Filter><Tag><Key>replicate</Key><Value>yes</Value></Tag></Filter>
    <DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>
    <Destination><Bucket>arn:aws:s3:::backup</Bucket></Destination>
  </Rule>
</ReplicationConfiguration>"#;
    let c = ReplicationConfiguration::from_xml(xml).unwrap();
    assert_eq!(c.rules.len(), 3);
    let r0 = &c.rules[0];
    assert_eq!(r0.id.as_deref(), Some("docs & logs"));
    assert_eq!(r0.priority, Some(2));
    let f = r0.filter.as_ref().unwrap();
    assert_eq!(f.prefix.as_deref(), Some("docs/"));
    assert_eq!(f.tags.len(), 2);
    assert_eq!(r0.destination.bucket_name(), "backup");
    assert_eq!(r0.destination.storage_class.as_deref(), Some("STANDARD_IA"));
    assert_eq!(r0.existing_object_replication, Some(true));
    assert_eq!(c.rules[1].prefix.as_deref(), Some("legacy/"));
    assert!(!c.rules[1].enabled);
    assert!(
        c.rules[1].replicates_delete_markers(),
        "V1 rules replicate delete markers"
    );
    let again = ReplicationConfiguration::from_xml(&c.to_xml()).unwrap();
    assert_eq!(again, c);
    assert_eq!(c.destinations(), vec!["arn:aws:s3:::backup".to_string()]);

    let tags: BTreeMap<String, String> = [("team", "a"), ("tier", "gold")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    assert!(r0.matches("docs/x", Some(&tags)));
    assert!(!r0.matches("img/x", Some(&tags)));
    assert!(!r0.matches("docs/x", None));

    for bad in [
        "<ReplicationConfiguration/>",
        "<NotIt><Rule/></NotIt>",
        "<ReplicationConfiguration><Rule><Status>Enabled</Status></Rule></ReplicationConfiguration>",
        "<ReplicationConfiguration><Rule><Status>On</Status><Destination><Bucket>arn:aws:s3:::x</Bucket></Destination></Rule></ReplicationConfiguration>",
        "<ReplicationConfiguration><Rule><Status>Enabled</Status><Destination><Bucket>nope</Bucket></Destination></Rule></ReplicationConfiguration>",
        "<ReplicationConfiguration><Rule><Status>Enabled</Status><Filter/><Destination><Bucket>arn:aws:s3:::x</Bucket></Destination></Rule></ReplicationConfiguration>",
        "<ReplicationConfiguration><Rule><ID>a</ID><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::x</Bucket></Destination></Rule><Rule><ID>a</ID><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::y</Bucket></Destination></Rule></ReplicationConfiguration>",
        "<ReplicationConfiguration><Rule><Priority>1</Priority><Status>Enabled</Status><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication><Destination><Bucket>arn:aws:s3:::x</Bucket></Destination></Rule></ReplicationConfiguration>",
        "<!DOCTYPE x><ReplicationConfiguration/>",
    ] {
        assert!(ReplicationConfiguration::from_xml(bad).is_err(), "{bad}");
    }
}

struct Pair {
    _d1: tempfile::TempDir,
    _d2: tempfile::TempDir,
    src: CairnEngine,
    dst: CairnEngine,
    registry: Arc<TargetRegistry>,
}

async fn pair() -> Pair {
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let src = open(d1.path());
    let dst = open(d2.path());
    bucket(&src, "src", true).await;
    bucket(&dst, "dst", true).await;
    let registry = Arc::new(TargetRegistry::new(&src, [5u8; 32]));
    registry.register(DEST, Arc::new(EngineTarget::new(dst.clone(), "dst")));
    Pair {
        _d1: d1,
        _d2: d2,
        src,
        dst,
        registry,
    }
}

fn versions(e: &CairnEngine, b: &str) -> Vec<(String, String, bool)> {
    let r = e
        .list_object_versions(
            b,
            &ListVersionsReq {
                list: ListReq {
                    max: 1000,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    r.objects
        .into_iter()
        .map(|o| {
            (
                o.version.key.clone(),
                o.version_id,
                o.version.is_delete_marker(),
            )
        })
        .collect()
}

#[tokio::test]
async fn engine_to_engine_round_trip() {
    let p = pair().await;
    p.src
        .put_bucket_replication("src", &all_rule(true))
        .await
        .unwrap();
    let meta = ObjectMeta {
        content_type: Some("text/plain".into()),
        user_metadata: [("origin".to_string(), "lab".to_string())].into(),
        ..Default::default()
    };
    let tags: BTreeMap<String, String> = [("k".to_string(), "v".to_string())].into();
    let a1 = put_meta(&p.src, "src", "a.txt", b"first", meta.clone(), tags.clone()).await;
    put(&p.src, "src", "a.txt", b"second").await;
    let parts = vec![data(6000, 1), data(6000, 2), data(10, 3)];
    let mp = put_multipart(&p.src, "src", "big/mp.bin", &parts).await;
    put(&p.src, "src", "gone", b"bye").await;
    let dm = p
        .src
        .delete_object("src", "gone", None, &root())
        .await
        .unwrap();
    assert!(dm.delete_marker);

    let w = ReplicationWorker::new(p.src.clone(), p.registry.clone());
    let st = w.tick().await.unwrap();
    assert_eq!(st.delivered, 5, "{st:#?}");
    assert_eq!(st.destinations[0].pending, 0);
    assert_eq!(st.destinations[0].lag, Duration::ZERO);

    assert_eq!(
        versions(&p.src, "src"),
        versions(&p.dst, "dst"),
        "same version ids"
    );
    assert_eq!(get(&p.dst, "dst", "a.txt").await.unwrap(), b"second");
    let (old, res) = get_version(&p.dst, "dst", "a.txt", a1.version_id.clone())
        .await
        .unwrap();
    assert_eq!(old, b"first");
    let body = res.version.body().unwrap();
    assert_eq!(body.content_type.as_deref(), Some("text/plain"));
    assert_eq!(
        body.user_metadata.get("origin").map(String::as_str),
        Some("lab")
    );
    assert_eq!(body.tags, tags);
    let (big, res) = get_version(&p.dst, "dst", "big/mp.bin", None)
        .await
        .unwrap();
    assert_eq!(big, parts.concat());
    assert_eq!(
        res.version.body().unwrap().etag,
        mp.etag,
        "multipart ETag preserved"
    );
    assert!(res.version.body().unwrap().etag.ends_with("-3"));
    assert_eq!(
        get(&p.dst, "dst", "gone").await.unwrap_err(),
        S3ErrorCode::NoSuchKey,
        "delete marker replicated"
    );

    let b = p.src.bucket("src").unwrap();
    assert_eq!(
        p.src.replication_status(&b, &a1.version).unwrap(),
        Some(ReplicationStatus::Completed)
    );
    let later = put(&p.src, "src", "later", b"x").await;
    assert_eq!(
        p.src.replication_status(&b, &later.version).unwrap(),
        Some(ReplicationStatus::Pending)
    );
    let st = w.tick().await.unwrap();
    assert_eq!(st.delivered, 1);
    assert_eq!(w.tick().await.unwrap().delivered, 0, "nothing new");
    let f = p.dst.fsck(Default::default()).await.unwrap();
    assert!(f.is_clean(), "{f:#?}");
}

#[tokio::test]
async fn existing_objects_and_filters() {
    let p = pair().await;
    put(&p.src, "src", "before", b"pre-existing").await;
    let xml = format!(
        r#"<ReplicationConfiguration>
  <Rule><ID>logs</ID><Priority>1</Priority><Status>Enabled</Status>
    <Filter><Prefix>logs/</Prefix></Filter>
    <DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>
    <Destination><Bucket>{DEST}</Bucket></Destination></Rule>
  <Rule><ID>tagged</ID><Priority>2</Priority><Status>Enabled</Status>
    <Filter><Tag><Key>replicate</Key><Value>yes</Value></Tag></Filter>
    <DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>
    <Destination><Bucket>{DEST}</Bucket></Destination></Rule>
</ReplicationConfiguration>"#
    );
    p.src.put_bucket_replication("src", &xml).await.unwrap();
    put(&p.src, "src", "logs/1", b"log").await;
    put(&p.src, "src", "other/1", b"skip me").await;
    let yes: BTreeMap<String, String> = [("replicate".to_string(), "yes".to_string())].into();
    put_meta(
        &p.src,
        "src",
        "other/2",
        b"tagged",
        ObjectMeta::default(),
        yes,
    )
    .await;
    p.src
        .delete_object("src", "logs/1", None, &root())
        .await
        .unwrap();
    let w = ReplicationWorker::new(p.src.clone(), p.registry.clone());
    let st = w.tick().await.unwrap();
    assert_eq!(st.delivered, 2);
    assert_eq!(st.skipped, 2, "untagged object and disabled delete marker");
    let keys: Vec<String> = versions(&p.dst, "dst").into_iter().map(|v| v.0).collect();
    assert_eq!(keys, vec!["logs/1".to_string(), "other/2".to_string()]);
    assert!(
        get(&p.dst, "dst", "before").await.is_err(),
        "existing objects not replicated"
    );
    let b = p.src.bucket("src").unwrap();
    let before = get_version(&p.src, "src", "before", None).await.unwrap().1;
    assert_eq!(
        p.src.replication_status(&b, &before.version).unwrap(),
        None,
        "pre-existing objects are not replicated, so they carry no status"
    );
    assert_eq!(get(&p.dst, "dst", "logs/1").await.unwrap(), b"log");
}

#[tokio::test]
async fn requires_versioning_and_round_trips_config() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    bucket(&e, "plain", false).await;
    let err = e
        .put_bucket_replication("plain", &all_rule(false))
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::InvalidRequest);
    bucket(&e, "ver", true).await;
    assert!(e.get_bucket_replication("ver").unwrap().is_none());
    e.put_bucket_replication("ver", &all_rule(false))
        .await
        .unwrap();
    let got = e.get_bucket_replication("ver").unwrap().unwrap();
    assert_eq!(
        got,
        ReplicationConfiguration::from_xml(&all_rule(false)).unwrap()
    );
    let id = e.bucket("ver").unwrap().id;
    assert!(
        load_cursor(&e.meta().read().unwrap(), id, DEST)
            .unwrap()
            .is_some()
    );
    e.delete_bucket_replication("ver").await.unwrap();
    assert!(e.get_bucket_replication("ver").unwrap().is_none());
    assert!(
        load_cursor(&e.meta().read().unwrap(), id, DEST)
            .unwrap()
            .is_none()
    );
}

/// Counts deliveries; fails transiently while `fail_transient > 0`, permanently for keys
/// starting with `poison`.
#[derive(Default)]
struct Fake {
    delivered: Mutex<Vec<String>>,
    fail_transient: AtomicUsize,
}

#[async_trait]
impl ReplicationTarget for Fake {
    async fn replicate_object(
        &self,
        v: &VersionRecord,
        data: &dyn PartSource,
    ) -> Result<(), ReplError> {
        if self.fail_transient.load(Ordering::SeqCst) > 0 {
            self.fail_transient.fetch_sub(1, Ordering::SeqCst);
            return Err(ReplError::Transient("503 SlowDown".into()));
        }
        if v.key.starts_with("poison") {
            return Err(ReplError::Permanent("400 InvalidArgument".into()));
        }
        drop(data.open_part(0).await?);
        self.delivered.lock().unwrap().push(v.key.clone());
        Ok(())
    }
    async fn replicate_delete_marker(&self, v: &VersionRecord) -> Result<(), ReplError> {
        self.delivered.lock().unwrap().push(format!("dm:{}", v.key));
        Ok(())
    }
}

#[derive(Default)]
struct Lag(Mutex<Vec<DestinationStatus>>);

impl ReplicationObserver for Lag {
    fn observe(&self, s: &DestinationStatus) {
        self.0.lock().unwrap().push(s.clone());
    }
}

#[tokio::test]
async fn cursor_survives_restart_and_redelivery_is_idempotent() {
    let d = tempfile::tempdir().unwrap();
    let dd = tempfile::tempdir().unwrap();
    let fake = Arc::new(Fake::default());
    let settings = ReplicationSettings {
        batch: 2,
        checkpoint_every: 1,
        ..Default::default()
    };
    {
        let src = open(d.path());
        bucket(&src, "src", true).await;
        src.put_bucket_replication("src", &all_rule(false))
            .await
            .unwrap();
        for k in ["k1", "k2", "k3"] {
            put(&src, "src", k, k.as_bytes()).await;
        }
        let reg = Arc::new(TargetRegistry::new(&src, [1u8; 32]));
        reg.register(DEST, fake.clone());
        let w = ReplicationWorker::with_settings(src.clone(), reg, settings.clone());
        let st = w.tick().await.unwrap();
        assert_eq!(st.delivered, 2);
        assert_eq!(st.destinations[0].pending, 1);
        assert!(st.destinations[0].lag > Duration::ZERO);
        drop(w);
        src.shutdown();
    }
    let src = open(d.path());
    let reg = Arc::new(TargetRegistry::new(&src, [1u8; 32]));
    reg.register(DEST, fake.clone());
    let w = ReplicationWorker::with_settings(src.clone(), reg.clone(), settings);
    let st = w.tick().await.unwrap();
    assert_eq!(st.delivered, 1, "resumed after restart");
    assert_eq!(*fake.delivered.lock().unwrap(), vec!["k1", "k2", "k3"]);

    // Lose the cursor (crash before checkpoint): an engine target dedupes by version id.
    let dst = open(dd.path());
    bucket(&dst, "dst", true).await;
    reg.register(DEST, Arc::new(EngineTarget::new(dst.clone(), "dst")));
    let id = src.bucket("src").unwrap().id;
    let reset = |src: CairnEngine| async move {
        src.meta()
            .write(move |txn| {
                let c = ReplCursor {
                    watermark: None,
                    ..Default::default()
                };
                let mut k = id.to_bytes().to_vec();
                k.extend_from_slice(DEST.as_bytes());
                txn.put(Table::ReplCursor, &k, &cairn_engine::cairn_meta::encode(&c))
            })
            .await
            .unwrap();
    };
    reset(src.clone()).await;
    while w.tick().await.unwrap().delivered > 0 {}
    reset(src.clone()).await;
    while w.tick().await.unwrap().delivered > 0 {}
    assert_eq!(
        versions(&dst, "dst").len(),
        3,
        "re-delivery created no duplicates"
    );
}

#[tokio::test]
async fn backoff_permanent_failures_and_lag_hook() {
    let d = tempfile::tempdir().unwrap();
    let src = open(d.path());
    bucket(&src, "src", true).await;
    src.put_bucket_replication("src", &all_rule(false))
        .await
        .unwrap();
    put(&src, "src", "a", b"1").await;
    put(&src, "src", "poison", b"2").await;
    put(&src, "src", "z", b"3").await;
    let fake = Arc::new(Fake::default());
    fake.fail_transient.store(1, Ordering::SeqCst);
    let reg = Arc::new(TargetRegistry::new(&src, [1u8; 32]));
    reg.register(DEST, fake.clone());
    let lag = Arc::new(Lag::default());
    let w = ReplicationWorker::with_settings(
        src.clone(),
        reg,
        ReplicationSettings {
            backoff_base: Duration::from_secs(3600),
            ..Default::default()
        },
    )
    .with_observer(lag.clone());
    let st = w.tick().await.unwrap();
    assert_eq!(st.transient_errors, 1);
    assert!(st.destinations[0].backing_off);
    assert_eq!(st.destinations[0].pending, 3);
    let st = w.tick().await.unwrap();
    assert_eq!(st.delivered, 0, "still backing off");
    assert!(st.destinations[0].backing_off);
    w.reset_backoff();
    let st = w.tick().await.unwrap();
    assert_eq!(st.delivered, 2);
    assert_eq!(st.failed, 1);
    assert_eq!(*fake.delivered.lock().unwrap(), vec!["a", "z"]);
    let id = src.bucket("src").unwrap().id;
    let c = load_cursor(&src.meta().read().unwrap(), id, DEST)
        .unwrap()
        .unwrap();
    assert_eq!((c.delivered, c.failed), (2, 1));
    assert!(c.last_error.unwrap().contains("InvalidArgument"));
    let seen = lag.0.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert!(seen[0].last_error.as_deref().unwrap().contains("SlowDown"));
    assert_eq!(seen[2].pending, 0);
}

#[tokio::test]
async fn unknown_target_backs_off() {
    let d = tempfile::tempdir().unwrap();
    let src = open(d.path());
    bucket(&src, "src", true).await;
    src.put_bucket_replication("src", &all_rule(false))
        .await
        .unwrap();
    put(&src, "src", "a", b"1").await;
    let reg = Arc::new(TargetRegistry::new(&src, [1u8; 32]));
    let w = ReplicationWorker::new(src.clone(), reg);
    let st = w.tick().await.unwrap();
    assert_eq!(st.transient_errors, 1);
    assert!(
        st.destinations[0]
            .last_error
            .as_deref()
            .unwrap()
            .contains("no replication target")
    );
}

#[tokio::test]
async fn target_registry_seals_secrets() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    let reg = TargetRegistry::new(&e, [3u8; 32]);
    let cfg = TargetConfig {
        arn: "arn:aws:s3:::remote".into(),
        endpoint: S3Endpoint {
            endpoint: Some("https://replica.example.com".into()),
            region: "eu-west-1".into(),
            bucket: "remote".into(),
            prefix: String::new(),
            access_key: "AKIAREPLICA".into(),
            secret_key: "super-secret-value-123".into(),
            path_style: true,
        },
        cairn_peer: true,
    };
    assert!(!format!("{cfg:?}").contains("super-secret"));
    reg.put(&cfg).await.unwrap();
    let list = reg.list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].access_key, "AKIAREPLICA");
    let r = e.meta().read().unwrap();
    let mut raw = Vec::new();
    r.scan_prefix(Table::Kv, TARGET_PREFIX, &mut |_, v| {
        raw.extend_from_slice(v);
        Ok(cairn_engine::cairn_meta::Flow::Continue)
    })
    .unwrap();
    assert!(
        !raw.windows(12).any(|w| w == b"super-secret"),
        "secret sealed at rest"
    );
    assert!(reg.resolve("arn:aws:s3:::remote").unwrap().is_some());
    assert!(reg.resolve("arn:aws:s3:::none").unwrap().is_none());
    let other_key = TargetRegistry::new(&e, [4u8; 32]);
    assert!(
        other_key.resolve("arn:aws:s3:::remote").is_err(),
        "wrong sealing key"
    );
    assert!(reg.remove("arn:aws:s3:::remote").await.unwrap());
    assert!(reg.list().unwrap().is_empty());
}

#[tokio::test]
async fn put_replica_rejects_mismatched_data_and_unversioned_bucket() {
    let p = pair().await;
    let v = put(&p.src, "src", "k", b"payload").await.version;
    struct Wrong;
    #[async_trait]
    impl PartSource for Wrong {
        async fn open_part(&self, _: usize) -> Result<cairn_blob::BlobReader, ReplError> {
            Err(ReplError::Permanent("no".into()))
        }
    }
    assert!(p.dst.put_replica("dst", &v, Some(&Wrong)).await.is_err());
    let other = EnginePartSource::new(&p.src, &put(&p.src, "src", "o", b"other!!").await.version);
    let err = p
        .dst
        .put_replica("dst", &v, Some(&other))
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::BadDigest);
    bucket(&p.dst, "flat", false).await;
    let src = EnginePartSource::new(&p.src, &v);
    assert!(p.dst.put_replica("flat", &v, Some(&src)).await.is_err());
    assert!(p.dst.put_replica("dst", &v, Some(&src)).await.unwrap());
    assert!(
        !p.dst.put_replica("dst", &v, Some(&src)).await.unwrap(),
        "idempotent"
    );
    let f = p.dst.fsck(Default::default()).await.unwrap();
    assert!(f.is_clean(), "failed replicas leave no garbage: {f:#?}");
    let _ = Ts::now();
}

/// Two-server HTTP round trip (Cairn → Cairn over aws-sdk-s3 with `x-cairn-version-id`).
///
/// TODO(Agent A): move into `crates/cairn-server/tests/replication.rs` using
/// `cairn_server::test_support::spawn` twice once cairn-s3 maps PUT/DELETE/Complete carrying
/// `x-cairn-version-id` to `CairnEngine::put_replica` and Put/Get/DeleteBucketReplication to the
/// engine. Until then it runs against two already-running servers:
/// `CAIRN_REPL_SRC=http://… CAIRN_REPL_DST=http://… CAIRN_REPL_AK=… CAIRN_REPL_SK=…
/// cargo test -p cairn-engine --test replication -- --ignored`.
#[tokio::test]
#[ignore = "needs two running Cairn servers (see doc comment); Agent A moves it to cairn-server tests"]
async fn two_server_http_round_trip() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
    let ep = |url: String, bucket: &str| S3Endpoint {
        endpoint: Some(url),
        region: "us-east-1".into(),
        bucket: bucket.into(),
        prefix: String::new(),
        access_key: env("CAIRN_REPL_AK"),
        secret_key: env("CAIRN_REPL_SK"),
        path_style: true,
    };
    let d = tempfile::tempdir().unwrap();
    let src = open(d.path());
    bucket(&src, "src", true).await;
    src.put_bucket_replication("src", &all_rule(true))
        .await
        .unwrap();
    let v = put(&src, "src", "hello", b"over http").await;
    put_multipart(&src, "src", "mp", &[data(6 << 20, 1), data(1000, 2)]).await;
    src.delete_object("src", "hello", None, &root())
        .await
        .unwrap();
    let reg = Arc::new(TargetRegistry::new(&src, [9u8; 32]));
    let dst = ep(env("CAIRN_REPL_DST"), "dst");
    reg.register(
        DEST,
        Arc::new(S3Target::new(&dst, true, &d.path().join("tmp"))),
    );
    let st = ReplicationWorker::new(src.clone(), reg)
        .tick()
        .await
        .unwrap();
    assert_eq!(st.delivered, 4, "{st:#?}");
    let c = cairn_blob::remote_s3::build_client(&dst);
    let got = c
        .get_object()
        .bucket("dst")
        .key("hello")
        .version_id(v.version_id.clone().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.body.collect().await.unwrap().into_bytes().as_ref(),
        b"over http"
    );
    let _ = env("CAIRN_REPL_SRC");
}
