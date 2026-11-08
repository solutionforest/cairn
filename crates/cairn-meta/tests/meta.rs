use cairn_core::{BucketId, PrincipalId, Ts, VersionId};
use cairn_meta::list::{Entry, ListParams, VersionParams, list_as_of, list_latest, list_versions};
use cairn_meta::pitr::head_at;
use cairn_meta::*;
use proptest::prelude::*;
use std::collections::BTreeMap;

fn store() -> (tempfile::TempDir, RedbMetaStore) {
    let d = tempfile::tempdir().unwrap();
    let s = RedbMetaStore::open(&d.path().join("meta/cairn.redb")).unwrap();
    (d, s)
}

fn obj(key: &str, at: i128, is_null: bool) -> VersionRecord {
    VersionRecord {
        key: key.into(),
        version_id: VersionId::new(Ts(at)),
        created_at: Ts(at),
        is_null,
        kind: VersionKind::Object(Box::new(ObjectBody {
            size: 1,
            etag: "e".into(),
            ..Default::default()
        })),
        state: VersionState::Live,
        lock: None,
        legal_hold: false,
        owner: PrincipalId::root(),
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[tokio::test]
async fn write_then_read_and_failed_job_isolated() {
    let (_d, s) = store();
    let b = BucketId(7);
    let mut handles = Vec::new();
    for i in 0..50 {
        let s2 = s.clone();
        handles.push(tokio::spawn(async move {
            s2.write(move |t| -> Result<(), MetaError> {
                let key = format!("k{i:02}");
                if i == 13 {
                    t.put_version(b, &obj("poison", 1, false))?;
                    return Err(MetaError::Corrupt("deliberate".into()));
                }
                t.put_version(b, &obj(&key, i as i128 + 1, false))?;
                t.refresh_latest(b, &key)?;
                Ok(())
            })
            .await
        }));
    }
    let mut errs = 0;
    for h in handles {
        if h.await.unwrap().is_err() {
            errs += 1;
        }
    }
    assert_eq!(errs, 1);
    let r = s.read().unwrap();
    let page = list_latest(
        &r,
        b,
        &ListParams {
            max: 1000,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(page.entries.len(), 49);
    assert!(
        r.versions_of(b, "poison").unwrap().is_empty(),
        "failed job must not commit"
    );
    s.shutdown();
}

async fn put_keys(s: &RedbMetaStore, b: BucketId, keys: &[&str]) {
    let keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    s.write(move |t| -> Result<(), MetaError> {
        for (i, k) in keys.iter().enumerate() {
            t.put_version(b, &obj(k, i as i128 + 1, true))?;
            t.refresh_latest(b, k)?;
        }
        Ok(())
    })
    .await
    .unwrap();
}

fn names(p: &cairn_meta::list::Page) -> Vec<String> {
    p.entries
        .iter()
        .map(|e| match e {
            Entry::Object { version, .. } => version.key.clone(),
            Entry::Prefix(p) => format!("{p}*"),
        })
        .collect()
}

#[tokio::test]
async fn list_prefix_delimiter_and_pagination() {
    let (_d, s) = store();
    let b = BucketId(1);
    let other = BucketId(2);
    put_keys(
        &s,
        b,
        &[
            "a.txt",
            "photos/2024/a.jpg",
            "photos/2024/b.jpg",
            "photos/2025/c.jpg",
            "photos/x.jpg",
            "z",
        ],
    )
    .await;
    put_keys(&s, other, &["a.txt", "photos/q"]).await;
    let r = s.read().unwrap();
    let all = list_latest(
        &r,
        b,
        &ListParams {
            max: 100,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(all.entries.len(), 6);
    let top = list_latest(
        &r,
        b,
        &ListParams {
            delimiter: Some("/"),
            max: 100,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(names(&top), ["a.txt", "photos/*", "z"]);
    let sub = list_latest(
        &r,
        b,
        &ListParams {
            prefix: "photos/",
            delimiter: Some("/"),
            max: 100,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        names(&sub),
        ["photos/2024/*", "photos/2025/*", "photos/x.jpg"]
    );
    let p1 = list_latest(
        &r,
        b,
        &ListParams {
            delimiter: Some("/"),
            max: 2,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(names(&p1), ["a.txt", "photos/*"]);
    assert!(p1.truncated);
    assert_eq!(p1.next_key.as_deref(), Some("photos/"));
    let p2 = list_latest(
        &r,
        b,
        &ListParams {
            delimiter: Some("/"),
            max: 2,
            after: p1.next_key.as_deref(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(names(&p2), ["z"]);
    assert!(!p2.truncated);
    let after = list_latest(
        &r,
        b,
        &ListParams {
            prefix: "photos/",
            after: Some("photos/2024/a.jpg"),
            max: 100,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        names(&after),
        ["photos/2024/b.jpg", "photos/2025/c.jpg", "photos/x.jpg"]
    );
    let exact = list_latest(
        &r,
        b,
        &ListParams {
            max: 3,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(exact.truncated);
    let none = list_latest(
        &r,
        b,
        &ListParams {
            max: 6,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!none.truncated);
}

#[tokio::test]
async fn versions_listing_hides_trash_unless_asked() {
    let (_d, s) = store();
    let b = BucketId(3);
    let v1 = obj("k", 10, false);
    let mut v2 = obj("k", 20, false);
    v2.state = VersionState::SoftDeleted {
        at: Ts(30),
        by: PrincipalId::root(),
        reason: DeleteReason::Api,
    };
    let v3 = obj("k", 40, false);
    let l = obj("l", 50, false);
    let recs = vec![v1.clone(), v2.clone(), v3.clone(), l.clone()];
    s.write(move |t| -> Result<(), MetaError> {
        for v in &recs {
            t.put_version(b, v)?;
            t.refresh_latest(b, &v.key)?;
        }
        Ok(())
    })
    .await
    .unwrap();
    let r = s.read().unwrap();
    let vis = list_versions(
        &r,
        b,
        &VersionParams {
            list: ListParams {
                max: 100,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    let ids: Vec<_> = vis
        .entries
        .iter()
        .map(|e| match e {
            Entry::Object { version, is_latest } => (version.version_id, *is_latest),
            _ => panic!(),
        })
        .collect();
    assert_eq!(
        ids,
        vec![
            (v3.version_id, true),
            (v1.version_id, false),
            (l.version_id, true)
        ]
    );
    let all = list_versions(
        &r,
        b,
        &VersionParams {
            list: ListParams {
                max: 100,
                ..Default::default()
            },
            include_trash: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(all.entries.len(), 4);
    let p1 = list_versions(
        &r,
        b,
        &VersionParams {
            list: ListParams {
                max: 1,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    assert!(p1.truncated);
    assert_eq!(p1.next_version, Some(v3.version_id));
    let p2 = list_versions(
        &r,
        b,
        &VersionParams {
            list: ListParams {
                max: 5,
                after: Some("k"),
                ..Default::default()
            },
            version_after: p1.next_version,
            include_trash: false,
        },
    )
    .unwrap();
    assert_eq!(p2.entries.len(), 2);
    assert_eq!(
        head_at(&r, b, "k", Ts(25)).unwrap().unwrap().version_id,
        v2.version_id
    );
    assert_eq!(
        head_at(&r, b, "k", Ts(35)).unwrap().unwrap().version_id,
        v1.version_id
    );
    assert_eq!(head_at(&r, b, "k", Ts(5)).unwrap(), None);
    let asof = list_as_of(
        &r,
        b,
        &ListParams {
            max: 10,
            ..Default::default()
        },
        Ts(45),
    )
    .unwrap();
    assert_eq!(names(&asof), ["k"]);
}

#[derive(Debug, Clone)]
enum Op {
    PutVersioned(u8),
    PutUnversioned(u8),
    DeleteMarker(u8),
    DeleteUnversioned(u8),
    DeleteVersion(u8, usize),
    Restore(u8, usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..3).prop_map(Op::PutVersioned),
        (0u8..3).prop_map(Op::PutUnversioned),
        (0u8..3).prop_map(Op::DeleteMarker),
        (0u8..3).prop_map(Op::DeleteUnversioned),
        (0u8..3, 0usize..8).prop_map(|(k, i)| Op::DeleteVersion(k, i)),
        (0u8..3, 0usize..8).prop_map(|(k, i)| Op::Restore(k, i)),
    ]
}

const KEYS: [&str; 3] = ["a", "a/b", "b"];

#[allow(clippy::type_complexity)]
fn apply(
    s: &RedbMetaStore,
    b: BucketId,
    op: &Op,
    now: Ts,
    model: &mut BTreeMap<&'static str, Vec<(VersionId, bool)>>,
) {
    let k = |i: u8| KEYS[i as usize];
    let hide_soft = |at| VersionState::SoftDeleted {
        at,
        by: PrincipalId::root(),
        reason: DeleteReason::Api,
    };
    let (key, change): (
        &'static str,
        Box<dyn FnMut(&WriteTxn) -> Result<(), MetaError> + Send>,
    ) = match op.clone() {
        Op::PutVersioned(i) | Op::DeleteMarker(i) | Op::PutUnversioned(i) => {
            let key = k(i);
            let mut v = obj(key, now.0, matches!(op, Op::PutUnversioned(_)));
            if matches!(op, Op::DeleteMarker(_)) {
                v.kind = VersionKind::DeleteMarker;
            }
            let supersede = matches!(op, Op::PutUnversioned(_));
            let stack = model.entry(key).or_default();
            if supersede {
                stack.clear();
            }
            stack.push((v.version_id, v.is_delete_marker()));
            (
                key,
                Box::new(move |t| {
                    if supersede {
                        for mut old in t.versions_of(b, key)?.into_iter().filter(|x| x.is_live()) {
                            old.state = VersionState::Superseded { at: now };
                            t.put_version(b, &old)?;
                        }
                    }
                    t.put_version(b, &v)
                }),
            )
        }
        Op::DeleteUnversioned(i) => {
            let key = k(i);
            model.entry(key).or_default().clear();
            (
                key,
                Box::new(move |t| {
                    for mut old in t.versions_of(b, key)?.into_iter().filter(|x| x.is_live()) {
                        old.state = hide_soft(now);
                        t.put_version(b, &old)?;
                    }
                    Ok(())
                }),
            )
        }
        Op::DeleteVersion(i, idx) => {
            let key = k(i);
            let stack = model.entry(key).or_default();
            if stack.is_empty() {
                return;
            }
            let (vid, _) = stack.remove(idx % stack.len());
            (
                key,
                Box::new(move |t| {
                    let mut v = t.version(b, key, &vid)?.unwrap();
                    v.state = hide_soft(now);
                    t.put_version(b, &v)
                }),
            )
        }
        Op::Restore(i, idx) => {
            let key = k(i);
            let r = s.read().unwrap();
            let hidden: Vec<_> = r
                .versions_of(b, key)
                .unwrap()
                .into_iter()
                .filter(|v| !v.is_live() && !v.is_delete_marker())
                .collect();
            if hidden.is_empty() {
                return;
            }
            let src = hidden[idx % hidden.len()].clone();
            let mut v = src.clone();
            v.version_id = VersionId::new(now);
            v.created_at = now;
            v.state = VersionState::Live;
            model.entry(key).or_default().push((v.version_id, false));
            (key, Box::new(move |t| t.put_version(b, &v)))
        }
    };
    let mut change = change;
    rt().block_on(s.write(move |t| -> Result<(), MetaError> {
        change(t)?;
        t.refresh_latest(b, key)?;
        Ok(())
    }))
    .unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]
    #[test]
    fn head_at_matches_materialised_history(ops in prop::collection::vec((op(), 1i128..4), 1..40), probes in prop::collection::vec(0i128..200, 1..30)) {
        let (_d, s) = store();
        let b = BucketId(99);
        let mut model: BTreeMap<&'static str, Vec<(VersionId, bool)>> = BTreeMap::new();
        let mut snapshots: Vec<(Ts, BTreeMap<&'static str, Option<VersionId>>)> = Vec::new();
        let mut now = 10i128;
        for (o, dt) in &ops {
            now += dt;
            apply(&s, b, o, Ts(now), &mut model);
            let snap = KEYS.iter().map(|k| {
                let head = model.get(k).and_then(|st| st.last()).and_then(|(v, dm)| (!dm).then_some(*v));
                (*k, head)
            }).collect();
            snapshots.push((Ts(now), snap));
        }
        let r = s.read().unwrap();
        for p in probes {
            let t = Ts(p);
            let expected = snapshots.iter().rev().find(|(ts, _)| *ts <= t).map(|(_, m)| m.clone());
            for k in KEYS {
                let want = expected.as_ref().and_then(|m| m[k]);
                let got = head_at(&r, b, k, t).unwrap().map(|v| v.version_id);
                prop_assert_eq!(got, want, "key {} at {}", k, p);
            }
            let page = list_as_of(&r, b, &ListParams { max: 100, ..Default::default() }, t).unwrap();
            let listed: Vec<String> = names(&page);
            let want_list: Vec<String> = KEYS.iter().filter(|k| expected.as_ref().and_then(|m| m[**k]).is_some()).map(|k| k.to_string()).collect();
            prop_assert_eq!(listed, want_list);
        }
        let current = snapshots.last().unwrap().1.clone();
        for k in KEYS {
            let latest = r.latest(b, k).unwrap().filter(|v| !v.is_delete_marker()).map(|v| v.version_id);
            prop_assert_eq!(latest, current[k]);
        }
        s.shutdown();
    }
}
