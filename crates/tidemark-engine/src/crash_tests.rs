//! C1 crash consistency: a child process (this test binary re-executed) runs a put, a multipart
//! complete or a delete and is SIGKILLed while parked at a named `failpoint!`. The parent then
//! reopens the data directory and checks that recovery leaves every object either fully there
//! or absent, never partial, with `tmp/` empty and fsck clean.

use crate::*;
use bytes::Bytes;
use futures::StreamExt;
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tidemark_core::PrincipalId;
use tidemark_meta::{Reader, Table, VersionRecord, decode, keys};

const POINT_ENV: &str = "TIDEMARK_FAILPOINT";
const DIR_ENV: &str = "TIDEMARK_CRASH_DIR";
const OP_ENV: &str = "TIDEMARK_CRASH_OP";
const ENC_ENV: &str = "TIDEMARK_CRASH_ENC";
const HIT: &str = "TIDEMARK_FAILPOINT_HIT";

/// Park the process forever at `name` when `TIDEMARK_FAILPOINT` selects it, so the parent can
/// SIGKILL it there.
pub(crate) fn failpoint(name: &str) {
    if std::env::var(POINT_ENV).as_deref() == Ok(name) {
        eprintln!("{HIT} {name}");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}

const OLD: &[u8] = b"the committed old version";

fn new_body() -> Vec<u8> {
    (0..900_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect()
}

fn parts() -> [Vec<u8>; 2] {
    [vec![b'a'; 200_000], vec![b'b'; 70_000]]
}

fn cfg(encrypted: bool) -> EngineConfig {
    EngineConfig {
        limits: LimitsConfig {
            min_part_size: 5,
            ..Default::default()
        },
        at_rest_key: encrypted.then(|| DataKey::new([9; 32])),
        fsync: true,
        ..Default::default()
    }
}

fn root() -> PrincipalId {
    PrincipalId::root()
}

fn chunked(data: Vec<u8>) -> Body {
    let chunks: Vec<_> = data
        .chunks(128 * 1024)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    Box::pin(futures::stream::iter(chunks))
}

async fn put(e: &TidemarkEngine, key: &str, data: Vec<u8>) -> S3Result<PutObjectRes> {
    let len = data.len() as u64;
    e.put_object(PutObjectReq {
        bucket: "bkt".into(),
        key: key.into(),
        body: chunked(data),
        content_length: Some(len),
        content_md5: None,
        checksum: ChecksumInput::None,
        meta: ObjectMeta::default(),
        tags: BTreeMap::new(),
        conditions: WriteConditions::default(),
        owner: root(),
    })
    .await
}

async fn get(e: &TidemarkEngine, key: &str) -> Result<Vec<u8>, S3ErrorCode> {
    let r = e
        .get_object(
            GetObjectReq {
                bucket: "bkt".into(),
                key: key.into(),
                ..Default::default()
            },
            true,
        )
        .await
        .map_err(|e| e.code)?;
    let mut s = r.body.unwrap();
    let mut out = Vec::new();
    while let Some(c) = s.next().await {
        out.extend_from_slice(&c.unwrap());
    }
    Ok(out)
}

fn versions(e: &TidemarkEngine, key: &str) -> Vec<VersionRecord> {
    let r = e.read().unwrap();
    let b = e.bucket("bkt").unwrap();
    let mut out = Vec::new();
    r.scan_prefix(
        Table::Versions,
        &keys::versions_of(b.id, key),
        &mut |_, v| {
            out.push(decode(v)?);
            Ok(tidemark_meta::Flow::Continue)
        },
    )
    .unwrap();
    out
}

/// The operation the child runs (and is killed in the middle of).
async fn child_op(e: &TidemarkEngine, op: &str) {
    match op {
        "put" => {
            put(e, "k", new_body()).await.unwrap();
        }
        "delete" => {
            e.delete_object("bkt", "k", None, &root()).await.unwrap();
        }
        "complete" => {
            let u = e
                .create_multipart_upload(CreateUploadReq {
                    bucket: "bkt".into(),
                    key: "m".into(),
                    owner: root(),
                    ..Default::default()
                })
                .await
                .unwrap();
            let mut done = Vec::new();
            for (i, data) in parts().into_iter().enumerate() {
                let n = i as u32 + 1;
                let len = data.len() as u64;
                let p = e
                    .upload_part(UploadPartReq {
                        bucket: "bkt".into(),
                        key: "m".into(),
                        upload_id: u.upload_id.clone(),
                        part_number: n,
                        body: chunked(data),
                        content_length: Some(len),
                        content_md5: None,
                        checksum: ChecksumInput::None,
                    })
                    .await
                    .unwrap();
                done.push(CompletePart {
                    number: n,
                    etag: p.etag,
                    checksum: None,
                });
            }
            e.complete_multipart_upload(CompleteReq {
                bucket: "bkt".into(),
                key: "m".into(),
                upload_id: u.upload_id,
                parts: done,
                owner: root(),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        other => panic!("unknown crash op {other}"),
    }
}

/// Child entry point: a no-op unless the parent set `TIDEMARK_CRASH_DIR`.
#[test]
fn child() {
    let Ok(dir) = std::env::var(DIR_ENV) else {
        return;
    };
    let op = std::env::var(OP_ENV).unwrap();
    let enc = std::env::var(ENC_ENV).is_ok();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let e = TidemarkEngine::open(Path::new(&dir), cfg(enc)).unwrap();
        child_op(&e, &op).await;
    });
    eprintln!("TIDEMARK_CRASH_NO_HIT");
    std::process::exit(3);
}

/// Data dir with bucket `bkt` holding `k = OLD`, cleanly shut down.
async fn prepared(enc: bool) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let e = TidemarkEngine::open(d.path(), cfg(enc)).unwrap();
    e.create_bucket("bkt", &root(), false, None).await.unwrap();
    put(&e, "k", OLD.to_vec()).await.unwrap();
    e.shutdown();
    d
}

/// Run `op` in a child process, SIGKILL it once it reaches `point`.
fn crash_at(dir: &Path, op: &str, point: &str, enc: bool) {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "crash_tests::child",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(DIR_ENV, dir)
    .env(OP_ENV, op)
    .env(POINT_ENV, point)
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    if enc {
        cmd.env(ENC_ENV, "1");
    }
    let mut child = cmd.spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let want = format!("{HIT} {point}");
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut log = Vec::new();
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(l) if l == want => break,
            Ok(l) => log.push(l),
            Err(_) => {
                let _ = child.kill();
                panic!("child never reached {point}: {log:#?}");
            }
        }
    }
    child.kill().unwrap();
    let st = child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(st.signal(), Some(9), "child was not SIGKILLed: {st:?}");
}

fn blob_files(dir: &Path) -> usize {
    fn walk(p: &Path) -> usize {
        std::fs::read_dir(p).map_or(0, |rd| {
            rd.flatten()
                .map(|e| {
                    if e.path().is_dir() {
                        walk(&e.path())
                    } else {
                        1
                    }
                })
                .sum()
        })
    }
    walk(&dir.join("blobs"))
}

fn tmp_entries(dir: &Path) -> usize {
    std::fs::read_dir(dir.join("tmp")).unwrap().count()
}

/// Reopen after the crash, run startup recovery and check the invariants every crash point
/// shares: unclean shutdown detected, `tmp/` swept, fsck clean (no orphan, missing or
/// drifted blob, no dangling upload).
async fn recover(dir: &Path, enc: bool) -> TidemarkEngine {
    let e = TidemarkEngine::open(dir, cfg(enc)).unwrap();
    let rep = e.recover(false).await.unwrap();
    assert!(rep.unclean_shutdown, "{rep:?}");
    assert_eq!(tmp_entries(dir), 0, "tmp/ not swept");
    let f = e
        .fsck(fsck::FsckOptions {
            verify: fsck::VerifyMode::Full,
            orphan_min_age: Duration::ZERO,
            repair: false,
        })
        .await
        .unwrap();
    assert!(f.is_clean(), "fsck after recovery: {f:#?}");
    e
}

async fn put_case(point: &str, committed: bool, enc: bool) {
    let d = prepared(enc).await;
    crash_at(d.path(), "put", point, enc);
    if point == "ingest.mid_body" {
        assert!(tmp_entries(d.path()) > 0, "crash left nothing in tmp/");
    }
    let e = recover(d.path(), enc).await;
    let vs = versions(&e, "k");
    if committed {
        assert_eq!(get(&e, "k").await.unwrap(), new_body());
        assert_eq!(vs.len(), 2);
    } else {
        assert_eq!(get(&e, "k").await.unwrap(), OLD);
        assert_eq!(vs.len(), 1, "a half-committed version survived");
        let blobs = blob_files(d.path());
        assert_eq!(blobs, 1, "the new blob outlived the crash");
    }
    // The store is fully usable afterwards.
    put(&e, "k", new_body()).await.unwrap();
    assert_eq!(get(&e, "k").await.unwrap(), new_body());
    e.shutdown();
}

#[tokio::test]
async fn kill_during_put_body_leaves_old_version_and_empty_tmp() {
    put_case("ingest.mid_body", false, false).await;
}

#[tokio::test]
async fn kill_after_blob_placed_before_commit_sweeps_orphan() {
    put_case("put.blob_placed", false, false).await;
}

#[tokio::test]
async fn kill_inside_put_transaction_commits_nothing() {
    put_case("put.in_txn", false, false).await;
}

#[tokio::test]
async fn kill_inside_put_transaction_encrypted() {
    put_case("put.in_txn", false, true).await;
}

#[tokio::test]
async fn kill_after_put_commit_keeps_whole_object() {
    put_case("put.committed", true, false).await;
}

async fn complete_case(point: &str, committed: bool) {
    let d = prepared(false).await;
    crash_at(d.path(), "complete", point, false);
    let e = recover(d.path(), false).await;
    let whole: Vec<u8> = parts().concat();
    let ups = e
        .list_multipart_uploads("bkt", "", None, None, None, 1000)
        .unwrap();
    if committed {
        assert_eq!(get(&e, "m").await.unwrap(), whole);
        assert!(ups.uploads.is_empty(), "upload outlived its completion");
    } else {
        assert_eq!(get(&e, "m").await, Err(S3ErrorCode::NoSuchKey));
        assert!(versions(&e, "m").is_empty(), "half-completed version");
        assert_eq!(ups.uploads.len(), 1);
        let u = &ups.uploads[0];
        assert_eq!(u.parts.len(), 2);
        // The upload survived intact and can still be completed.
        let parts = u
            .parts
            .values()
            .map(|p| CompletePart {
                number: p.number,
                etag: p.etag.clone(),
                checksum: None,
            })
            .collect();
        e.complete_multipart_upload(CompleteReq {
            bucket: "bkt".into(),
            key: "m".into(),
            upload_id: u.upload_id.clone(),
            parts,
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(get(&e, "m").await.unwrap(), whole);
    }
    assert_eq!(get(&e, "k").await.unwrap(), OLD);
    e.shutdown();
}

#[tokio::test]
async fn kill_inside_complete_transaction_keeps_upload() {
    complete_case("complete.in_txn", false).await;
}

#[tokio::test]
async fn kill_after_complete_commit_keeps_whole_object() {
    complete_case("complete.committed", true).await;
}

async fn delete_case(point: &str, committed: bool) {
    let d = prepared(false).await;
    crash_at(d.path(), "delete", point, false);
    let e = recover(d.path(), false).await;
    let vs = versions(&e, "k");
    assert_eq!(vs.len(), 1);
    if committed {
        assert_eq!(get(&e, "k").await, Err(S3ErrorCode::NoSuchKey));
        assert!(!vs[0].is_live(), "deleted version still live");
        // Soft delete: the bytes are still restorable after the crash.
        e.trash_restore("bkt", "k", None, &root()).await.unwrap();
        assert_eq!(get(&e, "k").await.unwrap(), OLD);
    } else {
        assert_eq!(get(&e, "k").await.unwrap(), OLD);
        assert!(vs[0].is_live(), "half-applied delete");
    }
    e.shutdown();
}

#[tokio::test]
async fn kill_inside_delete_transaction_keeps_object() {
    delete_case("delete.in_txn", false).await;
}

#[tokio::test]
async fn kill_after_delete_commit_is_a_restorable_soft_delete() {
    delete_case("delete.committed", true).await;
}

#[test]
fn failpoints_are_inert_without_the_env_var() {
    let t = Instant::now();
    failpoint("put.in_txn");
    assert!(t.elapsed() < Duration::from_secs(1));
}
