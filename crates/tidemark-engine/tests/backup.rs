//! `tidemark backup` / `tidemark restore`: full + incremental, encrypted and plain, restore into a fresh
//! data dir, open an engine there and read everything back.

mod support3b;

use std::path::Path;
use std::time::Duration;
use support3b::*;
use tidemark_engine::backup::{
    BackupError, BackupLocation, BackupMode, BackupOptions, KdfParams, RestoreOptions, backup,
    list_backups, restore,
};
use tidemark_engine::fsck::{FsckOptions, VerifyMode};
use tidemark_engine::{EngineConfig, TidemarkEngine};
use zeroize::Zeroizing;

fn pass(p: &str) -> Option<Zeroizing<String>> {
    Some(Zeroizing::new(p.to_string()))
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
    }
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

async fn round_trip(encrypted: bool, at_rest: bool) {
    let src = tempfile::tempdir().unwrap();
    let set = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let mut c = cfg();
    if at_rest {
        c.at_rest_key = Some(tidemark_blob::DataKey::random());
    }
    let e = TidemarkEngine::open(src.path(), c.clone()).unwrap();
    bucket(&e, "docs", true).await;
    bucket(&e, "plain", false).await;
    let v1 = put(&e, "docs", "a.txt", b"version one").await;
    put(&e, "docs", "a.txt", b"version two").await;
    put(&e, "docs", "gone.txt", b"to be deleted").await;
    e.delete_object("docs", "gone.txt", None, &root())
        .await
        .unwrap();
    let big = data(300_000, 9);
    put_multipart(
        &e,
        "docs",
        "big.bin",
        &[big[..200_000].to_vec(), big[200_000..].to_vec()],
    )
    .await;
    put(&e, "plain", "p", b"plain bucket").await;

    let loc = BackupLocation::Dir(set.path().to_path_buf());
    let mut opts = BackupOptions {
        mode: BackupMode::Incremental,
        passphrase: if encrypted {
            pass("correct horse")
        } else {
            None
        },
        kdf: fast_kdf(),
        include_keys: false,
    };
    let full = backup(&e, &loc, &opts).await.unwrap();
    assert_eq!(full.mode, BackupMode::Full, "no previous manifest → full");
    assert_eq!(full.blobs_uploaded, 6);
    assert_eq!(full.blobs_total, 6);

    put(&e, "docs", "new.txt", b"written after the full backup").await;
    put(&e, "plain", "p", b"plain bucket v2").await;
    let inc = backup(&e, &loc, &opts).await.unwrap();
    assert_eq!(inc.mode, BackupMode::Incremental);
    assert_eq!(inc.blobs_uploaded, 2, "only new blobs are uploaded");
    assert_eq!(
        inc.blobs_total, 8,
        "superseded blob still referenced (shadow history)"
    );
    assert_eq!(
        list_backups(&loc).await.unwrap(),
        vec![full.id.clone(), inc.id.clone()]
    );

    if encrypted {
        let mut files = Vec::new();
        walk(set.path(), &mut files);
        for f in files
            .iter()
            .filter(|f| !f.ends_with("tidemark-backup.json"))
        {
            let b = std::fs::read(f).unwrap();
            assert!(b.starts_with(b"CRNBK1"), "{} not sealed", f.display());
            assert!(!b.windows(11).any(|w| w == b"version one"));
        }
        let wrong = RestoreOptions {
            manifest: None,
            passphrase: pass("wrong"),
        };
        let other = tempfile::tempdir().unwrap();
        assert!(matches!(
            restore(&loc, other.path(), &wrong).await,
            Err(BackupError::Crypto(_))
        ));
        opts.passphrase = None;
        assert!(
            backup(&e, &loc, &opts).await.is_err(),
            "encrypted set needs the passphrase"
        );
    }
    e.shutdown();
    drop(e);

    let ropts = RestoreOptions {
        manifest: None,
        passphrase: if encrypted {
            pass("correct horse")
        } else {
            None
        },
    };
    let rep = restore(&loc, dst.path(), &ropts).await.unwrap();
    assert_eq!(rep.id, inc.id);
    assert_eq!(rep.blobs_restored, 8);
    let r = TidemarkEngine::open(dst.path(), c.clone()).unwrap();
    assert_eq!(get(&r, "docs", "a.txt").await.unwrap(), b"version two");
    assert_eq!(
        get_version(&r, "docs", "a.txt", v1.version_id.clone())
            .await
            .unwrap()
            .0,
        b"version one"
    );
    assert_eq!(get(&r, "docs", "big.bin").await.unwrap(), big);
    assert_eq!(
        get(&r, "docs", "new.txt").await.unwrap(),
        b"written after the full backup"
    );
    assert_eq!(get(&r, "plain", "p").await.unwrap(), b"plain bucket v2");
    assert_eq!(
        get(&r, "docs", "gone.txt").await.unwrap_err(),
        tidemark_core::S3ErrorCode::NoSuchKey,
        "delete marker restored"
    );
    let f = r
        .fsck(FsckOptions {
            verify: VerifyMode::Full,
            orphan_min_age: Duration::ZERO,
            repair: false,
        })
        .await
        .unwrap();
    assert!(f.is_clean(), "{f:#?}");
    r.shutdown();
    drop(r);

    let older = tempfile::tempdir().unwrap();
    let rep = restore(
        &loc,
        older.path(),
        &RestoreOptions {
            manifest: Some(full.id.clone()),
            passphrase: ropts.passphrase.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(rep.blobs_restored, 6);
    let o = TidemarkEngine::open(older.path(), c).unwrap();
    assert_eq!(get(&o, "plain", "p").await.unwrap(), b"plain bucket");
    assert!(get(&o, "docs", "new.txt").await.is_err());
    assert!(
        restore(&loc, older.path(), &ropts).await.is_err(),
        "refuses to overwrite an existing data dir"
    );
}

#[tokio::test]
async fn plain_full_incremental_restore() {
    round_trip(false, false).await;
}

#[tokio::test]
async fn encrypted_full_incremental_restore() {
    round_trip(true, false).await;
}

#[tokio::test]
async fn encrypted_backup_of_encrypted_at_rest_store() {
    round_trip(true, true).await;
}

#[tokio::test]
async fn tampered_blob_fails_restore() {
    let src = tempfile::tempdir().unwrap();
    let set = tempfile::tempdir().unwrap();
    let e = open(src.path());
    bucket(&e, "bkt", false).await;
    let v = put(&e, "bkt", "k", b"authentic content").await;
    let loc = BackupLocation::Dir(set.path().to_path_buf());
    backup(&e, &loc, &BackupOptions::default()).await.unwrap();
    let hex = v.version.blobs()[0].to_hex();
    let p = set.path().join("blobs").join(&hex[..2]).join(&hex);
    std::fs::write(&p, b"forged  content!!").unwrap();
    let dst = tempfile::tempdir().unwrap();
    let err = restore(&loc, dst.path(), &RestoreOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, BackupError::Verify(_)), "{err}");
    assert!(!dst.path().join("meta").join("tidemark.redb").exists());
}

#[tokio::test]
async fn include_keys_requires_encryption() {
    let src = tempfile::tempdir().unwrap();
    let set = tempfile::tempdir().unwrap();
    let e = TidemarkEngine::open(src.path(), EngineConfig::default()).unwrap();
    std::fs::create_dir_all(src.path().join("keys")).unwrap();
    std::fs::write(src.path().join("keys").join("master.key"), [7u8; 32]).unwrap();
    let loc = BackupLocation::Dir(set.path().to_path_buf());
    let plain = BackupOptions {
        include_keys: true,
        ..Default::default()
    };
    assert!(backup(&e, &loc, &plain).await.is_err());
    let enc = BackupOptions {
        include_keys: true,
        passphrase: pass("pw"),
        kdf: fast_kdf(),
        ..Default::default()
    };
    backup(&e, &loc, &enc).await.unwrap();
    let dst = tempfile::tempdir().unwrap();
    let rep = restore(
        &loc,
        dst.path(),
        &RestoreOptions {
            manifest: None,
            passphrase: pass("pw"),
        },
    )
    .await
    .unwrap();
    assert_eq!(rep.keys_restored, 1);
    assert_eq!(
        std::fs::read(dst.path().join("keys").join("master.key")).unwrap(),
        [7u8; 32]
    );
}
