//! Metadata schema migrations (DESIGN §12 "Upgrades", docs/OPERATIONS.md).
//!
//! The schema version is a big-endian `u32` in the `kv` table under `schema_version`. On
//! start the server calls [`migrate`]: it refuses a database newer than this binary knows,
//! copies the redb file to `<db>.pre-v<N>.bak` (N = target version) before changing anything,
//! then applies each registered [`Migration`] in its own write transaction together with the
//! version bump, so a crash leaves the database at a well-defined version.

use crate::{MetaError, MetaStore, Reader, RedbMetaStore, Table, WriteTxn};
use std::path::{Path, PathBuf};

/// `kv` key holding the schema version.
pub const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";

/// Schema version this binary writes.
pub const CURRENT_SCHEMA: u32 = 1;

/// One schema step `from → to` (`to == from + 1`).
#[derive(Clone, Copy)]
pub struct Migration {
    /// Version the step starts from.
    pub from: u32,
    /// Version after the step.
    pub to: u32,
    /// Short human description (shown by `cairn migrate --dry-run`).
    pub name: &'static str,
    /// Rewrite records inside the given transaction. Must be deterministic: the metadata writer
    /// may re-run it on a fresh transaction.
    pub apply: fn(&WriteTxn) -> Result<(), MetaError>,
}

impl std::fmt::Debug for Migration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Migration(v{} -> v{}: {})",
            self.from, self.to, self.name
        )
    }
}

/// Built-in migrations, oldest first. Empty while the schema is at v1.
pub const REGISTRY: &[Migration] = &[];

/// Migration failures.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// The database was written by a newer Cairn.
    #[error(
        "metadata schema v{found} is newer than this binary supports (v{supported}); upgrade Cairn or restore a backup"
    )]
    NewerSchema {
        /// Version found on disk.
        found: u32,
        /// Highest version this binary knows.
        supported: u32,
    },
    /// No registered step leaves `from`.
    #[error("no migration path from schema v{from} to v{to}")]
    NoPath {
        /// Stuck at.
        from: u32,
        /// Wanted.
        to: u32,
    },
    /// Stored version is not 4 bytes.
    #[error("corrupt schema_version value")]
    Corrupt,
    /// Snapshot copy failed.
    #[error("pre-upgrade snapshot {path}: {source}")]
    Snapshot {
        /// Backup path.
        path: PathBuf,
        /// I/O error.
        source: std::io::Error,
    },
    /// Database error.
    #[error(transparent)]
    Meta(#[from] MetaError),
}

/// What [`migrate`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Version on disk before (`None` = brand-new database, stamped with the target).
    pub from: Option<u32>,
    /// Version after (or that would be reached, for a dry run).
    pub to: u32,
    /// Steps applied (or planned), as `"vA->vB name"`.
    pub steps: Vec<String>,
    /// Backup written before applying steps.
    pub backup: Option<PathBuf>,
    /// True if nothing was written.
    pub dry_run: bool,
}

fn decode_version(b: &[u8]) -> Result<u32, MigrateError> {
    <[u8; 4]>::try_from(b)
        .map(u32::from_be_bytes)
        .map_err(|_| MigrateError::Corrupt)
}

/// Stored schema version (`None` if never stamped).
pub fn schema_version<R: Reader + ?Sized>(r: &R) -> Result<Option<u32>, MigrateError> {
    r.get(Table::Kv, SCHEMA_VERSION_KEY)?
        .map(|b| decode_version(&b))
        .transpose()
}

/// Write the schema version inside a transaction.
pub fn set_schema_version(txn: &WriteTxn, v: u32) -> Result<(), MetaError> {
    txn.put(Table::Kv, SCHEMA_VERSION_KEY, &v.to_be_bytes())
}

/// Refuse to run against a database newer than [`CURRENT_SCHEMA`] or one that still needs
/// migrating. Call after opening the store when [`migrate`] was not run.
pub fn ensure_current(store: &RedbMetaStore) -> Result<(), MigrateError> {
    match schema_version(&store.read()?)? {
        Some(v) if v > CURRENT_SCHEMA => Err(MigrateError::NewerSchema {
            found: v,
            supported: CURRENT_SCHEMA,
        }),
        Some(v) if v < CURRENT_SCHEMA => Err(MigrateError::NoPath {
            from: v,
            to: CURRENT_SCHEMA,
        }),
        _ => Ok(()),
    }
}

/// Backup path used before upgrading `db` to version `to`.
pub fn backup_path(db: &Path, to: u32) -> PathBuf {
    let mut s = db.as_os_str().to_owned();
    s.push(format!(".pre-v{to}.bak"));
    PathBuf::from(s)
}

fn has_data(store: &RedbMetaStore) -> Result<bool, MetaError> {
    let r = store.read()?;
    for t in Table::ALL {
        let mut any = false;
        r.scan(
            *t,
            std::ops::Bound::Unbounded,
            std::ops::Bound::Unbounded,
            &mut |k, _| {
                any = !(*t == Table::Kv && k == SCHEMA_VERSION_KEY);
                Ok(if any {
                    crate::Flow::Stop
                } else {
                    crate::Flow::Continue
                })
            },
        )?;
        if any {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Bring the database at `db` to [`CURRENT_SCHEMA`] with the built-in [`REGISTRY`].
/// Must run before the server opens the store (it opens and closes the file itself).
pub async fn migrate(db: &Path, dry_run: bool) -> Result<MigrationReport, MigrateError> {
    migrate_with(db, REGISTRY, CURRENT_SCHEMA, dry_run).await
}

/// [`migrate`] with an explicit registry and target (tests, future tooling).
/// A database with data but no stored version is treated as v1 (pre-framework).
pub async fn migrate_with(
    db: &Path,
    registry: &[Migration],
    target: u32,
    dry_run: bool,
) -> Result<MigrationReport, MigrateError> {
    let store = RedbMetaStore::open(db)?;
    let stored = schema_version(&store.read()?)?;
    let fresh = stored.is_none() && !has_data(&store)?;
    let from = match stored {
        Some(v) => v,
        None if fresh => target,
        None => 1,
    };
    if from > target {
        store.shutdown();
        return Err(MigrateError::NewerSchema {
            found: from,
            supported: target,
        });
    }
    let mut plan = Vec::new();
    let mut v = from;
    while v < target {
        let Some(m) = registry
            .iter()
            .find(|m| m.from == v && m.to > v && m.to <= target)
        else {
            store.shutdown();
            return Err(MigrateError::NoPath {
                from: v,
                to: target,
            });
        };
        plan.push(*m);
        v = m.to;
    }
    let steps: Vec<String> = plan
        .iter()
        .map(|m| format!("v{}->v{} {}", m.from, m.to, m.name))
        .collect();
    let mut report = MigrationReport {
        from: if fresh { None } else { Some(from) },
        to: target,
        steps,
        backup: None,
        dry_run,
    };
    if dry_run {
        store.shutdown();
        return Ok(report);
    }
    if plan.is_empty() {
        if stored.is_none() {
            store.write(move |t| set_schema_version(t, target)).await?;
        }
        store.shutdown();
        return Ok(report);
    }
    store.shutdown();
    drop(store);
    let bak = backup_path(db, target);
    std::fs::copy(db, &bak).map_err(|source| MigrateError::Snapshot {
        path: bak.clone(),
        source,
    })?;
    if let Ok(f) = std::fs::File::open(&bak) {
        let _ = f.sync_all();
    }
    tracing::warn!(backup = %bak.display(), from, to = target, "migrating metadata schema");
    report.backup = Some(bak);
    let store = RedbMetaStore::open(db)?;
    for m in plan {
        let res = store
            .write(move |t| {
                (m.apply)(t)?;
                set_schema_version(t, m.to)
            })
            .await;
        if let Err(e) = res {
            store.shutdown();
            return Err(e.into());
        }
        tracing::info!(
            from = m.from,
            to = m.to,
            name = m.name,
            "schema migration applied"
        );
    }
    store.shutdown();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop(_: &WriteTxn) -> Result<(), MetaError> {
        Ok(())
    }

    fn mark(t: &WriteTxn) -> Result<(), MetaError> {
        t.put(Table::Kv, b"migrated_v2", b"yes")
    }

    const V2: &[Migration] = &[Migration {
        from: 1,
        to: 2,
        name: "test step",
        apply: mark,
    }];

    /// A v1 fixture: one bucket-ish record and an explicit v1 stamp.
    async fn write_v1_fixture(db: &Path, stamp: bool) {
        let s = RedbMetaStore::open(db).unwrap();
        s.write(move |t| -> Result<(), MetaError> {
            t.put(Table::Buckets, b"photos", &[1, 0, 0, 0])?;
            if stamp {
                set_schema_version(t, 1)?;
            }
            Ok(())
        })
        .await
        .unwrap();
        s.shutdown();
    }

    fn version_of(db: &Path) -> Option<u32> {
        let s = RedbMetaStore::open(db).unwrap();
        let v = schema_version(&s.read().unwrap()).unwrap();
        s.shutdown();
        v
    }

    #[tokio::test]
    async fn v1_to_v2_snapshots_then_bumps() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("cairn.redb");
        write_v1_fixture(&db, true).await;

        let dry = migrate_with(&db, V2, 2, true).await.unwrap();
        assert_eq!(dry.from, Some(1));
        assert_eq!(dry.steps, vec!["v1->v2 test step".to_string()]);
        assert!(dry.backup.is_none());
        assert_eq!(version_of(&db), Some(1));
        assert!(!backup_path(&db, 2).exists());

        let r = migrate_with(&db, V2, 2, false).await.unwrap();
        let bak = r.backup.clone().unwrap();
        assert_eq!(bak, dir.path().join("cairn.redb.pre-v2.bak"));
        assert_eq!(version_of(&db), Some(2));
        let s = RedbMetaStore::open(&db).unwrap();
        assert_eq!(
            s.read().unwrap().get(Table::Kv, b"migrated_v2").unwrap(),
            Some(b"yes".to_vec())
        );
        assert!(
            s.read()
                .unwrap()
                .get(Table::Buckets, b"photos")
                .unwrap()
                .is_some()
        );
        s.shutdown();
        drop(s);
        // the backup is the untouched v1 database
        assert_eq!(version_of(&bak), Some(1));

        // idempotent: already at v2
        let again = migrate_with(&db, V2, 2, false).await.unwrap();
        assert!(again.steps.is_empty() && again.backup.is_none());
    }

    #[tokio::test]
    async fn unstamped_data_is_v1_and_fresh_db_is_stamped() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("old.redb");
        write_v1_fixture(&db, false).await;
        let noop_reg = [Migration {
            from: 1,
            to: 2,
            name: "noop",
            apply: noop,
        }];
        let r = migrate_with(&db, &noop_reg, 2, false).await.unwrap();
        assert_eq!(r.from, Some(1));
        assert_eq!(version_of(&db), Some(2));

        let fresh = dir.path().join("new.redb");
        let r = migrate(&fresh, false).await.unwrap();
        assert_eq!(r.from, None);
        assert!(r.backup.is_none());
        assert_eq!(version_of(&fresh), Some(CURRENT_SCHEMA));
        let s = RedbMetaStore::open(&fresh).unwrap();
        ensure_current(&s).unwrap();
        s.shutdown();
    }

    /// The committed fixture `tests/fixtures/meta-v1.redb` (written by the phase-1 schema)
    /// migrates through a no-op v1 -> v2 step without losing data.
    #[tokio::test]
    async fn committed_v1_fixture_migrates() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/meta-v1.redb");
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("cairn.redb");
        std::fs::copy(&src, &db).unwrap();
        assert_eq!(version_of(&db), Some(1));
        let reg = [Migration {
            from: 1,
            to: 2,
            name: "noop",
            apply: noop,
        }];
        let r = migrate_with(&db, &reg, 2, false).await.unwrap();
        assert_eq!(r.from, Some(1));
        assert!(r.backup.as_ref().unwrap().exists());
        assert_eq!(version_of(&db), Some(2));
        let s = RedbMetaStore::open(&db).unwrap();
        assert_eq!(
            s.read().unwrap().get(Table::Buckets, b"photos").unwrap(),
            Some(vec![1, 0, 0, 0])
        );
        s.shutdown();
    }

    /// Regenerate the committed fixture: `cargo test -p cairn-meta -- --ignored write_fixture`.
    #[tokio::test]
    #[ignore]
    async fn write_fixture() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/meta-v1.redb");
        let _ = std::fs::remove_file(&p);
        write_v1_fixture(&p, true).await;
    }

    #[tokio::test]
    async fn refuses_newer_schema_and_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("future.redb");
        let s = RedbMetaStore::open(&db).unwrap();
        s.write(|t| set_schema_version(t, CURRENT_SCHEMA + 5))
            .await
            .unwrap();
        assert!(matches!(
            ensure_current(&s),
            Err(MigrateError::NewerSchema { .. })
        ));
        s.shutdown();
        drop(s);
        assert!(matches!(
            migrate(&db, false).await,
            Err(MigrateError::NewerSchema { found, .. }) if found == CURRENT_SCHEMA + 5
        ));

        let db1 = dir.path().join("v1.redb");
        write_v1_fixture(&db1, true).await;
        assert!(matches!(
            migrate_with(&db1, &[], 3, false).await,
            Err(MigrateError::NoPath { from: 1, to: 3 })
        ));
        assert_eq!(version_of(&db1), Some(1));
    }
}
