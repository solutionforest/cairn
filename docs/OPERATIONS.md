# Cairn — Operations guide

Sections are owned by the agent that wrote them; append new sections, do not rewrite others.

## Upgrades

Cairn keeps its metadata (buckets, versions, IAM, sessions, outbox) in one redb file,
`<data_dir>/meta/cairn.redb`. Blobs are content-addressed and never change format in place, so an
upgrade is a metadata-schema question only.

**Schema version.** The version is a big-endian `u32` in the `kv` table under the key
`schema_version` (`cairn_meta::migrate::CURRENT_SCHEMA`, currently **1**). Every record also
carries a leading schema byte, so a migration can rewrite records lazily or in bulk.

**What happens on start.** Before the server opens the store it runs
`cairn_meta::migrate::migrate(<db>, dry_run = false)`:

1. A brand-new, empty database is stamped with the current version. A database with data but no
   stamp (written before the framework existed) is treated as v1.
2. A database **newer** than the binary (`schema_version > CURRENT_SCHEMA`) is refused with
   `metadata schema vN is newer than this binary supports`. Nothing is written. Downgrade by
   restoring the pre-upgrade backup (below) with the old binary.
3. If steps are needed, the redb file is first copied to `<db>.pre-v<N>.bak` (N = target
   version) and fsynced. Only then are the registered steps applied, each in its own write
   transaction together with the version bump, so a crash leaves the file at a well-defined
   version and re-running the upgrade continues from there.
4. A missing step (no registered `vA → vA+1`) aborts with `no migration path` before any write.

**Recommended procedure.**

```sh
cairn migrate --dry-run --data-dir /srv/cairn   # prints from/to and the planned steps; writes nothing
systemctl stop cairn
cairn backup --data-dir /srv/cairn ...           # optional extra copy (phase 3b)
# install the new binary
systemctl start cairn                            # runs the migration, writes meta/cairn.redb.pre-vN.bak
```

Disk space: the pre-upgrade snapshot is a full copy of `cairn.redb`; keep at least that much free
under `meta/`. Remove old `*.pre-v*.bak` files once the new version has run cleanly.

**Rollback / downgrade.** Stop the server, move `cairn.redb` aside, rename
`cairn.redb.pre-vN.bak` to `cairn.redb`, start the previous binary. Writes made after the upgrade
are lost (blobs they created become orphans that `cairn fsck --repair` / GC reclaim).

**For developers adding a migration.** Bump `CURRENT_SCHEMA`, append a
`Migration { from, to, name, apply }` to `cairn_meta::migrate::REGISTRY`. `apply` gets the
`&WriteTxn`, must be deterministic (the writer may re-run it), and should rewrite only what changed.
Add a test that copies `crates/cairn-meta/tests/fixtures/meta-v1.redb` (the committed v1 fixture)
and migrates it; never edit an existing fixture, add `meta-vN.redb` instead.
