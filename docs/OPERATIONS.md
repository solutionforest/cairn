# Tidemark — Operations guide

Sections are owned by the agent that wrote them; append new sections, do not rewrite others.

## Footprint

Run 2026-11-08T19:14Z by `scripts/footprint.sh`: tidemark 0.1.0 @ f922680 plus the size-optimised
release profile (`opt-level = "z"`, fat LTO, one codegen unit, stripped), `cargo build --release
--target x86_64-unknown-linux-musl`, x86_64 gVisor sandbox reporting 1 vCPU. RSS is the process
VmRSS from `/proc` (not a container working set; this sandbox exposes no VmHWM, so the peak is
the max of 0.2 s samples and a shorter spike could be missed).

| Measure | Value |
|---|---|
| Binary size | 18192904 bytes (17.3 MiB), static |
| RSS at ready | 29.7 MiB |
| Idle RSS after 110 s | 29.6 MiB |
| Peak RSS (max of 0.2 s VmRSS samples; VmHWM unavailable), 10240 MiB upload + download | 58.3 MiB |
| Max sampled RSS (0.2 s interval) during transfer | 58.3 MiB |
| Upload / download wall time | 34 s / 51 s |
| Round-trip sha256 | match |

**Why idle RSS on this host is not the E2 number.** gVisor keeps the whole executable resident
(the 17.3 MiB binary shows up in full in `/proc/<pid>/smaps`; a regular kernel pages in only
what runs) and faults anonymous memory in coarse chunks: five fresh starts of the same binary
measured 25.4–34.3 MiB, with the binary mapping constant at 17.4 MiB and anonymous memory
varying between 6 and 16 MiB from the first second on. The E2 budget is therefore checked on a
regular Linux kernel by `.github/workflows/footprint.yml` (GitHub-hosted runner, size + idle,
fails over budget); the step summary of the latest run is the number to quote.

Regular-kernel run 2026-11-09T04:15Z (CI `footprint` job, run 42560176403): tidemark 0.1.0 @ eb04188,
release build, aarch64-unknown-linux-musl, 4 vCPU, Linux 7.0.14. Binary 14379056 bytes
(13.7 MiB, static; the x86_64 build is 17.3 MiB), RSS 10.3 MiB at ready, **10.4 MiB idle after
110 s**.

Since 2026-11-09 the release binary no longer contains the AWS SDK or the OIDC libraries
(DECISIONS "Shelved features leave the release binary"): x86_64 is 15323528 bytes (14.6 MiB).
The tables above predate that; the CI `footprint` job re-measures size and idle RSS on every push.

**Size profile cost.** Server CPU per GiB, measured with `aws s3 cp` on this host for opt-level
3 / `s` / `z`: put 2.6 / 2.4–2.6 / 2.5–2.6 s, get 4.9–5.3 / 5.5 / 5.2 s, i.e. inside run-to-run
noise. Hashing (BLAKE3, SHA-2, CRC) runs on SIMD/assembly paths whatever the opt-level.

Against the v0.1 limits (PRODUCTION-READINESS E1, E2): the 10 GiB round trip stays far under
256 MiB, so uploads and downloads stream; the binary is under 20 MB. Re-measure with
`scripts/footprint.sh target/x86_64-unknown-linux-musl/release/tidemark`; set
`FOOTPRINT_MAX_BINARY_BYTES` / `FOOTPRINT_MAX_IDLE_MIB` / `FOOTPRINT_MAX_PEAK_MIB` to make it
fail over budget.

## Upgrades

**Promise.** A data directory or backup written by `v0.1.0-alpha.3` or any later release opens
in every later release; install the new binary and start it. Every push tests this against
every published release (`scripts/upgrade-test.sh`, DESIGN §4.5). Directories from
`0.1.0-alpha.1`/`alpha.2` (Cairn) are not covered; see the alpha.3 changelog entry.

Tidemark keeps its metadata (buckets, versions, IAM, sessions, outbox) in one redb file,
`<data_dir>/meta/tidemark.redb`. Blobs are content-addressed and never change format in place, so an
upgrade is a metadata-schema question only.

**Schema version.** The version is a big-endian `u32` in the `kv` table under the key
`schema_version` (`tidemark_meta::migrate::CURRENT_SCHEMA`, currently **1**). Every record also
carries a leading schema byte, so a migration can rewrite records lazily or in bulk.

**What happens on start.** Before the server opens the store it runs
`tidemark_meta::migrate::migrate(<db>, dry_run = false)`:

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
tidemark migrate --dry-run --data-dir /srv/tidemark   # prints from/to and the planned steps; writes nothing
systemctl stop tidemark
tidemark backup --data-dir /srv/tidemark ...           # optional extra copy
# install the new binary
systemctl start tidemark                            # runs the migration, writes meta/tidemark.redb.pre-vN.bak
```

Disk space: the pre-upgrade snapshot is a full copy of `tidemark.redb`; keep at least that much free
under `meta/`. Remove old `*.pre-v*.bak` files once the new version has run cleanly.

**Rollback / downgrade.** Stop the server, move `tidemark.redb` aside, rename
`tidemark.redb.pre-vN.bak` to `tidemark.redb`, start the previous binary. Writes made after the upgrade
are lost (blobs they created become orphans that `tidemark fsck --repair` / GC reclaim).

**For developers adding a migration.** Bump `CURRENT_SCHEMA`, append a
`Migration { from, to, name, apply }` to `tidemark_meta::migrate::REGISTRY`. `apply` gets the
`&WriteTxn`, must be deterministic (the writer may re-run it), and should rewrite only what changed.
Add a test that copies `crates/tidemark-meta/tests/fixtures/meta-v1.redb` (the committed v1 fixture)
and migrates it; never edit an existing fixture, add `meta-vN.redb` instead.

## Backup and restore

```sh
tidemark backup  --data-dir /srv/tidemark --to /mnt/backup/tidemark \
                 --passphrase-file /root/backup.pass [--include-keys] [--full]   # incremental by default
tidemark backup ls --from /mnt/backup/tidemark                                   # manifest ids, oldest first
tidemark restore --from /mnt/backup/tidemark --data-dir /srv/tidemark-restored [--id <manifest>] \
                 [--passphrase-file /root/backup.pass]
```

**Off-site copy.** Release binaries back up to a directory only. Copy that directory anywhere
`rclone` reaches (another Tidemark, S3, B2, SFTP). A set only ever gains files, and an encrypted
set is ciphertext except `tidemark-backup.json`, so a plain sync is safe:

```sh
# /etc/cron.d/tidemark-backup: hourly incremental, then mirror off-site
0 * * * * root tidemark backup --data-dir /srv/tidemark --to /mnt/backup/tidemark \
  --passphrase-file /root/backup.pass && rclone sync /mnt/backup/tidemark offsite:tidemark-backup
```

To restore from off-site, `rclone sync` the set back to a local directory first. A build with
`--features remote` can also use `--to s3://bucket/prefix --endpoint https://…` directly
(credentials from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`).

**What a backup contains.** A backup *set* (a directory) holds `tidemark-backup.json`
(format, KDF salt and parameters, key check), one manifest per backup, one metadata dump per
backup and a shared, content-addressed `blobs/` area. The metadata dump is every table read from
**one redb read transaction**, and the blob list comes from the same snapshot, so a backup is the
state of a single commit even while the server keeps serving traffic. Because blobs are immutable
and named by hash, an incremental backup uploads only blobs that the newest previous manifest does
not list; `--full` uploads everything again. Each manifest lists every blob needed to restore it,
so any manifest restores on its own.

**Encryption.** With a passphrase the whole set is encrypted: argon2id (64 MiB, 3 passes) derives
the set key from the passphrase; each file gets a random salt and a BLAKE3-derived subkey and is
sealed in 64 KiB ChaCha20-Poly1305 chunks with a STREAM nonce (truncation, reordering and tampering
are detected). Manifests and the metadata dump are sealed too; only `tidemark-backup.json` is clear
text. A set is either encrypted or not: use a new destination to change that or the passphrase.
`--include-keys` (only allowed with a passphrase) also saves `<data_dir>/keys/`; without it, keep
`keys/master.key` somewhere safe yourself — blobs encrypted at rest cannot be read without it.

**Restore** refuses a directory that already has `meta/tidemark.redb`. It downloads and verifies every
file (size + BLAKE3 from the manifest; plaintext blobs must also hash to their id), then loads the
metadata dump into a fresh redb file. Start `tidemark serve` on the restored directory as usual; run
`tidemark fsck --verify full` once as a drill.

**Schedule and retention.** Run `tidemark backup` from cron/systemd timers (e.g. hourly incremental,
weekly `--full` into a new set). Pruning inside a set is not implemented yet (blobs are shared
between manifests); rotate whole sets instead. A blob that GC deletes while a backup is running
makes that backup fail with a clear error; just run it again.

## fsck and scrub

```sh
tidemark fsck --data-dir /srv/tidemark [--verify none|sample:1000|full] [--repair] [--json]
tidemark scrub --data-dir /srv/tidemark [--rate 50MiB] [--concurrency 2] [--once]
```

`tidemark fsck` compares metadata and blobs: **orphan blobs** (file without a metadata row, older
than 1 h so in-flight uploads are not flagged), **missing blobs** (referenced, file absent),
**refcount drift** (stored refcount ≠ references counted in versions + multipart uploads),
**corrupt blobs** (BLAKE3 mismatch; `--verify` chooses none / a random sample / all), **dangling
multipart uploads** (bucket gone, index rows missing or orphaned) and **`latest` rows** that are
not the newest live version. It also lists the damage registry (findings of scrub and earlier
runs). Exit status: 0 clean, 1 findings, 2 error.

`--repair` only does safe, reversible things, and is safe on a running server (each fix re-checks
its precondition inside the metadata transaction; rows that changed meanwhile are skipped and
reported):
- refcounts are rewritten to the recounted value (keeping the GC index consistent);
- orphan files are *indexed for GC* (refcount 0) — GC deletes them after its grace period, so an
  orphan that turns out to be needed can still be recovered from disk until then;
- versions whose blobs are missing or corrupt are **flagged damaged**, never deleted: GET/HEAD
  answer `500 InternalError` with `x-tidemark-damaged: true`. Heal them by restoring the blob (from a
  backup) and re-run
  `fsck --repair`, which clears flags of blobs that verify again;
- dangling uploads are aborted and `latest` rows recomputed.

`tidemark scrub` re-hashes referenced blobs in the background in blob-id order, under an IO budget
(`rate` bytes/s, `concurrency` parallel reads), skipping blobs verified within
`reverify_after` (default 30 days). Progress (`scrub/cursor`) and per-blob last-verified times
(`scrub/at/<blob>`) live in the `kv` table, so it resumes after restarts. Corrupt or missing blobs
go to the damage registry and are logged at error level; run `tidemark fsck --repair` to flag the
affected versions. Defaults: 50 MiB/s, 2 concurrent, one pass then sleep 24 h.

```toml
[storage.scrub]
enabled = true
rate = "50MiB"
concurrency = 2
reverify_after = "30d"
idle_between_passes = "24h"
```

## Disk full

Tidemark keeps a free-space **reserve** on the data volume (default 1 GiB, `[storage] min_free`).
Before a PUT, UploadPart, UploadPartCopy, CopyObject or CompleteMultipartUpload writes blob data,
the engine checks `statvfs` on the data directory; if free space minus the declared length would
fall below the reserve, the request fails immediately with **507** (`InsufficientStorage`, with
`Retry-After: 60` and `x-tidemark-storage-full: true`) before any byte is streamed. A write that
still hits `ENOSPC` mid-stream is cleaned up and answered the same way. The reserve leaves room
for metadata commits, so reads, deletes, trash purges, lifecycle and GC keep working and the
server stays up and ready. Response bodies never include disk figures.

To recover: free space (purge trash with `tidemark admin trash purge`, lower retention, run
`tidemark gc` or add capacity), then writes resume automatically. Run `tidemark fsck`
afterwards if the disk filled completely (a crash at ENOSPC can leave orphan blobs, which fsck
indexes for GC). Alert well before the reserve is reached (`/metrics` free bytes).
