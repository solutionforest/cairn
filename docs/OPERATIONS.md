# Cairn — Operations guide

Sections are owned by the agent that wrote them; append new sections, do not rewrite others.

## Footprint

Run 2026-11-08T19:14Z by `scripts/footprint.sh`: cairn 0.1.0 @ f922680 plus the size-optimised
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
regular Linux kernel by `.github/workflows/footprint.yml` (self-hosted runner, size + idle,
fails over budget); the step summary of the latest run is the number to quote.

**Size profile cost.** Server CPU per GiB, measured with `aws s3 cp` on this host for opt-level
3 / `s` / `z`: put 2.6 / 2.4–2.6 / 2.5–2.6 s, get 4.9–5.3 / 5.5 / 5.2 s, i.e. inside run-to-run
noise. Hashing (BLAKE3, SHA-2, CRC) runs on SIMD/assembly paths whatever the opt-level.

Against the v0.1 limits (PRODUCTION-READINESS E1, E2): the 10 GiB round trip stays far under
256 MiB, so uploads and downloads stream; the binary is under 20 MB. Re-measure with
`scripts/footprint.sh target/x86_64-unknown-linux-musl/release/cairn`; set
`FOOTPRINT_MAX_BINARY_BYTES` / `FOOTPRINT_MAX_IDLE_MIB` / `FOOTPRINT_MAX_PEAK_MIB` to make it
fail over budget.

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

## OIDC federation (`AssumeRoleWithWebIdentity`)

*(Agent B, phase 3c.)* Workloads that already hold an OIDC ID token — GitHub Actions, GitLab CI,
Kubernetes service-account tokens, Google / Azure AD / Keycloak / Dex users — can exchange it for
temporary Cairn credentials without any long-lived key, exactly like AWS STS
`AssumeRoleWithWebIdentity`.

**1. Trust the identity provider** (server config; one block per issuer — the TOML keys map 1:1
onto `cairn_auth::OidcProviderConfig`; until `cairn serve` reads them, embedders build an
`OidcVerifier` and call `StsState::with_oidc`):

```toml
[[auth.oidc_providers]]
issuer    = "https://token.actions.githubusercontent.com"   # must equal the token's `iss`
audiences = ["cairn"]                                        # accepted `aud` values (≥ 1)
jwks_url  = "https://token.actions.githubusercontent.com/.well-known/jwks"
# jwks    = '{"keys":[...]}'          # inline JWKS instead of jwks_url (air-gapped IdPs)
[auth.oidc_providers.claim_tags]      # optional: claim -> session tag (aws:PrincipalTag/<tag>)
repository_owner = "org"
environment      = "env"
```

Rules: `issuer` and `jwks_url` must be `https://` (plain `http://` only on loopback, for
development); no OIDC discovery — give the JWKS URL. Only asymmetric algorithms are accepted
(RS256/384/512, PS256/384/512, ES256/384); `HS*` and `none` are rejected, as are symmetric or
encryption JWKs. The token must carry `iss`, `aud`, `sub` and `exp`; `exp`/`nbf` get 60 s of clock
leeway. The JWKS is fetched over rustls (no redirects, 5 s timeout, ≤ 1 MiB), cached for 1 h; a
token with an unknown `kid` triggers at most one refetch per provider every 10 s (key rotation
without a restart, without letting unauthenticated callers hammer the IdP). If a refetch fails,
cached keys keep working.

The **provider id** is the issuer without scheme (`token.actions.githubusercontent.com`). It
prefixes the trust-policy condition keys and may be used as the `Federated` principal.

**2. Create a role whose trust policy names the provider:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {"token.actions.githubusercontent.com:aud": "cairn"},
      "StringLike":   {"token.actions.githubusercontent.com:sub": "repo:acme/website:ref:refs/heads/main"}
    }
  }]
}
```

```sh
cairn admin role create ci-deploy --trust trust.json --max-session 3600
cairn admin role policy put ci-deploy write-site site-write.json
```

`Federated` accepts the issuer URL, the provider id or
`arn:aws:iam::000000000000:oidc-provider/<provider id>`. **Always constrain `sub`** (and `aud`):
without a condition every identity the IdP can mint may assume the role. `Principal: "*"` never
admits a web identity; an explicit `Deny` (federated or `*`) always wins.

Condition keys available in the trust policy: `<provider>:sub`, `<provider>:aud` (multi-valued),
`<provider>:iss`, `<provider>:azp`, `<provider>:email`, `<provider>:amr`,
`aws:FederatedProvider`, `aws:RequestTag/<tag>` and `aws:TagKeys` (from `claim_tags`),
`aws:SourceIp`, `aws:SecureTransport`, `aws:CurrentTime`, `aws:EpochTime`. Mapped tags stay on
the session as `aws:PrincipalTag/<tag>`, so one role can scope access per team, e.g.
`"Resource": "arn:aws:s3:::builds/${aws:PrincipalTag/org}/*"`.

**3. Exchange the token** (unsigned STS call, `POST /` form or `GET /?Action=…`):

```sh
aws sts assume-role-with-web-identity --endpoint-url https://cairn.example.com \
  --role-arn arn:aws:iam::000000000000:role/ci-deploy \
  --role-session-name "gha-$GITHUB_RUN_ID" \
  --web-identity-token "$ID_TOKEN" --duration-seconds 900
```

SDKs pick this up automatically with `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE` and
`AWS_ENDPOINT_URL_STS=https://cairn.example.com`. Duration: 15 min to the role's max session
(≤ 12 h). An optional `Policy` session policy narrows the session further.

Errors (AWS codes): `InvalidIdentityToken` (bad signature, wrong issuer / audience, unknown
`kid`, unsupported algorithm, federation not configured), `ExpiredTokenException`,
`IDPCommunicationError` (JWKS unreachable and nothing cached), `AccessDenied` (trust policy did
not allow it, or the role does not exist — the two are indistinguishable on purpose).

**Operating it.** Sessions show up in `cairn admin session ls` with source
`oidc:<provider>/<sub>`; revoke one with `cairn admin session revoke <access-key-id>`, or all of a role's by
deleting the role (`cairn admin role rm`). Removing a provider from the
config stops new exchanges immediately; already issued sessions run until they expire unless
revoked. The token itself is never logged or stored; the audit line is
`sts assume-role-with-web-identity role=… provider=… subject=… access_key_id=…`.

## Replication

*(Agent D, phase 3b. Library: `cairn_engine::replication`. The `cairn replicate …` subcommands
and the S3 bucket-replication operations are wired by Agent A; the semantics below are final.)*

Cairn replicates buckets asynchronously to another Cairn server or to any S3 endpoint (AWS,
Backblaze B2, MinIO, R2, …). This is the v1 HA story: active-passive, RPO = replication lag.

**1. Register the destination** (credentials never go into the bucket configuration; secrets are
stored sealed with ChaCha20-Poly1305 under a key derived from the server master key):

```sh
cairn replicate target add arn:aws:s3:::photos-dr \
  --endpoint https://dr.example.com --region us-east-1 --bucket photos-dr \
  --access-key AKIA… --secret-key-file /run/secrets/dr-secret \
  --cairn-peer                 # destination is Cairn: keep version ids (x-cairn-version-id)
cairn replicate target ls      # ARN, endpoint, bucket, access key (never the secret)
cairn replicate target rm arn:aws:s3:::photos-dr
```

The ARN is the name rules refer to; it does not have to match the remote bucket name.

**2. Enable versioning on both buckets and put a standard S3 replication configuration:**

```sh
aws s3api put-bucket-versioning --bucket photos --versioning-configuration Status=Enabled
aws s3api put-bucket-replication --bucket photos --replication-configuration '{
  "Role": "arn:aws:iam::000000000000:role/unused",
  "Rules": [{"ID": "all", "Priority": 1, "Status": "Enabled", "Filter": {"Prefix": ""},
             "DeleteMarkerReplication": {"Status": "Enabled"},
             "Destination": {"Bucket": "arn:aws:s3:::photos-dr"},
             "ExistingObjectReplication": {"Status": "Enabled"}}]}'
```

Supported rule elements: `ID`, `Priority`, `Status`, `Filter` (`Prefix`, `Tag`, `And`), the V1
`Prefix` form, `DeleteMarkerReplication`, `ExistingObjectReplication`, `Destination` (`Bucket`,
`Account`, `StorageClass`). `Role` is accepted and echoed but unused. Validation follows AWS
(filter rules need `Priority` and `DeleteMarkerReplication`; no delete-marker replication on
tag-filtered rules; unique IDs and priorities). The source bucket must have versioning
`Enabled` (`InvalidRequest` otherwise).

**What is replicated.** Every new object version and (when enabled) delete marker selected by a
rule, in creation order, with key, content, `Content-*` headers, `x-amz-meta-*`, tags and the
**multipart part layout** (so the ETag is identical). With `--cairn-peer` the destination also
keeps the source **version id** and timestamps, and re-delivery is idempotent. Not replicated
(same as AWS): version-specific deletes, Object Lock retention / legal hold, trash purges. Trash
restores and PITR restores are ordinary new versions and replicate normally. Without
`ExistingObjectReplication` only versions written after the configuration was put are sent.

**Delivery.** A background worker scans each replicated bucket every 2 s and keeps a durable
cursor per (bucket, destination) in the `repl_cursor` table, so restarts resume where they
stopped. Delivery is at-least-once: after a crash the last ≤ 32 versions may be sent again
(no-ops on Cairn peers; on plain S3 targets they become duplicate versions with identical
content). Transient failures (network, 5xx, throttling, 403/404 config errors, unknown target)
back off exponentially from 1 s to 5 min per destination; permanent failures (400-class) skip
the version, count it in `failed` and keep the message in `last_error`.

**Monitoring.** `cairn replicate status [--bucket b] [--json]` and `/metrics` show per
destination: `pending`, `lag` (age of the oldest unsent version), `delivered`, `failed`,
`last_error`, `backing_off`. HEAD/GET on the source return `x-amz-replication-status:
PENDING|COMPLETED`. `cairn replicate retry` clears backoff after fixing a target. Alert on lag
growing for more than a few minutes.

**Failover / failback runbook.** (1) Point clients at the replica (DNS or load balancer).
(2) On the replica, put a replication configuration back to the old primary with
`ExistingObjectReplication` enabled once it is reachable again; with `--cairn-peer` versions that
already exist on the old primary are skipped by id. (3) When caught up (`pending = 0`), switch
clients back and remove the reverse rule. Bidirectional rules are safe from loops between Cairn
peers (a replica write of an existing version id is a no-op) but double the scan work.

**Limits.** Each tick reads every version row of a replicated bucket (fine up to a few million
versions per bucket on NVMe; an engine change index can replace the scan later without changing
the cursor). `null` versions written before versioning was enabled replicate as regular versions.

## Tiering

*(Agent D, phase 3b. Library: `cairn_blob::tiered`; server config and the background task are
wired by Agent A.)*

Blob tiering keeps metadata and hot blobs on local disk and moves cold blobs to a remote S3
bucket, so capacity can exceed the host. The S3 API and the write path are unchanged.

```toml
[storage.tiering]
enabled            = true
min_idle           = "30d"      # not read or written for this long (file mtime = last access)
min_size           = "1MiB"     # optional: only move blobs at least this large
rehydrate_on_read  = false      # true: the first GET moves a cold blob back to local disk
interval           = "1h"       # how often the mover runs
[storage.tiering.remote]
endpoint = "https://s3.eu-central-1.amazonaws.com"
region = "eu-central-1"
bucket = "cairn-cold"
prefix = "node-1/"
access_key = "AKIA…"
secret_key_file = "/run/secrets/cold"
```

**How it works.** The mover uploads the blob file as stored (encrypted blobs stay encrypted on
the remote) to `<prefix><hex>` / `<prefix><hex>.enc`, writes a stub `blobs/ab/cd/<hex>.cold`
(`cairn-cold 1 <size> <encrypted>`), then removes the local file. Reads of a cold blob are
transparent: plaintext blobs are fetched with ranged GETs, encrypted blobs are fetched whole into
`tmp/` and decrypted locally; the remote copy is verified (BLAKE3) on rehydration. Hot reads bump
the file's mtime at most once an hour. Deleting a blob (GC) removes the local file, the stub and
the remote object.

**Operational notes.** If the remote is unreachable, GETs of cold blobs fail with 500 while hot
data and all writes keep working. `cairn scrub` skips cold blobs (re-hashing would download
them); verify the remote bucket with its own tooling or `rehydrate_on_read`. `cairn backup`
copies stubs, not cold data: protect the cold bucket with its own versioning / replication.
Never point two Cairn nodes at the same bucket + prefix.

## Backup and restore

*(Agent D, phase 3b. Library: `cairn_engine::backup::{backup, restore, list_backups}`; CLI wiring
by Agent A.)*

```sh
cairn backup  --data-dir /srv/cairn --to /mnt/backup/cairn            # incremental by default
cairn backup  --data-dir /srv/cairn --to s3://backups/cairn/ --endpoint https://… \
              --passphrase-file /root/backup.pass [--include-keys] [--full]
cairn backup ls --from /mnt/backup/cairn                               # manifest ids, oldest first
cairn restore --from /mnt/backup/cairn --data-dir /srv/cairn-restored [--id <manifest>] \
              [--passphrase-file /root/backup.pass]
```

**What a backup contains.** A backup *set* (directory or S3 prefix) holds `cairn-backup.json`
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
are detected). Manifests and the metadata dump are sealed too; only `cairn-backup.json` is clear
text. A set is either encrypted or not: use a new destination to change that or the passphrase.
`--include-keys` (only allowed with a passphrase) also saves `<data_dir>/keys/`; without it, keep
`keys/master.key` somewhere safe yourself — blobs encrypted at rest cannot be read without it.

**Restore** refuses a directory that already has `meta/cairn.redb`. It downloads and verifies every
file (size + BLAKE3 from the manifest; plaintext blobs must also hash to their id), then loads the
metadata dump into a fresh redb file. Start `cairn serve` on the restored directory as usual; run
`cairn fsck --verify full` once as a drill.

**Schedule and retention.** Run `cairn backup` from cron/systemd timers (e.g. hourly incremental,
weekly `--full` into a new set). Pruning inside a set is not implemented yet (blobs are shared
between manifests); rotate whole sets instead. A blob that GC deletes while a backup is running
makes that backup fail with a clear error; just run it again.

## fsck and scrub

*(Agent D, phase 3b. Library: `CairnEngine::fsck`, `cairn_engine::scrub::Scrubber`; CLI and the
background task are wired by Agent A.)*

```sh
cairn fsck --data-dir /srv/cairn [--verify none|sample:1000|full] [--repair] [--json]
cairn scrub --data-dir /srv/cairn [--rate 50MiB] [--concurrency 2] [--once]
```

`cairn fsck` compares metadata and blobs: **orphan blobs** (file without a metadata row, older
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
  answer `500 InternalError` with `x-cairn-damaged: true`. Heal them by restoring the blob (from a
  backup or a replica, e.g. re-replicate with `ExistingObjectReplication`) and re-run
  `fsck --repair`, which clears flags of blobs that verify again;
- dangling uploads are aborted and `latest` rows recomputed.

`cairn scrub` re-hashes referenced blobs in the background in blob-id order, under an IO budget
(`rate` bytes/s, `concurrency` parallel reads), skipping blobs verified within
`reverify_after` (default 30 days). Progress (`scrub/cursor`) and per-blob last-verified times
(`scrub/at/<blob>`) live in the `kv` table, so it resumes after restarts. Corrupt or missing blobs
go to the damage registry and are logged at error level; run `cairn fsck --repair` to flag the
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

*(Agent D, phase 3b. Library: `cairn_blob::space`; put-path wiring by Agent A.)*

Cairn keeps a free-space **reserve** on the data volume (default 1 GiB, `[storage] min_free`).
Before a PUT, UploadPart, UploadPartCopy, CopyObject or CompleteMultipartUpload writes blob data,
the engine checks `statvfs` on the data directory; if free space minus the declared length would
fall below the reserve, the request fails immediately with **507** (`InsufficientStorage`, with
`Retry-After: 60` and `x-cairn-storage-full: true`) before any byte is streamed. A write that
still hits `ENOSPC` mid-stream is cleaned up and answered the same way. The reserve leaves room
for metadata commits, so reads, deletes, trash purges, lifecycle and GC keep working and the
server stays up and ready. Response bodies never include disk figures.

To recover: free space (purge trash with `cairn admin trash purge`, lower retention, run
`cairn gc`, add capacity or enable tiering), then writes resume automatically. Run `cairn fsck`
afterwards if the disk filled completely (a crash at ENOSPC can leave orphan blobs, which fsck
indexes for GC). Alert well before the reserve is reached (`/metrics` free bytes).
