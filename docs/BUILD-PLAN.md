# Tidemark — Build plan (v0.1: alpha → beta → stable)

Scope lives in `docs/DESIGN.md` (§0 says what is in, what is out, and the four claims). Done means
every row in `docs/PRODUCTION-READINESS.md` is checked. Decisions and their reasons are in
`docs/DECISIONS.md`. Dates are UTC.

## The one sentence

Tidemark v0.1 is **a single-binary S3 server you cannot lose data on**: one box, one data directory,
every delete reversible with nothing configured, every bucket readable as of any time in its
retention window, blobs deduplicated, and an MCP server that obeys the same policies as S3.
Nothing else ships in v0.1.

## The competitor that matters

VaultS3 (Go, AGPL, single binary, 1.7k stars, v5, externally audited, 17 MiB idle) already ships
everything we shelved plus a dashboard. We will not out-feature it. We ship four claims it cannot
make (DESIGN §0) and prove each one with a test or a published number. Any work item that does not
serve a claim, a table-stakes row, or the release itself is out.

## Environment
- Build host: 1 vCPU, 32 GB RAM, Rust stable 1.99. Iterate with `cargo check -p` / `cargo test -p`;
  run `cargo test --workspace` only at milestones. Never `--release` while developing.
- One checkout, several agents: Cargo serialises on the target-dir lock; do not delete `target/`.
- Tests use temp dirs and `127.0.0.1:0`; no network.

## Fixed decisions
`s3s` 0.17 protocol layer · `redb` metadata · BLAKE3 content-addressed blobs on the filesystem ·
`hyper`/`axum`/`rustls` (no OpenSSL) · `postcard` records with a schema byte · `tokio` ·
`rmcp` 3 for MCP · edition 2024 · `#![forbid(unsafe_code)]` · AGPL-3.0-only · DCO, no CLA.
Crate API contracts are documented in each crate's `lib.rs` rustdoc.

## Where we are (2026-11-09)

Every row in `docs/PRODUCTION-READINESS.md` is checked. `v0.1.0-alpha.3` (first release named
Tidemark) is public: binaries, SBOMs, checksums and an anonymously pullable image. Numbers: ~290
workspace tests, 322/370 ceph s3-tests (87.0%), binary 14.6 MiB x86_64, idle 10.4 MiB, all CI
green (on GitHub-hosted runners).

## Remaining work

Ordered. Each step lands only when the one before it is green; nothing from a later block starts
early unless it is blocked on nothing and someone has spare time.

### Block 0 — unbreak the quickstart ✅ 2026-11-09

`v0.1.0-alpha.3` tagged and released (run 42653905651, all six jobs green); the GHCR package was
already public. README "Linux binary" and "Quick start" (clone, `scripts/start.sh`, delete,
`trash restore`, byte-identical) re-run anonymously from empty directories; the post-release
`compose` run is green.

### Block 1 — alpha → beta: the data directory becomes a promise

Beta means: a data directory written by release N opens in release N+1, always. Today alpha.3
breaks alpha.2 directories and the CHANGELOG says so. From `beta.1` on that is forbidden.

| # | Work | Proof |
|---|------|-------|
| 1.1 ✅ | Freeze the on-disk formats: `meta` schema version, `postcard` record schema bytes, blob layout, credential-store labels, backup format. Write them down in DESIGN §4 as "frozen at beta.1; changes go through `migrate`". | DESIGN §4 table; DECISIONS entry |
| 1.2 ✅ | Upgrade test in CI: download the previous release binary, `init` + write a mixed workload (versions, multipart, tags, policy, trash, encrypted store), stop; open with the current build, `migrate --dry-run` then `serve`; every byte and every version id identical, `fsck` clean. Runs on every push for every release since alpha.3. | `.github/workflows/upgrade.yml`; `scripts/upgrade-test.sh` |
| 1.3 | Soak: 24 h under `rclone` + `warp` mixed load with a kill -9 every 10 min and a disk-full window; `fsck --verify` clean at the end, RSS flat. One scheduled workflow (weekly) on a GitHub-hosted runner, shorter (2 h) with the same shape. | `.github/workflows/soak.yml`; numbers in OPERATIONS.md — 2026-11-10: script + weekly 2 h workflow done, first 30 min run PASS (2.25 M requests, fsck clean, RSS ≤ 180 MiB); **24 h run still open** |
| 1.4 ✅ | Drop `aws-sdk-s3` from `tidemark-blob` and `tidemark-server` (only tiering used it; tiering is shelved). Keep it as a dev-dependency for tests. Expect a smaller binary and fewer `cargo audit` ignores. | done 2026-11-09: AWS SDK behind `remote`, OIDC/JWT behind `oidc`, `rustls-pemfile` replaced; 17.3 → 14.6 MiB; one advisory ignore removed (DECISIONS) |
| 1.5 ✅ | Fuzz targets promised in DESIGN §14: SigV4 parse/verify plus presign round trip, policy JSON parse/evaluate (Deny-all always wins), our S3 header parsers (`as-of`, tagging, copy range), metadata key encoding. XML is parsed by s3s, and blob paths come from content hashes, so neither takes attacker input in our code. Nightly 4 × 150 s. | done 2026-11-09: `fuzz/` (4 targets, 132K–8M clean runs locally, a removed key separator caught in seconds); `.github/workflows/fuzz.yml` |
| 1.6 ✅ | Security self-review of the auth boundary before anyone else looks: presign edge cases, policy evaluator condition keys, admin API, STS, admin-ui backends. Findings become tests or DECISIONS entries. | done 2026-11-10: `docs/SECURITY-REVIEW-2026-11-10.md`; 5 fixes (2 high, 3 medium), each with a test that fails on the old code; 3 accepted items in DECISIONS |
| 1.7 ✅ | Performance numbers. DESIGN §13 states targets nobody has measured. Run `warp` on one fixed machine, publish the real numbers in OPERATIONS.md, and either keep or lower the §13 targets to match. No bench harness beyond one script. | done 2026-11-10: 3 runs on GitHub-hosted 4 vCPU; OPERATIONS.md "Throughput"; DESIGN §13 lowered to the measured numbers (small PUT ~2 100/s, not 5 000) |

Exit: `v0.1.0-beta.1` tagged with the upgrade test green from alpha.3 → beta.1.

### Block 1b — malware scanning (after beta.1, before v0.1.0)

| # | Work | Proof |
|---|------|-------|
| 1b.1 | `[scan]`: stream PUT / CompleteMultipartUpload / CopyObject to clamd `INSTREAM` or an HTTP endpoint before commit; infected → `quarantine/<bucket>/<key>` + `400 VirusDetected`; fail closed; compose `scan` profile. No new on-disk format. | `crates/tidemark-server/tests/scan.rs` (fake clamd + fake HTTP endpoint; two removed checks caught); real ClamAV + EICAR run locally (PUT, zip, 20 MiB multipart); OPERATIONS.md "Malware scanning" |

### Block 2 — beta → v0.1.0

| # | Work | Proof |
|---|------|-------|
| 2.1 | Two beta releases at least two weeks apart with the upgrade test passing between them and no data-affecting bug open. | release history |
| 2.2 ✅ | Operations kit: Prometheus alert rules (disk, trash growth, scrub damage, gc stalls), one Grafana dashboard JSON, a backup-to-remote cron example using `tidemark backup` + `rclone`. Small files under `deploy/`. | `deploy/prometheus/`, `deploy/grafana/`, `deploy/backup/`, OPERATIONS.md "Monitoring"; done 2026-11-10: 11 promtool-tested rules, 23-panel dashboard, `scripts/deploy-kit-test.sh` in CI; found and fixed: live servers could not be backed up (now `tidemark admin backup`) |
| 2.3 ✅ | s3-tests: decide the `[s3 alt]` question for good. A second account means multi-account IAM, which v0.1 does not have; write the decision down and stop re-triaging those ~28 tests. Anything else that fails is a bug or a documented AWS-vs-Ceph difference. | DECISIONS entry; `expected-pass.txt`; done 2026-11-10: 20 alt-identity tests stay failing by decision; 1 bug fixed (Complete checksum); root-deny deviation documented |
| 2.4 | Issue flow: respond to every issue within a week; each bug fixed carries a regression test; each `s3-compat` issue adds its test name to `expected-pass.txt` when fixed. | issue templates (exist); labels (exist) |
| 2.5 | Announce once: release notes for v0.1.0, one post (r/selfhosted or HN), README comparison table re-verified on that day. | CHANGELOG `[0.1.0]` |

After v0.1.0: single-node erasure coding across disks, sketched in
`docs/DESIGN-v0.2-MULTI-DISK.md` (3–4 weeks; starts only on a real issue).

### Not planned

The shelved list below stays shelved. Likely requests, in the order we expect them: OIDC login,
Object Lock / WORM, bucket quotas, CORS for browser uploads, replication to a second box. Each
needs an issue with real demand and a DECISIONS entry saying which §0 claim it serves or why a
table-stakes row now requires it. A dashboard with object browsing is not planned; the admin UI
stays status/buckets/users/keys/restore and S3 clients do the browsing.

## Shelved (code may exist; not wired, not tested in CI, not documented as features)
Replication · blob tiering · events outbox, webhooks, function sinks, SSE stream · OIDC federation ·
Object Lock · SSE-C / KMS · rate limiting · TLS hot reload · bucket quotas · CORS · PostObject ·
erasure coding · compression · full-text / vector search · FUSE · S3 Select · bench harness ·
built-in admin UI · `ai` feature · Helm · multi-node. Each returns only with a DESIGN.md entry saying which
§0 claim it serves.

An optional local admin UI lives in `admin-ui/`: one HTML/JS page plus a single-file Python or PHP
backend that holds the keys and signs admin API calls. Nothing is added to the server binary.

## Working agreements
- Lane 1 owns `tidemark-server`, `tidemark-cli`; lane 2 owns `tidemark-engine`, `tidemark-blob`, tests under
  `crates/tidemark-server/tests/`; lane 3 owns `scripts/`, `.github/`, `deploy/`, `docs/`,
  `README.md`, `CONTRIBUTING.md`. Touching another lane's files: additive only, say so in the
  commit message.
- `docs/COMPAT.md` and `docs/EXTENSIONS.md` are updated in the same commit as the behaviour.
- A DESIGN change gets a dated entry in `docs/DECISIONS.md` in the same commit.
- Commits carry `Signed-off-by` (DCO). No CLA, ever.
