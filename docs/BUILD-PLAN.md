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

Every row in `docs/PRODUCTION-READINESS.md` is checked. `v0.1.0-alpha.2` is public; the rename
to Tidemark is committed but **`v0.1.0-alpha.3` is not tagged**, and the README quickstart and
`scripts/start.sh` already download it, so the quickstart 404s today. Numbers: 292 workspace tests,
322/370 ceph s3-tests (87.0%), binary 17.3 MiB x86_64, idle 10.4 MiB, all CI green on
GitHub-hosted runners.

## Remaining work

Ordered. Each step lands only when the one before it is green; nothing from a later block starts
early unless it is blocked on nothing and someone has spare time.

### Block 0 — unbreak the quickstart (today)

| # | Work | Proof |
|---|------|-------|
| 0.1 | Tag `v0.1.0-alpha.3` on `master`; the CHANGELOG section is already dated. | release run green: two binaries, SBOMs, SHA256SUMS, GHCR image |
| 0.2 | Make the new GHCR package `solutionforest/tidemark` public (package visibility does not follow the repo; the CLI token lacks `packages` scope, so this is a one-time UI step). Leave `cairn` as is; its last tag is alpha.2 and the old README pins it. | `docker pull ghcr.io/solutionforest/tidemark:v0.1.0-alpha.3` anonymously |
| 0.3 | Re-run the README quickstart and `scripts/start.sh` from an empty directory against the published tarball; run `compose` once. | the three commands in README "Start" succeed; `compose` workflow run green |
| 0.4 | This file. BUILD-PLAN described lanes that finished a day ago. | this section |

### Block 1 — alpha → beta: the data directory becomes a promise

Beta means: a data directory written by release N opens in release N+1, always. Today alpha.3
breaks alpha.2 directories and the CHANGELOG says so. From `beta.1` on that is forbidden.

| # | Work | Proof |
|---|------|-------|
| 1.1 | Freeze the on-disk formats: `meta` schema version, `postcard` record schema bytes, blob layout, credential-store labels, backup format. Write them down in DESIGN §4 as "frozen at beta.1; changes go through `migrate`". | DESIGN §4 table; DECISIONS entry |
| 1.2 | Upgrade test in CI: download the previous release binary, `init` + write a mixed workload (versions, multipart, tags, policy, trash, encrypted store), stop; open with the current build, `migrate --dry-run` then `serve`; every byte and every version id identical, `fsck` clean. Runs on every push once beta.1 exists. | `.github/workflows/upgrade.yml`; `scripts/upgrade-test.sh` |
| 1.3 | Soak: 24 h under `rclone` + `warp` mixed load with a kill -9 every 10 min and a disk-full window; `fsck --verify` clean at the end, RSS flat. One scheduled workflow (weekly) on a GitHub-hosted runner, shorter (2 h) with the same shape. | `.github/workflows/soak.yml`; numbers in OPERATIONS.md |
| 1.4 | Drop `aws-sdk-s3` from `tidemark-blob` and `tidemark-server` (only tiering used it; tiering is shelved). Keep it as a dev-dependency for tests. Expect a smaller binary and fewer `cargo audit` ignores. | `deny.toml` / `.cargo/audit.toml` ignore list shrinks; footprint job prints the new size |
| 1.5 | Fuzz targets promised in DESIGN §14 but never written: SigV4 header/query parsing reaching our code, policy JSON, lifecycle/tagging XML, key → blob path. Nightly 10-minute run. | `fuzz/` with 4 targets; `.github/workflows/fuzz.yml` |
| 1.6 | Security self-review of the auth boundary before anyone else looks: presign edge cases, policy evaluator condition keys, admin API, STS, admin-ui backends. Findings become tests or DECISIONS entries. | `docs/SECURITY-REVIEW-<date>.md` with each finding and its test |
| 1.7 | Performance numbers. DESIGN §13 states targets nobody has measured. Run `warp` on one fixed machine, publish the real numbers in OPERATIONS.md, and either keep or lower the §13 targets to match. No bench harness beyond one script. | `scripts/bench.sh`; OPERATIONS.md "Throughput" |

Exit: `v0.1.0-beta.1` tagged with the upgrade test green from alpha.3 → beta.1.

### Block 2 — beta → v0.1.0

| # | Work | Proof |
|---|------|-------|
| 2.1 | Two beta releases at least two weeks apart with the upgrade test passing between them and no data-affecting bug open. | release history |
| 2.2 | Operations kit: Prometheus alert rules (disk, trash growth, scrub damage, gc stalls), one Grafana dashboard JSON, a backup-to-remote cron example using `tidemark backup` + `rclone`. Small files under `deploy/`. | `deploy/prometheus/`, `deploy/grafana/`, OPERATIONS.md links |
| 2.3 | s3-tests: decide the `[s3 alt]` question for good. A second account means multi-account IAM, which v0.1 does not have; write the decision down and stop re-triaging those ~28 tests. Anything else that fails is a bug or a documented AWS-vs-Ceph difference. | DECISIONS entry; `expected-pass.txt` |
| 2.4 | Issue flow: respond to every issue within a week; each bug fixed carries a regression test; each `s3-compat` issue adds its test name to `expected-pass.txt` when fixed. | issue templates (exist); labels (exist) |
| 2.5 | Announce once: release notes for v0.1.0, one post (r/selfhosted or HN), README comparison table re-verified on that day. | CHANGELOG `[0.1.0]` |

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
  `crates/tidemark-server/tests/`; lane 3 owns `scripts/`, `.github/`, `deploy/`, `docs/`, `bench/`,
  `README.md`, `CONTRIBUTING.md`. Touching another lane's files: additive only, say so in the
  commit message.
- `docs/COMPAT.md` and `docs/EXTENSIONS.md` are updated in the same commit as the behaviour.
- A DESIGN change gets a dated entry in `docs/DECISIONS.md` in the same commit.
- Commits carry `Signed-off-by` (DCO). No CLA, ever.
