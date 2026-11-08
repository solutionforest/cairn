# Cairn v0.1 — Definition of done

Thirty-six rows. Each `[x]` names its proof (test file, CI job, or doc). The first public tag
waits for every row. Shelved features (BUILD-PLAN "Shelved") have no rows here on purpose.
Rows marked **claim** are the four DESIGN §0 claims against VaultS3 and RustFS; a release with
any of them unproven is a release of a worse VaultS3.

Legend: `[ ]` todo · `[~]` partial · `[x]` done.

## A. S3 compatibility
- [x] A1 `cairn init` + `cairn serve` boot from one TOML file. (crates/cairn-cli/tests/cli.rs)
- [x] A2 Every S3 op in COMPAT.md has an `aws-sdk-s3` integration test: bucket CRUD, Put/Get/Head/Delete(s), Copy, List v1/v2/versions, versioning, 7 multipart ops, tagging, metadata, Range + conditionals, 5 checksum algorithms, AWS-shaped error XML with request ids. (crates/cairn-server/tests/*.rs)
- [ ] A3 `aws s3 cp/sync/ls/rm`, `rclone sync`, `mc` pass `scripts/e2e-clients.sh`; results table in COMPAT.md.
- [ ] A4 ceph `s3-tests` runs on every push and fails CI if any test in the committed `scripts/s3-tests/expected-pass.txt` regresses; a weekly full sweep reports new passes to promote; baseline ≥ 80% of the non-shelved subset. (scripts/s3-tests/, .github/workflows/s3-tests.yml)
- [~] A5 **claim 2** PITR without a prior snapshot: `x-cairn-as-of` reads and `cairn pitr restore` to an arbitrary instant, including an instant before a bucket delete, integration-tested through the server; retention GC tested. (soft delete + as-of: crates/cairn-server/tests/pitr.rs; trash/retention engine-only: crates/cairn-engine/tests/engine.rs; restore-across-bucket-delete pending)
- [ ] A6 **claim 1** Zero-config undo: a fresh bucket with versioning never enabled; overwrite an object, delete it, delete the bucket; `cairn trash restore` brings back bucket and every version byte-identical, through the server and the CLI.
- [ ] A7 **claim 3** Dedup proven: N uploads of identical bytes leave one blob file; CopyObject, trash restore and PITR restore add zero blob bytes on disk (asserted by walking `blobs/`); an encrypted store dedups the same way.

## B. Security
- [x] B1 SigV4 header + presigned verification with credential-store lookup; expired presign rejected. (crates/cairn-server/tests/auth_wire.rs::unsigned_and_badly_signed_requests_are_rejected, ::expired_presigned_url_is_rejected)
- [x] B2 Policy evaluation on every S3, admin and MCP request: identity ∪ group ∪ bucket policy ∪ PublicAccessBlock; explicit deny wins. (crates/cairn-server/tests/auth_wire.rs::identity_group_and_bucket_policy_denies_win, ::public_bucket_policy_respects_public_access_block, ::admin_api_is_mounted_and_authenticated, ::admin_api_refuses_non_root_without_policy, ::mcp_http_is_mounted_and_authenticated, ::mcp_http_applies_the_same_explicit_deny_as_s3; cairn-auth/src/s3s_bridge/tests.rs)
- [x] B3 STS `AssumeRole` / `GetSessionToken`; sessions expire and are revocable. (crates/cairn-server/tests/auth_wire.rs::sts_session_works_and_is_revocable, ::assume_role_through_server_scopes_and_expires; cairn-auth/src/sts/tests.rs)
- [~] B4 Root credentials sealed in the credential store at `cairn init`, never logged; secrets zeroized and redacted. (cairn-admin/src/tests.rs::secrets_never_logged; `ensure_root` not called from init)
- [ ] B5 SSE-S3 at rest with a master key from file or env; plaintext blobs never written when enabled.
- [x] B6 `cargo deny` + `cargo audit` in CI, `SECURITY.md`, `forbid(unsafe_code)` everywhere. (.github/workflows/security.yml, deny.toml)
- [x] B7 Admin API requires root or `cairn:*` policy; CORS default-deny. (cairn-admin/src/tests.rs)

## C. Durability and recovery
- [~] C1 Crash consistency: kill -9 during put / multipart complete / delete leaves nothing half-committed; recovery sweeps `tmp/`. (recovery test exists; fault-injection test pending)
- [x] C2 GC never deletes a referenced blob. (crates/cairn-engine/tests/engine.rs::gc_never_deletes_referenced_blobs)
- [~] C3 `cairn fsck` detects orphan / missing / corrupt blobs and refcount drift; `--repair` fixes what is safe; GET of a damaged version fails loudly. (crates/cairn-engine/tests/fsck.rs 6 tests; subcommand + GET check pending)
- [~] C4 `cairn scrub` verifies blob hashes on a schedule with an IO budget. (crates/cairn-engine/tests/scrub.rs; not spawned from serve)
- [~] C5 `cairn backup` (full + incremental, encrypted) and `cairn restore` round-trip. (crates/cairn-engine/tests/backup.rs 5 tests; subcommands pending)
- [~] C6 Disk full → `507`, server stays up, GET/DELETE/GC still work. (cairn-blob SpaceGuard tested; put-path wiring + server test pending)
- [~] C7 Schema migrations with pre-upgrade snapshot and `cairn migrate --dry-run`. (cairn_meta::migrate + v1 fixture; subcommand pending)
- [x] C8 Graceful shutdown on SIGTERM drains requests and closes redb cleanly. (crates/cairn-cli/tests/cli.rs, crates/cairn-server/tests/server.rs)

## D. Operability
- [x] D1 `/healthz` and `/readyz`. (crates/cairn-server/tests/server.rs)
- [ ] D2 `/metrics`: requests by op/status, latency, bytes in/out, blob count/bytes, trash bytes, gc runs.
- [ ] D3 JSON logs with request-id correlation; audit JSONL for mutating and denied requests.
- [ ] D4 Lifecycle expiration + abort-incomplete-multipart and GC run on schedule; tested with a fake clock.
- [ ] D5 `cairn config check` prints the effective config with secrets masked; every key has a default and a `CAIRN_*` env override.
- [~] D6 Admin CLI: users, keys, groups, policies, roles, buckets, trash, pitr; `--json`. (cairn_admin::cli + loopback e2e test; not mounted in the binary)
- [~] D7 **claim 4** MCP server (stdio + HTTP) with the DESIGN §11 tools under policy: a principal denied `s3:GetObject` on a key is denied the same key through MCP `get_object`, and `as_of` tools require `cairn:TimeTravel`. (crates/cairn-mcp/tests/tools.rs 10 tests; not mounted; cross-channel deny test pending)

## E. Limits
- [~] E1 A 10 GiB upload and download complete with RSS under 256 MiB (streaming end to end); number recorded in OPERATIONS.md and README. (measured by scripts/footprint.sh, default 10 GiB streamed through `aws s3 cp -` with sha256 round-trip check; release-build run pending)
- [~] E2 Idle RSS ≤ 25 MiB (container working set after a 110 s settle, same method VaultS3 publishes) and static binary ≤ 20 MB; `scripts/footprint.sh` produces both, numbers in README next to the competitor table. (scripts/footprint.sh written and smoke-tested on a debug build with a 64 MiB transfer; release-build numbers not yet measured)

## F. Release
- [x] F1 fmt, clippy `-D warnings`, tests, docs green on every push. (.github/workflows/ci.yml, self-hosted while private)
- [~] F2 Tag → static musl x86_64 + aarch64 binaries, GHCR image, SBOM, checksums. (.github/workflows/release.yml reviewed 2026-11-08: all 12 action pins resolve to their tagged commits, static-link + `cargo audit bin` check, per-binary CycloneDX SBOM, SHA256SUMS, multi-arch GHCR from the released bytes; never exercised on a tag)
- [~] F3 README quickstart passes on a clean machine from a release binary; COMPAT.md, EXTENSIONS.md, OPERATIONS.md current. (README written; quickstart `serve` invocation and container root-credential bootstrap corrected 2026-11-08; not verified against a release binary)
- [~] F4 Name decided (crates.io `cairn`, `cairn-cli`, `cairn-core` are taken; see DECISIONS.md name check); rename done if needed before the tag.
- [x] F5 `CONTRIBUTING.md` states DCO sign-off and no CLA; README states the governance promises (no telemetry, no account, no licence key, nothing in the core moves behind a paid tier); README comparison table matches DESIGN §0 and every cell about Cairn is true today. (CONTRIBUTING.md "No CLA. DCO instead."; README.md "Promises" and "Compared with the alternatives": §0 rows/columns, Cairn cells name their proof or the pending row; footprint cells say "not yet measured" until scripts/footprint.sh runs on a release build)
