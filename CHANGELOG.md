# Changelog

All notable changes to Cairn are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may break
compatibility; breaking changes are called out under **Changed** or **Removed**).

The release workflow copies the section matching the tag (or `Unreleased`) into the GitHub
Release notes, so write entries for operators, not for developers.

## [Unreleased]

### Added
- Storage core: `redb` metadata store with group commit and point-in-time (`head_at`) queries;
  content-addressed filesystem blob store with BLAKE3 ids, streaming multi-hash writer and
  chunked AES-256-GCM encryption at rest.
- IAM: policy language and evaluator, credential store, STS sessions, SigV4 signing/presign.
- Engine and S3 layer (in progress): buckets, objects, versions, multipart uploads, checksums.
- Event notifications (`cairn-events`): S3 event-message 2.1 records plus `cairn:TrashRestored`,
  `cairn:PitrRestore`, `cairn:BucketDeleted`; `NotificationConfiguration` XML including
  `CloudFunctionConfiguration` / `LambdaFunctionConfiguration`; durable outbox committed in the
  same transaction as the mutation; per-sink delivery worker with exponential backoff, jitter
  and a dead-letter queue; webhook sink with HMAC-SHA256 signatures; function sinks with
  `bearer`, `sigv4-lambda` (AWS Lambda Invoke) and `cf-access` (Cloudflare Access) auth;
  Server-Sent Events stream at `/_cairn/v1/events`.
- Release engineering: static musl binaries for x86_64 and aarch64, multi-arch container image
  on `ghcr.io/solutionforest/cairn`, CycloneDX SBOMs, SHA256SUMS, `cargo deny` / `cargo audit`
  in CI, `SECURITY.md`.
- Deployment examples: `deploy/docker-compose.yml`, `deploy/cairn.service` (hardened systemd
  unit), `deploy/cairn.example.toml` (every key with its default).
- Tooling: `bench/` (warp-based benchmark harness), `scripts/s3-tests/` (ceph s3-tests runner
  with an allowed-failures list).

[Unreleased]: https://github.com/solutionforest/cairn/commits/master
