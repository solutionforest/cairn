# Changelog

All notable changes to Cairn are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may break
compatibility; breaking changes are called out under **Changed** or **Removed**).

The release workflow copies the section matching the tag (or `Unreleased`) into the GitHub
Release notes, so write entries for operators, not for developers.

## [Unreleased]

## [0.1.0-alpha.1] - 2026-11-09

First pre-release. Single node, one data directory, one static binary. On-disk formats may
still change before 0.1.0; `cairn migrate` handles any change, with a snapshot taken first.

### Added
- **S3 API** for buckets, objects, versions, multipart uploads (7 operations), CopyObject,
  ListObjects v1/v2/versions, tagging, Range and conditional requests, 5 checksum algorithms,
  GetObjectAttributes, bucket policies and PublicAccessBlock, lifecycle expiration and
  abort-incomplete-multipart, SSE-S3 (`AES256`) and bucket default encryption. ACLs work the
  way S3 has defaulted to since 2023 (`BucketOwnerEnforced`). Per-operation status and
  deviations: `docs/COMPAT.md`. Clients tested: aws-cli, rclone, mc, aws-sdk-s3.
- **Undo without setup:** every bucket keeps history, so deleting an object, a version or a
  whole bucket goes to the trash; `cairn trash restore` brings it back byte-identical.
- **Point-in-time recovery** without a prior snapshot: read any object as of an instant with
  `x-cairn-as-of`, or `cairn pitr restore` a bucket to one, including before it was deleted.
- **Deduplication:** content-addressed blobs; identical uploads, copies and restores write no
  new bytes, encrypted or not.
- **MCP server** (stdio and HTTP at `/_cairn/mcp`) whose every tool call is an IAM policy
  decision; time travel needs `cairn:TimeTravel`.
- **Security:** SigV4 (header and presigned), IAM users, groups, managed and inline policies,
  roles, STS `AssumeRole` / `GetSessionToken`, explicit-deny-wins evaluation on S3, admin and
  MCP requests; root credential sealed in the credential store at `cairn init`, never logged;
  encryption at rest with a master key from file or environment.
- **Recovery and integrity:** crash-consistent writes (kill -9 safe), `cairn fsck [--repair]`,
  scheduled `cairn scrub`, encrypted full and incremental `cairn backup` / `cairn restore`,
  schema migrations with `cairn migrate --dry-run`, `507` on a full disk with reads and deletes
  still working.
- **Operations:** `/healthz`, `/readyz`, Prometheus `/metrics`, JSON logs with request ids, an
  audit log of mutating and denied requests, `cairn config check`, and `cairn admin` for users,
  keys, groups, policies, roles, buckets, trash and PITR (`--json`).
- **Footprint:** 17.3 MiB static binary (x86_64), about 10 MiB idle RSS, under 60 MiB RSS
  while streaming a 10 GiB object.
- **Distribution:** static musl binaries for x86_64 and aarch64, a multi-arch image on
  `ghcr.io/solutionforest/cairn`, CycloneDX SBOMs and `SHA256SUMS`; `deploy/` has a
  docker-compose file, a hardened systemd unit and an example config with every key.

### Not in this release
Replication, tiering, event notifications, OIDC, Object Lock, SSE-C / SSE-KMS, CORS,
PostObject, quotas and rate limiting are not supported; `docs/COMPAT.md` lists how each
related request is answered.

[Unreleased]: https://github.com/solutionforest/cairn/compare/v0.1.0-alpha.1...master
[0.1.0-alpha.1]: https://github.com/solutionforest/cairn/releases/tag/v0.1.0-alpha.1
