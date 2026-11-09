# Changelog

All notable changes to Tidemark (named Cairn up to 0.1.0-alpha.2) are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may break
compatibility; breaking changes are called out under **Changed** or **Removed**).

Every release has its own dated section here: the release workflow refuses a tag without one
and copies that section into the GitHub Release notes, so write entries for operators, not for
developers.

## [Unreleased]

## [0.1.0-alpha.3] - 2026-11-09

The project is renamed from Cairn to **Tidemark**. Only names changed; S3 behaviour is the same.

### Changed
- **Breaking:** every name moved from `cairn` to `tidemark`: the binary and release assets
  (`tidemark-<version>-<target>.tar.gz`), the image `ghcr.io/solutionforest/tidemark`, the
  repository `github.com/solutionforest/tidemark` (old links redirect), environment variables
  (`TIDEMARK_*`), custom headers (`x-tidemark-*`), IAM actions (`tidemark:*`), admin paths
  (`/_tidemark/...`), Prometheus metrics (`tidemark_*`), the config file (`tidemark.toml`) and
  the systemd unit (`tidemark.service`).
- New access key ids start with `TDMK` (20 characters, the same shape as AWS `AKIA…` keys).
- **Breaking:** data directories and backups made by 0.1.0-alpha.1 or alpha.2 do not open in this
  release (the metadata file and key-check labels were renamed). Copy objects out with any S3
  client, run `tidemark init` on a new directory, and copy them back.

## [0.1.0-alpha.2] - 2026-11-09

First public pre-release. Same server as 0.1.0-alpha.1; this release adds easier ways to start it.
Binaries and the image are built on GitHub-hosted runners and download without a GitHub account.

### Added
- Public multi-arch image `ghcr.io/solutionforest/cairn` (`linux/amd64`, `linux/arm64`) and a
  root `compose.yaml`: `docker compose up -d`, with `--profile ui` for the admin UI.
- `scripts/start.sh`: one command downloads and verifies the release binary, creates a data
  directory with fresh credentials, and starts the server (and with `--ui`, the admin UI).
- Optional local admin UI (`admin-ui/`): status, buckets, users, keys, and one-click restore from
  the trash. Runs with Python 3 or PHP and needs no packages.

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
  `ghcr.io/solutionforest/cairn`, CycloneDX SBOMs and `SHA256SUMS`; `compose.yaml` runs it
  (with the admin UI as an opt-in profile), and `deploy/` has a hardened systemd unit and an
  example config with every key.

### Not in this release
Replication, tiering, event notifications, OIDC, Object Lock, SSE-C / SSE-KMS, CORS,
PostObject, quotas and rate limiting are not supported; `docs/COMPAT.md` lists how each
related request is answered.

[Unreleased]: https://github.com/solutionforest/tidemark/compare/v0.1.0-alpha.3...master
[0.1.0-alpha.3]: https://github.com/solutionforest/tidemark/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/solutionforest/tidemark/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/solutionforest/tidemark/releases/tag/v0.1.0-alpha.1
