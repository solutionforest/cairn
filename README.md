# Cairn

[![ci](https://github.com/solutionforest/cairn/actions/workflows/ci.yml/badge.svg)](https://github.com/solutionforest/cairn/actions/workflows/ci.yml)
[![security](https://github.com/solutionforest/cairn/actions/workflows/security.yml/badge.svg)](https://github.com/solutionforest/cairn/actions/workflows/security.yml)
[![release](https://img.shields.io/github/v/release/solutionforest/cairn?include_prereleases)](https://github.com/solutionforest/cairn/releases)
[![licence: AGPL-3.0-only](https://img.shields.io/badge/licence-AGPL--3.0--only-blue)](LICENSE)

**Lightweight, self-hosted, S3-compatible object storage in Rust.** One static binary, one data
directory, no external services. Built for people who run one box (or a few): a NAS, a VPS, a
Raspberry Pi, a homelab, a small team's backup target.

Cairn's difference is a safety net that S3 clones usually leave out: every bucket keeps history
internally ("shadow versioning"), so deletes are soft, the trash is restorable, and a bucket can
be read or restored **as of any point in time** inside its retention window. On top: IAM-style
policies and STS, encryption at rest, Object Lock, event notifications that can call webhooks
and serverless functions, and a built-in MCP server so AI agents can use your storage under the
same policies as everyone else.

> **Status: pre-alpha.** The storage core, IAM and events are built and tested at the crate
> level; the S3 server is being wired up now. There is no release yet and on-disk formats may
> change. Follow [`docs/BUILD-PLAN.md`](docs/BUILD-PLAN.md) for progress and
> [`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md) for what "1.0-ready" means.
> "Cairn" is a working title (see the name-check entry in the BUILD-PLAN decisions log).

## 60-second quickstart

```sh
# 1. Get the binary (static, x86_64 or aarch64 Linux) or the container image
curl -fsSLO https://github.com/solutionforest/cairn/releases/latest/download/cairn-<version>-x86_64-unknown-linux-musl.tar.gz
tar xzf cairn-*.tar.gz && sudo install cairn-*/cairn /usr/local/bin/
#    or: docker run -p 9000:9000 -v cairn-data:/data ghcr.io/solutionforest/cairn

# 2. Initialise a data directory (prints the root access key and secret once) and serve
cairn init --data-dir ./cairn-data
cairn serve --data-dir ./cairn-data            # S3 on http://127.0.0.1:9000

# 3. Use any S3 client
export AWS_ACCESS_KEY_ID=<printed key> AWS_SECRET_ACCESS_KEY=<printed secret> AWS_REGION=us-east-1
aws --endpoint-url http://127.0.0.1:9000 s3 mb s3://photos
aws --endpoint-url http://127.0.0.1:9000 s3 cp ./cat.jpg s3://photos/
aws --endpoint-url http://127.0.0.1:9000 s3 ls s3://photos/
```

Configuration: every key with its default is in [`deploy/cairn.example.toml`](deploy/cairn.example.toml);
any key can be set from the environment as `CAIRN_<SECTION>_<KEY>`. Production deployment
examples: [`deploy/docker-compose.yml`](deploy/docker-compose.yml) and a hardened systemd unit,
[`deploy/cairn.service`](deploy/cairn.service). Operations (backup, restore, upgrade, DR):
[`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## Features compared with MinIO

Honest status as of today. ✅ built and tested · 🚧 in progress · 📋 planned (phase in
BUILD-PLAN) · ❌ not planned.

| | Cairn | MinIO (AGPL community edition) |
|---|---|---|
| Deployment | single static binary + one data dir ✅ | single binary; erasure-coded multi-drive/multi-node |
| S3 core (buckets, objects, multipart, versioning, ranges, conditionals, checksums) | 🚧 1c | ✅ |
| Multi-node / erasure coding across machines | ❌ v1 (scale-up; async replication for DR) | ✅ |
| Soft delete for everything + restorable trash | 📋 2a (engine primitives ✅) | ❌ (versioning only) |
| Point-in-time read (`x-cairn-as-of`) and bucket PITR restore | 📋 2a (`head_at` query ✅) | ❌ |
| IAM policies, groups, bucket policies, STS | 🚧 2b (policy engine ✅, 143 evaluator cases) | ✅ |
| OIDC federation (`AssumeRoleWithWebIdentity`) | 📋 3c | ✅ |
| Encryption at rest (SSE-S3, SSE-C, named keys) | 🚧 (AES-256-GCM blob layer ✅; S3 headers 2a) | ✅ (KMS via KES) |
| Object Lock (governance, compliance, legal hold) | 📋 2a | ✅ |
| Lifecycle expiration | 📋 2a | ✅ (+ tiering transitions) |
| Bucket notifications: webhooks (HMAC-signed) | ✅ library, wiring 📋 | ✅ (webhook, Kafka, AMQP, NATS, …) |
| Notifications to serverless functions (Lambda SigV4, bearer, Cloudflare Access) | ✅ library, wiring 📋 | ❌ |
| Live event stream (SSE) for sidecar extensions | ✅ library, wiring 📋 | ✅ (`mc admin trace`/listen) |
| Async replication (to Cairn or any S3) | 📋 3b | ✅ |
| Blob tiering to remote S3 | 📋 3b | ✅ |
| Built-in MCP server for AI agents, governed by IAM | 📋 3c | ❌ |
| Admin UI | 📋 4 | ✅ (console) |
| Prometheus metrics, health endpoints, audit log | 📋 2a | ✅ |
| Backup / restore / fsck / scrub tooling | 📋 3b | partial (`mc mirror`, heal) |

MinIO is far more mature and scales out; Cairn trades scale-out for a smaller footprint and
stronger "undo" guarantees on a single node. If you need a multi-petabyte cluster, use MinIO,
Ceph RGW or Garage.

## S3 compatibility

Cairn targets drop-in compatibility with the AWS SDKs, `aws` CLI, `rclone`, `restic`, `mc`,
and the long tail of S3-backed apps (Nextcloud, Immich, Velero, Loki, Terraform state, …). The
per-operation status, known differences and client test results are tracked in
[`docs/COMPAT.md`](docs/COMPAT.md) (created with the S3 server in phase 1c), Cairn-specific
headers and actions in [`docs/EXTENSIONS.md`](docs/EXTENSIONS.md), and conformance is measured
nightly with the ceph `s3-tests` suite ([`scripts/s3-tests/`](scripts/s3-tests/)).

## Licence

Cairn is licensed under the **GNU Affero General Public License v3.0 only**
([`LICENSE`](LICENSE)).

- **Self-hosting for yourself or your organisation** (including commercially, internally, or as
  the storage behind your product): no obligations beyond the licence notice. Using Cairn
  through its S3 API does not make your application a derivative work.
- **Modifying Cairn and letting others use it over a network** (for example offering it as a
  hosted storage service, or running a patched version for customers): you must offer those
  users the complete corresponding source of your modified Cairn under the AGPL.
- **Redistributing binaries or images**: ship or link the corresponding source, keep the
  licence and notices.

This is not legal advice. Commercial licensing for cases the AGPL does not fit may be offered by
the maintainers later; ask via an issue.

## Security

Please report vulnerabilities privately; see [`SECURITY.md`](SECURITY.md) (GitHub security
advisories or `security@solutionforest.net`, 90-day coordinated disclosure). Release binaries
embed their dependency list for `cargo audit bin`, and ship with a CycloneDX SBOM and SHA256SUMS.

## Contributing and design

Start with [`docs/DESIGN.md`](docs/DESIGN.md) (architecture and rationale) and
[`AGENTS.md`](AGENTS.md) (build constraints and conventions). Changes are recorded in
[`CHANGELOG.md`](CHANGELOG.md). Benchmarks: [`bench/`](bench/).
