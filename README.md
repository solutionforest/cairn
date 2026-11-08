# Cairn

[![ci](https://github.com/solutionforest/cairn/actions/workflows/ci.yml/badge.svg)](https://github.com/solutionforest/cairn/actions/workflows/ci.yml)
[![security](https://github.com/solutionforest/cairn/actions/workflows/security.yml/badge.svg)](https://github.com/solutionforest/cairn/actions/workflows/security.yml)
[![release](https://img.shields.io/github/v/release/solutionforest/cairn?include_prereleases)](https://github.com/solutionforest/cairn/releases)
[![licence: AGPL-3.0-only](https://img.shields.io/badge/licence-AGPL--3.0--only-blue)](LICENSE)

**Lightweight, self-hosted, S3-compatible object storage in Rust.** One static binary, one data
directory, no external services. Built for people who run one box (or a few): a NAS, a VPS, a
Raspberry Pi, a homelab, a small team's backup target.

Cairn makes four promises that other S3 servers do not:

1. **You cannot lose data, even if you configured nothing.** Every bucket keeps history
   internally ("shadow versioning"), so every delete (object, version, or whole bucket) is
   reversible from the trash. No versioning to remember to turn on.
2. **Any bucket is readable and restorable as of any instant** in its retention window
   (`x-cairn-as-of`, `cairn pitr`). No snapshot to have taken first.
3. **Identical content costs disk once.** Blobs are content-addressed; copies and restores write
   no new bytes.
4. **AI agents get the same storage under the same rules.** The MCP server is in the binary and
   every tool call is an IAM policy decision, not a root token.

On top: IAM-style policies and STS, SigV4, encryption at rest, lifecycle, fsck/scrub/backup,
metrics and audit logs. That is the whole list, on purpose.

Cairn is single-node by design and deliberately narrow. If you want a dashboard, erasure coding,
clustering, OIDC, search or FUSE in one AGPL binary, [VaultS3](https://github.com/Kodiqa-Solutions/VaultS3)
already does that well. If you need a distributed cluster, use [RustFS](https://github.com/rustfs/rustfs)
or [Garage](https://garagehq.deuxfleurs.fr/).

> **Status: pre-alpha.** The storage core, IAM, recovery tooling and MCP are built and tested;
> the server wiring and the end-to-end proofs of the four claims are in progress. There is no
> release yet and on-disk formats may change. Follow [`docs/BUILD-PLAN.md`](docs/BUILD-PLAN.md) for progress and
> [`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md) for what "1.0-ready" means.
> "Cairn" is a working title (see the name-check entry in the BUILD-PLAN decisions log).

## 60-second quickstart

```sh
# 1. Get the binary (static, x86_64 or aarch64 Linux) or the container image
curl -fsSLO https://github.com/solutionforest/cairn/releases/latest/download/cairn-v<version>-x86_64-unknown-linux-musl.tar.gz
tar xzf cairn-*.tar.gz && sudo install cairn-*/cairn /usr/local/bin/
#    or: docker run -p 9000:9000 -v cairn-data:/data \
#          -e CAIRN_ROOT_ACCESS_KEY=<key> -e CAIRN_ROOT_SECRET=<secret> ghcr.io/solutionforest/cairn

# 2. Initialise a data directory (prints the root access key and secret once) and serve
cairn init --data-dir ./cairn-data
cairn serve --config ./cairn-data/cairn.toml   # S3 on http://127.0.0.1:9000

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

## Compared with the alternatives

Same rows and columns as [`docs/DESIGN.md`](docs/DESIGN.md) §0. Competitor cells come from each
project's own documentation. Cairn cells say only what is true in `main` today, with the proof
or the missing proof named (rows in [`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md)).

| | RustFS | VaultS3 | Garage | **Cairn** (today) |
|---|---|---|---|---|
| Shape | distributed cluster, Apache-2.0, Rust | single binary, AGPL, Go, 100+ features incl. dashboard, EC, Raft, OIDC, search | small replicated store, AGPL, Rust | single binary, AGPL, Rust |
| Versioning | per-bucket opt-in | per-bucket opt-in; snapshots are an explicit commit | none | always on internally (engine; every write is a new version) |
| Undo after a delete you did not plan for | no | only if versioning was already on | no | object and bucket trash built (`cairn admin trash`); end-to-end proof through server + CLI pending (A6) |
| Read a bucket as it was at time T | no | snapshot you took earlier | no | `x-cairn-as-of` reads tested through the server (`crates/cairn-server/tests/pitr.rs`); restore across a bucket delete pending (A5) |
| Identical bytes stored once | no | no | no | BLAKE3 content addressing built; on-disk proof (walk `blobs/`) pending (A7) |
| MCP for agents | separate server, plain S3 creds | none | none | in-process (`[mcp] enabled`, `cairn mcp --stdio`) under IAM; cross-channel deny test pending (D7) |

Cairn is deliberately narrow: no dashboard, erasure coding, clustering, replication, OIDC, search,
FUSE or S3 Select in v0.1 (DESIGN §0 "Shelved"). Idle memory, binary size and 10 GiB-transfer RSS
are produced by [`scripts/footprint.sh`](scripts/footprint.sh) and appear here only once measured
on a release build:

| Footprint (release build, `scripts/footprint.sh`) | Cairn |
|---|---|
| Idle RSS after a 110 s settle | not yet measured |
| Peak RSS during a 10 GiB upload + download | not yet measured |
| Static binary size | not yet measured |

VaultS3 publishes 17 MiB idle on its own hardware; we do not quote other projects' numbers as if
they were measured on ours. If a cell about Cairn is wrong, open an issue; the table is part of
the definition of done.

## Promises

These are commitments, not aspirations, and they are in git:

- **No telemetry.** The server never phones home.
- **No account.** Nothing to sign up for, ever, to download, run or update Cairn.
- **No licence key.** The binary you build or download is the whole product.
- **Nothing in the core moves behind a paid tier.** If it is in the binary, it stays in the binary.
- **No CLA.** Contributions are DCO-signed ([`CONTRIBUTING.md`](CONTRIBUTING.md)), so no single
  party, including the maintainers, can relicense the core.
- Every security fix gets a public advisory ([`SECURITY.md`](SECURITY.md)).

## S3 compatibility

Cairn targets drop-in compatibility with the AWS SDKs, `aws` CLI, `rclone`, `restic`, `mc`,
and the long tail of S3-backed apps (Nextcloud, Immich, Velero, Loki, Terraform state, …). The
per-operation status, known differences and client test results are tracked in
[`docs/COMPAT.md`](docs/COMPAT.md), Cairn-specific
headers and actions in [`docs/EXTENSIONS.md`](docs/EXTENSIONS.md), and every push runs the ceph
`s3-tests` suite and fails if any test in the committed
[`scripts/s3-tests/expected-pass.txt`](scripts/s3-tests/expected-pass.txt) regresses (baseline:
275 of 462 executed, 59.5%; the target is 80%).

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

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) (DCO, scope), [`docs/DESIGN.md`](docs/DESIGN.md)
(architecture, rationale, and §0 for what is in and out) and [`AGENTS.md`](AGENTS.md) (build
constraints and conventions). Changes are recorded in [`CHANGELOG.md`](CHANGELOG.md).
