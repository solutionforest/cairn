# Security policy

## Reporting

**Never open a public issue for a security problem.** Report privately:

1. [GitHub private vulnerability reporting](https://github.com/solutionforest/tidemark/security/advisories/new) (preferred)
2. Email `security@solutionforest.net`

Include the version, relevant config, impact and reproduction steps.

| Step | Target |
|---|---|
| Acknowledge | 3 business days |
| Assessment and severity (CVSS 4.0) | 10 business days |
| Fix for critical / high | normally within 30 days |
| Public disclosure | coordinated, at most **90 days** after the report |

We publish a GitHub Security Advisory (and CVE where applicable) with each fix and credit
reporters unless asked not to.

## Supported versions

Pre-1.0: only the latest `0.x` release and `master`.

## Scope

In scope: the `tidemark` binary and crates, the `ghcr.io/solutionforest/tidemark` images, release
artefacts and `deploy/` files. Most interesting: auth bypass (SigV4, presigned URLs, STS), policy
errors, cross-tenant exposure (including via dedup), data loss, path traversal, secrets in logs,
and small-request DoS.

Out of scope: attacks needing root on the host, already-public RustSec advisories (unless
exploitable through Tidemark), and volumetric DoS.

## Safe harbour

Good-faith research is welcome: test only your own deployment, do not touch others' data, and
give us time to fix before disclosure.

## Hardening

`#![forbid(unsafe_code)]` everywhere, rustls only, `cargo deny` and `cargo audit` on every push.
Release binaries embed their dependency list (`cargo audit bin`) and ship with an SBOM and
SHA256SUMS. Secrets are zeroized and redacted from logs.
