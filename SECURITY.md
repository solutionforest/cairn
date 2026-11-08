# Security policy

Cairn stores other people's data and credentials, so we treat security reports as the highest
priority work in the project.

## Supported versions

Cairn is pre-1.0. Only the latest release line receives security fixes.

| Version | Supported |
|---------|-----------|
| latest `0.x` release | yes |
| `master` (unreleased) | yes, fixes land here first |
| older `0.x` releases | no, upgrade to the latest |

From 1.0 onward the latest minor release and the previous minor release will be supported.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report privately through either channel:

1. **GitHub private vulnerability reporting** (preferred): on
   <https://github.com/solutionforest/cairn/security/advisories/new>, click "Report a
   vulnerability". This creates a draft advisory only maintainers can see.
2. **Email** `security@solutionforest.net`. Encrypt with our PGP key if you need to (ask in a
   first, content-free email and we will send it).

Please include: affected version or commit, configuration relevant to the issue, a description
of the impact, and a proof of concept or reproduction steps. Reports that include a suggested
fix are welcome but not required.

## What happens next

| Step | Target |
|------|--------|
| Acknowledge receipt | 3 business days |
| Initial assessment (confirmed / not a vulnerability / need more info) and severity (CVSS 4.0) | 10 business days |
| Fix released for critical / high severity | as fast as possible, normally within 30 days |
| Public disclosure | coordinated with you, at most **90 days** after the report |

We follow a 90-day coordinated disclosure policy: we publish a GitHub Security Advisory (and
request a CVE where applicable) when the fix is released, or 90 days after the report, whichever
comes first. If a fix needs more time we will tell you why and agree a new date with you; if a
vulnerability is being actively exploited we may disclose sooner with mitigations. We credit
reporters in the advisory unless you ask us not to.

## Scope

In scope: the `cairn` binary and all crates in this repository, the container images published
to `ghcr.io/solutionforest/cairn`, the release artefacts on GitHub Releases, and the example
deployment files under `deploy/`.

Particularly interesting: authentication bypass (SigV4, presigned URLs, STS sessions), policy
evaluation errors (access granted that should be denied), cross-tenant data exposure (including
via blob deduplication or SSE-C), data loss or corruption not caused by the operator, path
traversal from object keys into the filesystem, secrets appearing in logs, and denial of service
with a small request.

Out of scope: issues requiring a compromised host or root on the server, findings in
dependencies that are already public RustSec advisories (we track those with `cargo deny` and
`cargo audit` in CI; tell us if one is exploitable through Cairn), missing hardening headers on
endpoints that do not serve browsers, and volumetric DoS.

## Safe harbour

We will not pursue legal action against good-faith research that respects this policy: test only
against your own deployment, do not access or modify other people's data, and give us a
reasonable time to fix before disclosure.

## Hardening already in place

- Memory-safe Rust with `#![forbid(unsafe_code)]` in every crate; TLS via rustls only (no
  OpenSSL); pure-Rust dependency tree checked by `cargo deny` and `cargo audit` on every push and
  weekly.
- Release binaries embed their dependency list (`cargo auditable`) so `cargo audit bin cairn`
  works on a deployed binary; each release ships a CycloneDX SBOM and SHA256SUMS.
- Secrets (root keys, HMAC keys, sink tokens) are zeroized on drop and redacted from logs and
  `Debug` output.
