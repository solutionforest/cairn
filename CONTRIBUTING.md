# Contributing to Cairn

Thanks for looking. Cairn is small on purpose; read [`docs/DESIGN.md`](docs/DESIGN.md) §0 before
proposing a feature. If it does not serve one of the four claims there, or a table-stakes row in
[`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md), it will be declined kindly.
VaultS3, RustFS, SeaweedFS and Garage are all good; breadth lives there.

## Issues, not pull requests

For now Cairn takes contributions as **issues only**. Opening a pull request is limited to
repository collaborators, and any from outside the maintainer team are closed automatically
(`.github/workflows/pr-policy.yml`) with a pointer to the issue tracker.

[Open an issue](https://github.com/solutionforest/cairn/issues/new/choose) and pick a template:

- **Bug report**: version, how you run Cairn, client and exact command, expected vs actual,
  log lines (redact keys and secrets). A minimal reproduction gets fixed fastest.
- **S3 compatibility**: client, operation, the AWS behaviour you expected. Check
  [`docs/COMPAT.md`](docs/COMPAT.md) first; known deviations are listed there.
- **Feature request**: the problem first, then the solution you have in mind.

How an issue becomes a fix: the maintainers' AI agent triages it, reproduces it in a test,
writes the change following [`AGENTS.md`](AGENTS.md), and runs the full gate (fmt, clippy, tests,
s3-tests). A maintainer reviews and merges it; the commit references the issue, and the issue is
closed when the fix ships in a release. If you already have a patch, paste the diff in the issue;
it is read and credited (`Co-authored-by`) when used.

Security problems never go in a public issue; use [`SECURITY.md`](SECURITY.md).

## No CLA. DCO instead.

This applies to every commit, including maintainer and agent commits, and to any patch you post
in an issue. There is no contributor licence agreement. You keep your copyright. Every commit carries a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off:

```
git commit -s
```

which adds `Signed-off-by: Your Name <you@example.com>`. By signing off you certify the DCO
statement: you wrote the change or have the right to submit it under AGPL-3.0-only. Because no
single party collects copyright, nobody (including the maintainers) can relicense the core.

The DCO 1.1 in one breath: (a) you created the contribution and may submit it under the
project's licence, or (b) it is based on prior work under a compatible open-source licence and
you may submit it with modifications, or (c) someone who certified (a) or (b) gave it to you
unchanged; and (d) you understand the contribution and your sign-off are public and kept
indefinitely. Use your real name. Unsigned commits are not merged.

We will never ask you to sign a CLA or assign copyright, and we will not accept one offered.

## Promises

- Nothing in the core moves behind a paid tier. If it is in the binary, it stays in the binary.
- No telemetry, no account, no licence key. The server never phones home.
- The core stays AGPL-3.0-only.
- Every security fix gets a public advisory ([`SECURITY.md`](SECURITY.md)).

This file is in git; any change to these lines is in the history.

## Building (to reproduce or test a patch)

Constraints and conventions for humans and agents are in [`AGENTS.md`](AGENTS.md): pure-Rust
dependencies (rustls, no C build deps), `#![forbid(unsafe_code)]`, clippy clean with
`-D warnings`, `cargo fmt`, every S3 operation gets an `aws-sdk-s3` integration test and a
`docs/COMPAT.md` row. CI runs fmt, clippy, tests, docs, `cargo deny` and `cargo audit`.

```
cargo check -p cairn-engine        # iterate per crate
cargo test -p cairn-server         # integration tests boot the server in-process
cargo test --workspace             # before proposing a patch
```

## Changes to behaviour

- A change to the design gets a dated line in [`docs/DECISIONS.md`](docs/DECISIONS.md) in the same
  commit.
- A change an operator would notice gets a line under `Unreleased` in [`CHANGELOG.md`](CHANGELOG.md).
- Every release has its own changelog entry. Before tagging `vX.Y.Z`, move the `Unreleased`
  entries into a `## [X.Y.Z] - YYYY-MM-DD` section and add its `[X.Y.Z]: <url>` link line.
  The release workflow stops before building if either is missing
  (`scripts/changelog-section.sh X.Y.Z` runs the same check locally) and uses that section as
  the GitHub Release notes.
- New `x-cairn-*` headers or `cairn:*` actions go in [`docs/EXTENSIONS.md`](docs/EXTENSIONS.md).
