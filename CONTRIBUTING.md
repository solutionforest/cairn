# Contributing to Cairn

Thanks for looking. Cairn is small on purpose; read [`docs/DESIGN.md`](docs/DESIGN.md) §0 before
proposing a feature. If it does not serve one of the four claims there, or a table-stakes row in
[`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md), it will be declined kindly.
VaultS3, RustFS, SeaweedFS and Garage are all good; breadth lives there.

## No CLA. DCO instead.

There is no contributor licence agreement. You keep your copyright. Every commit carries a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off:

```
git commit -s
```

which adds `Signed-off-by: Your Name <you@example.com>`. By signing off you certify the DCO
statement: you wrote the change or have the right to submit it under AGPL-3.0-only. Because no
single party collects copyright, nobody (including the maintainers) can relicense the core.

## Promises

- Nothing in the core moves behind a paid tier. If it is in the binary, it stays in the binary.
- No telemetry, no account, no licence key. The server never phones home.
- The core stays AGPL-3.0-only.
- Every security fix gets a public advisory ([`SECURITY.md`](SECURITY.md)).

This file is in git; any change to these lines is in the history.

## Building

Constraints and conventions for humans and agents are in [`AGENTS.md`](AGENTS.md): pure-Rust
dependencies (rustls, no C build deps), `#![forbid(unsafe_code)]`, clippy clean with
`-D warnings`, `cargo fmt`, every S3 operation gets an `aws-sdk-s3` integration test and a
`docs/COMPAT.md` row. CI runs fmt, clippy, tests, docs, `cargo deny` and `cargo audit`.

```
cargo check -p cairn-engine        # iterate per crate
cargo test -p cairn-server         # integration tests boot the server in-process
cargo test --workspace             # before opening a PR
```

## Changes to behaviour

- A change to the design gets a dated line in [`docs/DECISIONS.md`](docs/DECISIONS.md) in the same
  commit.
- A change an operator would notice gets a line under `Unreleased` in [`CHANGELOG.md`](CHANGELOG.md).
- New `x-cairn-*` headers or `cairn:*` actions go in [`docs/EXTENSIONS.md`](docs/EXTENSIONS.md).
