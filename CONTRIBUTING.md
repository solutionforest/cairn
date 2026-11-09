# Contributing

## Issues, not pull requests

Tidemark takes contributions as **issues only**. Pull requests from outside the maintainer team
are closed automatically. [Open an issue](https://github.com/solutionforest/tidemark/issues/new/choose):

- **Bug**: version, how you run it, the exact command, expected vs actual, logs (redact keys).
- **S3 incompatibility**: client, operation, expected AWS behaviour. Check [COMPAT.md](docs/COMPAT.md) first.
- **Feature**: the problem first. Scope is narrow on purpose ([DESIGN.md](docs/DESIGN.md) §0).

Our AI agent reproduces the issue in a test, writes the fix and runs the full gate; a maintainer
reviews and merges. Have a patch? Paste the diff in the issue; it is credited when used.

Security problems never go in a public issue: see [SECURITY.md](SECURITY.md).

## DCO, no CLA

Every commit is signed off with `git commit -s` ([Developer Certificate of Origin](https://developercertificate.org/)).
You keep your copyright, so nobody, including the maintainers, can relicense the core.

## Promises

No telemetry, no account, no licence key. Nothing in the core moves behind a paid tier. The core
stays AGPL-3.0-only. Every security fix gets a public advisory.

## Building

Conventions are in [AGENTS.md](AGENTS.md).

```sh
cargo test -p tidemark-server   # one crate
cargo test --workspace          # everything
scripts/tests/run.sh            # scripts and admin UI backends
```

## Changing behaviour

- Every bug fix comes with a test that fails without the fix.
- Design change: a dated entry in [docs/DECISIONS.md](docs/DECISIONS.md).
- Operator-visible change: a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).
- Release `vX.Y.Z`: needs a dated `## [X.Y.Z] - YYYY-MM-DD` section and link line in the
  changelog, or the release workflow stops (`scripts/changelog-section.sh X.Y.Z` checks locally).
- New `x-tidemark-*` headers or `tidemark:*` actions: document in [docs/EXTENSIONS.md](docs/EXTENSIONS.md).
