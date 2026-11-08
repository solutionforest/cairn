# ceph s3-tests runner

Conformance harness for the S3 API against the community `ceph/s3-tests` suite (boto3 +
pytest). Used by `.github/workflows/s3-tests.yml` (nightly, gated by the `S3_TESTS_ENABLED`
repository variable) and runnable locally.

## Run locally

```sh
# 1. start a server
cairn init --data-dir /tmp/cairn-s3t          # prints root credentials
cairn serve --data-dir /tmp/cairn-s3t &

# 2. run the subset (needs git, python3 with venv; uses tox when installed)
S3_ENDPOINT=http://127.0.0.1:9000 \
S3_MAIN_ACCESS_KEY=... S3_MAIN_SECRET_KEY=... \
scripts/s3-tests/run.sh

# narrow it down while debugging
S3_TESTS_EXTRA="-k multipart -x -vv" scripts/s3-tests/run.sh
```

Outputs land in `target/s3-tests/report/`: `junit.xml`, `failed.txt`, `summary.md`.

## What runs

- Suite: `ceph/s3-tests` pinned to commit `5b39871` (2026-10-12), the last commit before
  upstream moved the suite into `ceph/ceph`. Override with `S3_TESTS_REPO` / `S3_TESTS_COMMIT`.
- Files: `s3tests/functional/test_s3.py` and `test_headers.py` (override `S3_TESTS_PATHS`).
- Markers: everything except features Cairn does not implement or that are RGW-specific:
  `fails_on_aws` (RGW-only behaviour), `fails_with_subdomain` (needs wildcard DNS), append
  objects, bucket logging, storage classes / transitions / cloud tiering, S3 Select, website
  hosting, SNS, S3 Control, IAM account/user/group/role APIs, STS + web identity token tests,
  and SigV2. Bucket policy, versioning, lifecycle expiration, Object Lock, SSE, checksums,
  tagging, conditional writes and multipart are **included**. Override with
  `S3_TESTS_MARKERS`.
- `[s3 alt]` / `[s3 tenant]` default to the main credentials until phase 2b provides users;
  set `S3_ALT_*` to a second user then, or the cross-principal ACL/policy tests stay red.

## Allowed failures

`allowed-failures.txt` lists `module::test_name` ids that may fail, each with a reason.
`compare.py` fails the run on any failure **not** in the list and reports listed tests that now
pass so the list only shrinks. Targets: ≥ 80% of executed tests passing by the end of phase 2a,
≥ 95% by the end of phase 3 (PRODUCTION-READINESS A9).
