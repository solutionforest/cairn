# ceph s3-tests runner

Conformance harness for the S3 API against the community `ceph/s3-tests` suite (boto3 +
pytest). Used by `.github/workflows/s3-tests.yml` on every push (gate) and weekly (full sweep),
and runnable locally.

## Run locally

```sh
# 1. start a throwaway server (fresh data dir, fixed root key, second user `s3alt`)
cargo build -p cairn-cli
eval "$(scripts/s3-tests/start-cairn.sh target/debug/cairn)"

# 2. gate on expected-pass.txt (needs git, python3 with venv)
scripts/s3-tests/run.sh

# promote new passes after a fix (review the diff before committing)
scripts/s3-tests/run.sh --write-expected

# weekly-style full sweep: no deselection, report only
S3_TESTS_FULL=1 scripts/s3-tests/run.sh

# narrow it down while debugging
S3_TESTS_EXTRA="-x -vv" S3_TESTS_DESELECT="multipart" scripts/s3-tests/run.sh
kill "$CAIRN_PID"
```

Outputs land in `target/s3-tests/report/`: `junit.xml`, `passed.txt`, `failed.txt`,
`new-passes.txt`, `summary.md`.

## What runs

- Suite: `ceph/s3-tests` pinned to commit `5b39871` (2026-10-12), the last commit before
  upstream moved the suite into `ceph/ceph`. Override with `S3_TESTS_REPO` / `S3_TESTS_COMMIT`.
- Files: `s3tests/functional/test_s3.py` and `test_headers.py` (override `S3_TESTS_PATHS`).
- Markers: everything except features Cairn does not implement or that are RGW-specific:
  `fails_on_aws` (RGW-only behaviour), `fails_with_subdomain` (needs wildcard DNS), append
  objects, bucket logging, storage classes / transitions / cloud tiering, S3 Select, website
  hosting, SNS, S3 Control, IAM account/user/group/role APIs, STS + web identity token tests,
  SigV2, and the v0.1-shelved Object Lock and SSE-C/KMS (`object_lock`, `encryption`);
  CORS and PostObject (shelved, no marker) are removed with `-k` (`S3_TESTS_DESELECT`).
- ACL grants: the tests in `acl-grants.txt` need an ACL grant to someone other than the bucket
  owner, which S3 refuses on its default `BucketOwnerEnforced` buckets and Cairn does not
  support. The gate deselects them by exact name through the `cairn_deselect.py` pytest plugin
  (pytest's own `--deselect` matches by prefix). The full sweep runs them.
  Bucket policy, versioning, lifecycle expiration, SSE-S3, checksums, tagging, conditional
  writes and multipart are **included**. Override with `S3_TESTS_MARKERS`.
- `[s3 alt]` is the `s3alt` user created by `start-cairn.sh` with an `s3:*` policy (the
  suite's setup lists and deletes alt's buckets); it is a second user in Cairn's single
  account, so tests that expect cross-account denial fail. `[s3 tenant]` defaults to alt.

## Gating: expected-pass.txt

`expected-pass.txt` lists the `module::test_name` ids that pass today. `compare.py` fails the
run if any of them does not pass (regression or vanished test); tests that pass but are not
listed are reported in `new-passes.txt` and the job summary and never fail CI. The list only
grows: promote with `run.sh --write-expected` and review the diff; dropping an id needs a reason
in the commit message. The baseline line at the top records pass rate at generation time.
Target (PRODUCTION-READINESS A4): ≥ 80% of the executed non-shelved subset.
