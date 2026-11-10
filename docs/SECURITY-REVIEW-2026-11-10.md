# Security self-review: the auth boundary (2026-11-10)

BUILD-PLAN 1.6. An internal review before anyone else looks, not an audit. Every finding below
has a test that fails on the code before the fix (checked by reverting the fix) and passes after.

**Affected releases:** SEC-1 to SEC-5 are present in `v0.1.0-alpha.1` to `alpha.3` and fixed in
the next release.

## Scope

| Area | Code |
|---|---|
| SigV4 verify, presigned URLs | `tidemark-auth/src/sigv4.rs`, `sigv4/verify.rs`; S3 requests are verified by `s3s` 0.17 |
| Request → IAM mapping, condition keys | `tidemark-auth/src/s3s_bridge.rs`, `actions.rs` |
| Policy evaluator | `tidemark-auth/src/eval.rs`, `policy/condition.rs`, `engine.rs` |
| STS | `tidemark-auth/src/sts.rs`, `store/sts.rs` |
| Admin API | `tidemark-admin/src/api.rs` |
| MCP HTTP auth | `tidemark-mcp/src/auth.rs` |
| Admin UI backends | `admin-ui/server.py`, `admin-ui/server.php`, `admin-ui/index.html` |

Method: read each path for places where our view of a request can differ from the one the
handler acts on, then send that request to a real server.

## Findings

| ID | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| SEC-1 | High | `aws:SecureTransport` was true when the request URI had an `https` scheme. A plain-HTTP client can send `GET https://host/bucket/key HTTP/1.1` (absolute-form request target), so a bucket policy that denies non-TLS access did not apply. | Only the connection, or a trusted proxy's `X-Forwarded-Proto`, sets it. | `security_review::sec1_absolute_https_uri_does_not_count_as_secure_transport`, `s3s_bridge::tests::condition_context_keys` |
| SEC-2 | High | Condition keys from the query string (`s3:prefix`, `s3:delimiter`, `s3:max-keys`, `s3:VersionId`) were matched case-insensitively, while s3s reads exact names. `?Prefix=home/alice/&prefix=` passed an `s3:prefix` = `home/alice/*` condition, and s3s then listed the whole bucket. | Exact-case lookup, the same as s3s. `versionId` stays case-insensitive for picking `s3:GetObjectVersion`, which can only make the check stricter. | `s3s_bridge::tests::condition_keys_read_the_parameter_s3s_reads` |
| SEC-3 | Medium | `GetObjectAttributes` honours `x-tidemark-as-of` but was not in the `tidemark:TimeTravel` check, so a caller denied time travel could read ETag, size and checksums of past versions. | Added to the operations that need `tidemark:TimeTravel`. | `security_review::sec3_object_attributes_as_of_needs_time_travel` |
| SEC-4 | Medium | `AssumeRole` did not copy the caller key's `allowed_source_cidrs` into the role session. A key limited to `10.0.0.0/8` could assume a role from inside the range and use the session from anywhere. `GetSessionToken` already copied them. | The role session inherits the caller's CIDRs (chained sessions keep them too). | `store::tests::assume_role_session_keeps_the_callers_source_cidrs` |
| SEC-5 | Medium | The admin API accepted presigned (query-string) SigV4, so a leaked URL worked as an admin bearer token for up to 7 days. No client of ours presigns admin calls. | Requests without an `Authorization` header get 401 `MissingAuthenticationToken`. | `security_review::sec5_admin_api_refuses_presigned_urls` |

## Checked, no change

| Check | Evidence |
|---|---|
| Presigned URLs bind the method and reject a future `X-Amz-Date` | `security_review::presigned_urls_bind_method_and_reject_future_dates`; expiry > 7 days and negative are s3-tests cases |
| Unsigned and wrongly signed requests are 403; expired presigned URLs fail | `auth_wire::unsigned_and_badly_signed_requests_are_rejected`, `expired_presigned_url_is_rejected` |
| Duplicate query parameters: s3s rejects them for every operation input, so a condition key cannot read a value s3s ignores | s3s `http::de::parse_opt_query` |
| Principal and time keys (`aws:username`, `aws:PrincipalArn`, `aws:CurrentTime`, …) cannot be supplied by the caller; tag condition keys are always prefixed | `engine.rs` `enrich`; `eval_tests` |
| Missing keys follow AWS: negated operators match, `…IfExists` matches, `ForAllValues` matches, `ForAnyValue` does not, `Null` only checks presence | `policy/condition.rs`; `eval_tests` |
| Operations with no IAM mapping are root-only | `s3s_bridge.rs` `authorize` |
| STS: role chaining capped at 1 h, role sessions cannot call `GetSessionToken`, a long-lived key presenting a session token is refused | `store/sts.rs`; `store::tests` |
| MCP accepts only an `Authorization` header (bearer secret compared in constant time, or header SigV4) | `tidemark-mcp/src/auth.rs`; `auth_wire::mcp_http_*` |
| Admin UI: the custom `X-Tidemark-UI` header forces a CORS preflight (no CSRF), the `Host` check stops DNS rebinding, every API value is HTML-escaped, the backends forward only an allow-list of paths | `scripts/tests/admin_ui_test.py` |

## Accepted by design (DECISIONS 2026-11-10)

- **Admin actions are server-wide.** `tidemark:CreateAccessKey`, `PutUserPolicy`,
  `AttachUserPolicy` and the other identity actions are authorised on the server ARN, not per
  user. Anyone allowed one of them can give themselves any permission, as in AWS IAM. Grant
  them only to administrators.
- **The Python admin UI backend trusts its bind address.** It checks `Host` and `Origin` but not
  the client address, so it must listen on loopback (the default) or behind a proxy with its own
  login. The compose file binds it inside the container and publishes it to `127.0.0.1` only.
  The PHP backend also refuses non-loopback clients.
- **SigV4 scope region and service are not pinned** on the admin API and STS. The signature still
  covers method, path, query, signed headers and body, so a signature cannot be moved to another
  request.
