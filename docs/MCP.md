# Tidemark MCP server

Tidemark ships a [Model Context Protocol](https://modelcontextprotocol.io) server (`tidemark-mcp`,
built on `rmcp`) so AI agents can browse, read, write and recover objects. It is not a separate
permission system: **every tool call is authorised by Tidemark IAM exactly like the equivalent S3
request** (same action, same resource ARN, bucket policy and PublicAccessBlock included), with one
extra condition key, `tidemark:McpTool`, holding the tool name.

Two transports:

| Transport | Endpoint | Credentials |
|-----------|----------|-------------|
| stdio | `tidemark mcp --stdio` (spawned by the client) | env `TIDEMARK_ACCESS_KEY_ID`, `TIDEMARK_SECRET_ACCESS_KEY`, optional `TIDEMARK_SESSION_TOKEN` |
| Streamable HTTP | `https://<host>/_tidemark/mcp` (when `[mcp] enabled = true`) | every request: `Authorization: Bearer <access-key-id>:<secret>[:<session-token>]`, or AWS SigV4 |

Give the agent its **own** user or role with a narrow policy; never hand it the root key.

## Authentication

**stdio.** The credentials are checked when the server starts (it exits with an error if they are
invalid) and re-checked on every tool call, so revoking the key, disabling the user or letting an
STS session expire takes effect immediately. stdio calls are treated as
`aws:SecureTransport = true` and carry no `aws:SourceIp`; keys restricted to source CIDRs are
therefore denied over stdio.

**HTTP.** There is no login step: each HTTP request (initialize, every `tools/call`, the SSE GET)
is authenticated on its own, and the tool runs as the credential *that request* carries. The
`Mcp-Session-Id` is not a credential — a request with a valid session id but no credentials is
answered `401`. Accepted forms:

- `Authorization: Bearer AKID:SECRET` — a long-lived access key (secret compared in constant
  time).
- `Authorization: Bearer AKID:SECRET:SESSION_TOKEN` — STS credentials (`AssumeRole`,
  `GetSessionToken`, `AssumeRoleWithWebIdentity`). The token is required for session keys and
  rejected for long-lived keys.
- AWS SigV4 (`Authorization: AWS4-HMAC-SHA256 …`, any service name, `host` signed, body hash
  checked server-side, ±15 min skew) — the same verifier as the STS and admin endpoints. Use it
  when the secret must not travel in the request.

Failures answer `401` with `WWW-Authenticate: Bearer realm="tidemark-mcp"` and never say which part
was wrong. Serve MCP over TLS: bearer credentials are sent in clear text otherwise. The `Host`
header check that rmcp applies against DNS rebinding is off by default because credentials are
required on every request; set `McpConfig::allowed_hosts` to enable it.

## Connecting clients

**Claude Code (stdio)**

```sh
claude mcp add tidemark \
  --env TIDEMARK_ACCESS_KEY_ID=TIDEMARK... \
  --env TIDEMARK_SECRET_ACCESS_KEY=... \
  -- tidemark mcp --stdio --config /etc/tidemark/tidemark.toml
```

**Claude Code (HTTP)**

```sh
claude mcp add --transport http tidemark https://tidemark.example.com/_tidemark/mcp \
  --header "Authorization: Bearer TDMK...:SECRET"
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "tidemark": {
      "command": "tidemark",
      "args": ["mcp", "--stdio", "--config", "/etc/tidemark/tidemark.toml"],
      "env": {
        "TIDEMARK_ACCESS_KEY_ID": "TIDEMARK...",
        "TIDEMARK_SECRET_ACCESS_KEY": "..."
      }
    }
  }
}
```

For a remote server, point any client that speaks Streamable HTTP at `/_tidemark/mcp` with the
`Authorization` header above (or bridge with `npx mcp-remote https://…/_tidemark/mcp --header
"Authorization: Bearer …"`).

**Any MCP client.** stdio: newline-delimited JSON-RPC on stdin/stdout. HTTP: MCP Streamable HTTP
(protocol 2025-03-26 and later); POST JSON-RPC with `Accept: application/json, text/event-stream`,
keep the `Mcp-Session-Id` returned by `initialize`.

**Short-lived credentials for agents.** Prefer STS: assume a dedicated role (or federate a CI
identity with `AssumeRoleWithWebIdentity`, see OPERATIONS "OIDC federation") and pass the three
values (`TIDEMARK_SESSION_TOKEN` for stdio, the third bearer field for HTTP).

## Tools

All tools return structured JSON (`structuredContent`, mirrored as text). Failures come back as a
tool result with `isError: true` and `{"error": "<S3-style code>", "message": "…"}`; a denied call
is always `AccessDenied` — authorisation runs before the bucket or key is looked up, so a denied
caller cannot probe which buckets or keys exist.

| Tool | Arguments | IAM action → resource | Notes |
|------|-----------|-----------------------|-------|
| `list_buckets` | — | `s3:ListAllMyBuckets` → `arn:aws:s3:::*` | Returns only buckets on which `list_objects` (`s3:ListBucket`, `tidemark:McpTool = list_objects`) would be allowed. |
| `list_objects` | `bucket, prefix?, delimiter?, start_after?, max_keys? (≤1000, default 100), as_of?` | `s3:ListBucket` → bucket (+ `tidemark:TimeTravel` → bucket with `as_of`) | `s3:prefix`, `s3:delimiter`, `s3:max-keys`, `tidemark:AsOf` in context. Paginate with `next_start_after`. |
| `get_object` | `bucket, key, version_id?, as_of?, range? (first-last, first-, -N), mode? (auto/text/base64)` | `s3:GetObject` (`s3:GetObjectVersion` with `version_id`) → object; `as_of` without `version_id` also needs `tidemark:TimeTravel` → object | Body capped (default 1 MiB): larger objects return the first bytes with `truncated: true`; an explicit range larger than the cap is refused. |
| `head_object` | `bucket, key, version_id?, as_of?` | as `get_object` | Metadata, user metadata, tag count; no body. |
| `put_object` | `bucket, key, content \| content_base64, content_type?, metadata?, tags?` | `s3:PutObject` → object | `s3:RequestObjectTag/<k>`, `s3:RequestObjectTagKeys`. Body ≤ 4 MiB (decoded). |
| `delete_object` | `bucket, key, version_id?` | `s3:DeleteObject` / `s3:DeleteObjectVersion` → object | Soft delete: recoverable with `trash_restore`. |
| `copy_object` | `source_bucket, source_key, source_version_id?, bucket, key` | `s3:PutObject` → destination and `s3:GetObject(Version)` → source | Metadata and tags copied; no data copy. |
| `search` | `bucket, query?, prefix?, content_type?, min_size?, max_size?, modified_after?, modified_before?, limit? (≤500)` | `s3:ListBucket` → bucket | Metadata scan of current objects (≤10 000 keys per call; `complete: false` when the budget ran out). |
| `trash_list` | `bucket, prefix?, limit? (≤1000)` | `tidemark:ListTrash` → bucket | Soft-deleted and superseded versions with `expires_at`. |
| `trash_restore` | `bucket, key, version_id?` | `tidemark:Restore` → object | Writes a new live version sharing the old blobs; history is not rewritten. |
| `pitr_head_at` | `bucket, key, at` | `s3:GetObject` + `tidemark:TimeTravel` → object, `tidemark:AsOf = at` | The version that was current at `at`. |
| `pitr_diff` | `bucket, at, prefix?` | `tidemark:PitrDiff` → bucket | `recreate` / `revert` / `remove` per key. |
| `pitr_restore` | `bucket, at, prefix?, dry_run? (default true), confirm` | `tidemark:Pitr` → bucket | Applying needs `dry_run: false` **and** `confirm: true`; ≤1000 changes per call. Every change is a normal new version or delete marker, so the restore is itself reversible. |
| `bucket_info` | `bucket` | `s3:ListBucket` → bucket | Versioning, object lock, retention; `tags` only if `s3:GetBucketTagging` is also allowed. |

Every call also sets `tidemark:McpTool`, `aws:SecureTransport`, `aws:SourceIp` (HTTP, when the
server knows it) plus the usual principal keys (`aws:username`, `aws:PrincipalArn`,
`aws:PrincipalTag/*`, …). Timestamps (`as_of`, `at`, `modified_*`) are RFC 3339.

Not implemented (DESIGN §11.1 items dropped for now): `get_object` `mode = url` and `presign`
(the server does not know the client-facing S3 endpoint), `storage_stats` and `set_bucket_policy`
(admin API / S3 instead), semantic `search` (phase 4 `ai` feature), tag/metadata filters in
`search`, MCP resources (`s3://…`) and prompts.

## Example: a restricted agent

Read the `docs` bucket except `private/` (time travel back to 2026 only), write only under
`inbox/`, browse and restore the trash,
and never run `pitr_restore` or `delete_object` through MCP even though the same user may delete
via S3:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
    {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetObject", "s3:GetObjectVersion"],
     "Resource": ["arn:aws:s3:::docs", "arn:aws:s3:::docs/*"]},
    {"Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject"],
     "Resource": "arn:aws:s3:::docs/inbox/*"},
    {"Effect": "Allow", "Action": ["tidemark:ListTrash", "tidemark:PitrDiff"],
     "Resource": "arn:aws:s3:::docs"},
    {"Effect": "Allow", "Action": "tidemark:TimeTravel",
     "Resource": ["arn:aws:s3:::docs", "arn:aws:s3:::docs/*"],
     "Condition": {"DateGreaterThanEquals": {"tidemark:AsOf": "2026-01-01T00:00:00Z"}}},
    {"Effect": "Allow", "Action": "tidemark:Restore", "Resource": "arn:aws:s3:::docs/inbox/*"},
    {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::docs/private/*"},
    {"Effect": "Deny", "Action": "*", "Resource": "*",
     "Condition": {"StringEquals": {"tidemark:McpTool": ["pitr_restore", "delete_object"]}}}
  ]
}
```

```sh
tidemark admin user add docs-agent
tidemark admin user policy put docs-agent mcp docs-agent.json
tidemark admin key create docs-agent       # prints the secret once
```

Tool allow-lists work the same way: `"Condition": {"StringEquals": {"tidemark:McpTool":
["list_objects", "head_object"]}}` on an Allow lets the key read metadata through MCP but not
bodies (`get_object` is denied), and does not grant anything to non-MCP requests, which never
carry `tidemark:McpTool` (use `StringEqualsIfExists` / `Null` to express "S3 or these tools").

## Embedding (Rust)

```rust
let state = tidemark_mcp::McpState::new(engine.clone(), store.clone(), bucket_policies.clone());
// HTTP: merge into the server router (serves /_tidemark/mcp)
let app = app.merge(tidemark_mcp::http_router(state.clone()));
// stdio (tidemark mcp --stdio)
tidemark_mcp::serve_stdio(state).await?;
```

Limits (`tidemark_mcp::McpConfig`): `max_get_bytes` (1 MiB), `max_put_bytes` (4 MiB),
`max_search_scan` (10 000), `max_pitr_changes` (1 000), `max_http_body` (8 MiB),
`allowed_hosts` (empty = no Host check).
