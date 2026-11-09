# Tidemark — S3 extensions

Every extension is opt-in and namespaced: request/response headers are `x-tidemark-*`, IAM actions
are `tidemark:*`. Standard S3 clients never see a difference unless they send these headers.

## Request headers

| Header | Operations | Value | Behaviour | Policy action |
|---|---|---|---|---|
| `x-tidemark-as-of` | GetObject, HeadObject, ListObjects, ListObjectsV2 | RFC 3339 timestamp (`2026-11-08T10:00:00Z`) or unix nanoseconds (`1794132000000000000`) | Time travel: read the key / list the bucket as it was at that instant, including versions that have since been overwritten or deleted but are still inside the bucket's retention window. Malformed values → `400 InvalidArgument`. Ignored when `versionId` is given. | `tidemark:TimeTravel` (phase 2b) |
| `x-tidemark-include-trash` | ListObjectVersions | `true` | Also list Superseded (overwritten in unversioned buckets) and SoftDeleted versions, which are otherwise invisible to every S3 operation. | `tidemark:ListTrash` (phase 2b) |

## Response headers

| Header | Operations | Value |
|---|---|---|
| `x-tidemark-blob-hash` | GetObject, HeadObject | `blake3:<64 hex>` — content hash of the object's bytes. Only for objects stored as a single blob (simple PUT/COPY); multipart objects omit it. |

## Planned (not yet served)

| Name | Kind | Phase |
|---|---|---|
| `?x-tidemark-restore=<version-id>` (POST) | Restore a trashed version as a new head | 2a |
| `x-tidemark-version-id` | Preserve version ids on Tidemark→Tidemark replication | 3b |

## IAM actions (`tidemark:*`)

Canonical list, mirrored from `crates/tidemark-auth/src/actions.rs` (Agent B owns evaluation; this
table must change with it). In phase 1c only the root credential exists, so none of these are
enforced yet beyond "root may do anything".

| Action | Guards |
|---|---|
| `tidemark:AddUserToGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:AttachGroupPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:AttachRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:AttachUserPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:Backup` | backup/restore |
| `tidemark:CreateAccessKey` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:CreateGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:CreatePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:CreateRole` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:CreateServiceAccount` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:CreateUser` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DeleteAccessKey` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DeleteGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DeleteGroupPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DeletePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DeleteRole` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DeleteRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DeleteUser` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DeleteUserPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DetachGroupPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DetachRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:DetachUserPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:Fsck` | metadata/blob consistency check |
| `tidemark:Gc` | trigger GC |
| `tidemark:GetGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:GetPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:GetRetention` | read retention windows |
| `tidemark:GetRole` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:GetServerInfo` | server info |
| `tidemark:GetStorageStats` | storage statistics |
| `tidemark:GetUser` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:ListAccessKeys` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:ListGroups` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:ListPolicies` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:ListRoles` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:ListSessions` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:ListTrash` | `x-tidemark-include-trash`, admin trash listing |
| `tidemark:ListUsers` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:ManageEvents` | event sinks |
| `tidemark:ManageKms` | named SSE keys |
| `tidemark:ManageQuota` | bucket quotas |
| `tidemark:ManageReplication` | replication rules |
| `tidemark:Pitr` | point-in-time restore of a bucket/prefix |
| `tidemark:PitrDiff` | PITR dry-run diff |
| `tidemark:Purge` | irreversible trash purge |
| `tidemark:PutGroupPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:PutRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:PutUserPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:ReadAuditLog` | audit log |
| `tidemark:RemoveUserFromGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:Restore` | restore a trashed version |
| `tidemark:RestoreBucket` | restore a trashed bucket |
| `tidemark:RevokeSession` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:RotateRootCredentials` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:Scrub` | blob re-hash |
| `tidemark:Search` | AI search (phase 4) |
| `tidemark:SetRetention` | set per-bucket retention windows |
| `tidemark:SubscribeEvents` | event stream |
| `tidemark:TimeTravel` | `x-tidemark-as-of` reads |
| `tidemark:UpdateAccessKey` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:UpdateAssumeRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:UpdatePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `tidemark:UpdateUser` | IAM administration (users, keys, groups, roles, policies, sessions) |

## Health endpoints

`GET /healthz` (process up) and `GET /readyz` (metadata readable, `tmp/` writable, not shutting
down; `503` otherwise). They answer only unsigned, query-less GET/HEAD requests, so a bucket
named `healthz` or `readyz` remains reachable with signed requests.

## Condition keys and MCP (Agent B, phase 3c)

Tidemark-specific IAM condition keys, usable in identity, bucket and session policies:

| Key | Set on | Value |
|---|---|---|
| `tidemark:McpTool` | every call made through the MCP server (`/_tidemark/mcp`, `tidemark mcp --stdio`) | the tool name (`list_buckets`, `list_objects`, `get_object`, `head_object`, `put_object`, `delete_object`, `copy_object`, `search`, `trash_list`, `trash_restore`, `pitr_head_at`, `pitr_diff`, `pitr_restore`, `bucket_info`). Absent on plain S3 / admin requests, so `"StringEquals": {"tidemark:McpTool": [...]}` on an Allow grants only via MCP, and on a Deny blocks only those tools. |
| `tidemark:AsOf` | S3 requests with `x-tidemark-as-of`; MCP `as_of` / `at` arguments | the requested instant (RFC 3339), for `Date*` conditions. |

`x-tidemark-as-of` reads (and MCP `as_of`, `pitr_head_at`) need the normal read action **and**
`tidemark:TimeTravel` on the same resource (object ARN for GetObject/HeadObject, bucket ARN for
ListObjects/ListObjectsV2); not checked when a `versionId` is given. Enforced by
`tidemark_auth::TidemarkS3Access` from phase 3c.

MCP tools map onto the same actions as their S3 equivalents (`s3:GetObject`, `s3:PutObject`,
`s3:ListBucket`, …) plus `tidemark:ListTrash`, `tidemark:Restore`, `tidemark:PitrDiff`, `tidemark:Pitr` for
the recovery tools; see `docs/MCP.md` for the full table.

Standard AWS keys added in phase 3c: `aws:PrincipalTag/<tag>` (session tags of web-identity
sessions, mapped from OIDC claims) and, in role trust policies for `AssumeRoleWithWebIdentity`,
`<provider>:sub`, `<provider>:aud`, `<provider>:iss`, `<provider>:azp`, `<provider>:email`,
`<provider>:amr`, `aws:FederatedProvider`, `aws:RequestTag/<tag>`, `aws:TagKeys` (OPERATIONS,
"OIDC federation").
