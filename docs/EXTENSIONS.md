# Cairn — S3 extensions

Every extension is opt-in and namespaced: request/response headers are `x-cairn-*`, IAM actions
are `cairn:*`. Standard S3 clients never see a difference unless they send these headers.

## Request headers

| Header | Operations | Value | Behaviour | Policy action |
|---|---|---|---|---|
| `x-cairn-as-of` | GetObject, HeadObject, ListObjects, ListObjectsV2 | RFC 3339 timestamp (`2026-11-08T10:00:00Z`) or unix nanoseconds (`1794132000000000000`) | Time travel: read the key / list the bucket as it was at that instant, including versions that have since been overwritten or deleted but are still inside the bucket's retention window. Malformed values → `400 InvalidArgument`. Ignored when `versionId` is given. | `cairn:TimeTravel` (phase 2b) |
| `x-cairn-include-trash` | ListObjectVersions | `true` | Also list Superseded (overwritten in unversioned buckets) and SoftDeleted versions, which are otherwise invisible to every S3 operation. | `cairn:ListTrash` (phase 2b) |

## Response headers

| Header | Operations | Value |
|---|---|---|
| `x-cairn-blob-hash` | GetObject, HeadObject | `blake3:<64 hex>` — content hash of the object's bytes. Only for objects stored as a single blob (simple PUT/COPY); multipart objects omit it. |

## Planned (not yet served)

| Name | Kind | Phase |
|---|---|---|
| `?x-cairn-restore=<version-id>` (POST) | Restore a trashed version as a new head | 2a |
| `x-cairn-version-id` | Preserve version ids on Cairn→Cairn replication | 3b |

## IAM actions (`cairn:*`)

Canonical list, mirrored from `crates/cairn-auth/src/actions.rs` (Agent B owns evaluation; this
table must change with it). In phase 1c only the root credential exists, so none of these are
enforced yet beyond "root may do anything".

| Action | Guards |
|---|---|
| `cairn:AddUserToGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:AttachGroupPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:AttachRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:AttachUserPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:Backup` | backup/restore |
| `cairn:CreateAccessKey` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:CreateGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:CreatePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:CreateRole` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:CreateServiceAccount` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:CreateUser` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DeleteAccessKey` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DeleteGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DeleteGroupPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DeletePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DeleteRole` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DeleteRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DeleteUser` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DeleteUserPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DetachGroupPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DetachRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:DetachUserPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:Fsck` | metadata/blob consistency check |
| `cairn:Gc` | trigger GC |
| `cairn:GetGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:GetPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:GetRetention` | read retention windows |
| `cairn:GetRole` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:GetServerInfo` | server info |
| `cairn:GetStorageStats` | storage statistics |
| `cairn:GetUser` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:ListAccessKeys` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:ListGroups` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:ListPolicies` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:ListRoles` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:ListSessions` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:ListTrash` | `x-cairn-include-trash`, admin trash listing |
| `cairn:ListUsers` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:ManageEvents` | event sinks |
| `cairn:ManageKms` | named SSE keys |
| `cairn:ManageQuota` | bucket quotas |
| `cairn:ManageReplication` | replication rules |
| `cairn:Pitr` | point-in-time restore of a bucket/prefix |
| `cairn:PitrDiff` | PITR dry-run diff |
| `cairn:Purge` | irreversible trash purge |
| `cairn:PutGroupPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:PutRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:PutUserPolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:ReadAuditLog` | audit log |
| `cairn:RemoveUserFromGroup` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:Restore` | restore a trashed version |
| `cairn:RestoreBucket` | restore a trashed bucket |
| `cairn:RevokeSession` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:RotateRootCredentials` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:Scrub` | blob re-hash |
| `cairn:Search` | AI search (phase 4) |
| `cairn:SetRetention` | set per-bucket retention windows |
| `cairn:SubscribeEvents` | event stream |
| `cairn:TimeTravel` | `x-cairn-as-of` reads |
| `cairn:UpdateAccessKey` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:UpdateAssumeRolePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:UpdatePolicy` | IAM administration (users, keys, groups, roles, policies, sessions) |
| `cairn:UpdateUser` | IAM administration (users, keys, groups, roles, policies, sessions) |

## Health endpoints

`GET /healthz` (process up) and `GET /readyz` (metadata readable, `tmp/` writable, not shutting
down; `503` otherwise). They answer only unsigned, query-less GET/HEAD requests, so a bucket
named `healthz` or `readyz` remains reachable with signed requests.
