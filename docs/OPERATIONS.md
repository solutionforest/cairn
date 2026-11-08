# Cairn — Operations guide

Sections are owned by the agent that wrote them; append new sections, do not rewrite others.

## Upgrades

Cairn keeps its metadata (buckets, versions, IAM, sessions, outbox) in one redb file,
`<data_dir>/meta/cairn.redb`. Blobs are content-addressed and never change format in place, so an
upgrade is a metadata-schema question only.

**Schema version.** The version is a big-endian `u32` in the `kv` table under the key
`schema_version` (`cairn_meta::migrate::CURRENT_SCHEMA`, currently **1**). Every record also
carries a leading schema byte, so a migration can rewrite records lazily or in bulk.

**What happens on start.** Before the server opens the store it runs
`cairn_meta::migrate::migrate(<db>, dry_run = false)`:

1. A brand-new, empty database is stamped with the current version. A database with data but no
   stamp (written before the framework existed) is treated as v1.
2. A database **newer** than the binary (`schema_version > CURRENT_SCHEMA`) is refused with
   `metadata schema vN is newer than this binary supports`. Nothing is written. Downgrade by
   restoring the pre-upgrade backup (below) with the old binary.
3. If steps are needed, the redb file is first copied to `<db>.pre-v<N>.bak` (N = target
   version) and fsynced. Only then are the registered steps applied, each in its own write
   transaction together with the version bump, so a crash leaves the file at a well-defined
   version and re-running the upgrade continues from there.
4. A missing step (no registered `vA → vA+1`) aborts with `no migration path` before any write.

**Recommended procedure.**

```sh
cairn migrate --dry-run --data-dir /srv/cairn   # prints from/to and the planned steps; writes nothing
systemctl stop cairn
cairn backup --data-dir /srv/cairn ...           # optional extra copy (phase 3b)
# install the new binary
systemctl start cairn                            # runs the migration, writes meta/cairn.redb.pre-vN.bak
```

Disk space: the pre-upgrade snapshot is a full copy of `cairn.redb`; keep at least that much free
under `meta/`. Remove old `*.pre-v*.bak` files once the new version has run cleanly.

**Rollback / downgrade.** Stop the server, move `cairn.redb` aside, rename
`cairn.redb.pre-vN.bak` to `cairn.redb`, start the previous binary. Writes made after the upgrade
are lost (blobs they created become orphans that `cairn fsck --repair` / GC reclaim).

**For developers adding a migration.** Bump `CURRENT_SCHEMA`, append a
`Migration { from, to, name, apply }` to `cairn_meta::migrate::REGISTRY`. `apply` gets the
`&WriteTxn`, must be deterministic (the writer may re-run it), and should rewrite only what changed.
Add a test that copies `crates/cairn-meta/tests/fixtures/meta-v1.redb` (the committed v1 fixture)
and migrates it; never edit an existing fixture, add `meta-vN.redb` instead.

## OIDC federation (`AssumeRoleWithWebIdentity`)

*(Agent B, phase 3c.)* Workloads that already hold an OIDC ID token — GitHub Actions, GitLab CI,
Kubernetes service-account tokens, Google / Azure AD / Keycloak / Dex users — can exchange it for
temporary Cairn credentials without any long-lived key, exactly like AWS STS
`AssumeRoleWithWebIdentity`.

**1. Trust the identity provider** (server config; one block per issuer — the TOML keys map 1:1
onto `cairn_auth::OidcProviderConfig`; until `cairn serve` reads them, embedders build an
`OidcVerifier` and call `StsState::with_oidc`):

```toml
[[auth.oidc_providers]]
issuer    = "https://token.actions.githubusercontent.com"   # must equal the token's `iss`
audiences = ["cairn"]                                        # accepted `aud` values (≥ 1)
jwks_url  = "https://token.actions.githubusercontent.com/.well-known/jwks"
# jwks    = '{"keys":[...]}'          # inline JWKS instead of jwks_url (air-gapped IdPs)
[auth.oidc_providers.claim_tags]      # optional: claim -> session tag (aws:PrincipalTag/<tag>)
repository_owner = "org"
environment      = "env"
```

Rules: `issuer` and `jwks_url` must be `https://` (plain `http://` only on loopback, for
development); no OIDC discovery — give the JWKS URL. Only asymmetric algorithms are accepted
(RS256/384/512, PS256/384/512, ES256/384); `HS*` and `none` are rejected, as are symmetric or
encryption JWKs. The token must carry `iss`, `aud`, `sub` and `exp`; `exp`/`nbf` get 60 s of clock
leeway. The JWKS is fetched over rustls (no redirects, 5 s timeout, ≤ 1 MiB), cached for 1 h; a
token with an unknown `kid` triggers at most one refetch per provider every 10 s (key rotation
without a restart, without letting unauthenticated callers hammer the IdP). If a refetch fails,
cached keys keep working.

The **provider id** is the issuer without scheme (`token.actions.githubusercontent.com`). It
prefixes the trust-policy condition keys and may be used as the `Federated` principal.

**2. Create a role whose trust policy names the provider:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {"token.actions.githubusercontent.com:aud": "cairn"},
      "StringLike":   {"token.actions.githubusercontent.com:sub": "repo:acme/website:ref:refs/heads/main"}
    }
  }]
}
```

```sh
cairn admin role create ci-deploy --trust trust.json --max-session 3600
cairn admin role policy put ci-deploy write-site site-write.json
```

`Federated` accepts the issuer URL, the provider id or
`arn:aws:iam::000000000000:oidc-provider/<provider id>`. **Always constrain `sub`** (and `aud`):
without a condition every identity the IdP can mint may assume the role. `Principal: "*"` never
admits a web identity; an explicit `Deny` (federated or `*`) always wins.

Condition keys available in the trust policy: `<provider>:sub`, `<provider>:aud` (multi-valued),
`<provider>:iss`, `<provider>:azp`, `<provider>:email`, `<provider>:amr`,
`aws:FederatedProvider`, `aws:RequestTag/<tag>` and `aws:TagKeys` (from `claim_tags`),
`aws:SourceIp`, `aws:SecureTransport`, `aws:CurrentTime`, `aws:EpochTime`. Mapped tags stay on
the session as `aws:PrincipalTag/<tag>`, so one role can scope access per team, e.g.
`"Resource": "arn:aws:s3:::builds/${aws:PrincipalTag/org}/*"`.

**3. Exchange the token** (unsigned STS call, `POST /` form or `GET /?Action=…`):

```sh
aws sts assume-role-with-web-identity --endpoint-url https://cairn.example.com \
  --role-arn arn:aws:iam::000000000000:role/ci-deploy \
  --role-session-name "gha-$GITHUB_RUN_ID" \
  --web-identity-token "$ID_TOKEN" --duration-seconds 900
```

SDKs pick this up automatically with `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE` and
`AWS_ENDPOINT_URL_STS=https://cairn.example.com`. Duration: 15 min to the role's max session
(≤ 12 h). An optional `Policy` session policy narrows the session further.

Errors (AWS codes): `InvalidIdentityToken` (bad signature, wrong issuer / audience, unknown
`kid`, unsupported algorithm, federation not configured), `ExpiredTokenException`,
`IDPCommunicationError` (JWKS unreachable and nothing cached), `AccessDenied` (trust policy did
not allow it, or the role does not exist — the two are indistinguishable on purpose).

**Operating it.** Sessions show up in `cairn admin session ls` with source
`oidc:<provider>/<sub>`; revoke one with `cairn admin session revoke <access-key-id>`, or all of a role's by
deleting the role (`cairn admin role rm`). Removing a provider from the
config stops new exchanges immediately; already issued sessions run until they expire unless
revoked. The token itself is never logged or stored; the audit line is
`sts assume-role-with-web-identity role=… provider=… subject=… access_key_id=…`.
