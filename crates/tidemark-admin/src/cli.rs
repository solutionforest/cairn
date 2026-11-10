//! `tidemark admin …`: a clap subcommand tree that tidemark-cli mounts, talking to the admin API.
//!
//! ```ignore
//! let cmd = Cli::command().subcommand(tidemark_admin::cli());
//! if let Some(("admin", m)) = matches.subcommand() {
//!     let client = tidemark_admin::cli::client_from_matches(m)?;
//!     tidemark_admin::run(m, &client).await?;
//! }
//! ```

use crate::client::AdminClient;
use anyhow::{Context, Result, bail};
use clap::{ArgMatches, Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use serde_json::{Value, json};
use std::fmt::Write as _;
use tidemark_auth::SecretString;

/// `tidemark admin` arguments.
#[derive(Debug, Parser)]
#[command(
    name = "admin",
    about = "Administer a running Tidemark server (users, keys, policies, buckets, trash, PITR)"
)]
pub struct AdminArgs {
    /// Server endpoint.
    #[arg(
        long,
        global = true,
        env = "TIDEMARK_ENDPOINT",
        default_value = "http://127.0.0.1:9000"
    )]
    pub endpoint: String,
    /// Access key id (root or a principal allowed `tidemark:*`).
    #[arg(long, global = true, env = "TIDEMARK_ACCESS_KEY")]
    pub access_key: Option<String>,
    /// Secret access key.
    #[arg(
        long,
        global = true,
        env = "TIDEMARK_SECRET_KEY",
        hide_env_values = true
    )]
    pub secret_key: Option<String>,
    /// STS session token for temporary credentials.
    #[arg(
        long,
        global = true,
        env = "TIDEMARK_SESSION_TOKEN",
        hide_env_values = true
    )]
    pub session_token: Option<String>,
    /// Signing region.
    #[arg(
        long,
        global = true,
        env = "TIDEMARK_REGION",
        default_value = "us-east-1"
    )]
    pub region: String,
    /// Print raw JSON instead of tables.
    #[arg(long, global = true)]
    pub json: bool,
    /// Command.
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Top-level admin commands.
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Show the calling principal.
    Whoami,
    /// Server summary.
    Info,
    /// IAM users.
    #[command(subcommand)]
    User(UserCmd),
    /// Access keys.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Service accounts (a user with one bucket-scoped policy and a key).
    #[command(subcommand, name = "sa")]
    ServiceAccount(SaCmd),
    /// Groups.
    #[command(subcommand)]
    Group(GroupCmd),
    /// Managed policies.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Roles (assumable via STS).
    #[command(subcommand)]
    Role(RoleCmd),
    /// STS sessions.
    #[command(subcommand)]
    Session(SessionCmd),
    /// Buckets: usage, quota, retention, lock.
    #[command(subcommand)]
    Bucket(BucketCmd),
    /// Soft-deleted objects.
    #[command(subcommand)]
    Trash(TrashCmd),
    /// Point-in-time recovery.
    #[command(subcommand)]
    Pitr(PitrCmd),
    /// Backups made by the running server into `backup.dir`.
    #[command(subcommand)]
    Backup(BackupCmd),
}

/// Inline policy and attachment commands shared by users, groups and roles.
#[derive(Debug, Subcommand)]
pub enum InlineCmd {
    /// Put an inline policy from a JSON file (`-` = stdin).
    Put {
        /// Owner name.
        owner: String,
        /// Policy name.
        name: String,
        /// File with the policy document.
        file: String,
    },
    /// Remove an inline policy.
    Rm {
        /// Owner name.
        owner: String,
        /// Policy name.
        name: String,
    },
}

/// User commands.
#[derive(Debug, Subcommand)]
pub enum UserCmd {
    /// List users.
    Ls,
    /// Create a user.
    Add {
        /// Name.
        name: String,
    },
    /// Show a user.
    Info {
        /// Name.
        name: String,
    },
    /// Delete a user (and its keys and sessions).
    Rm {
        /// Name.
        name: String,
    },
    /// Re-enable a disabled user.
    Enable {
        /// Name.
        name: String,
    },
    /// Disable a user (keys stop working).
    Disable {
        /// Name.
        name: String,
    },
    /// Inline policies.
    #[command(subcommand)]
    Policy(InlineCmd),
    /// Attach a managed policy.
    Attach {
        /// User.
        user: String,
        /// Managed policy.
        policy: String,
    },
    /// Detach a managed policy.
    Detach {
        /// User.
        user: String,
        /// Managed policy.
        policy: String,
    },
}

/// Access key commands.
#[derive(Debug, Subcommand)]
pub enum KeyCmd {
    /// List keys (all, or one user's).
    Ls {
        /// Only this user's keys.
        #[arg(long)]
        user: Option<String>,
    },
    /// Create a key; the secret is printed once.
    Create {
        /// Owner user.
        user: String,
        /// Expiry (RFC 3339).
        #[arg(long)]
        expires: Option<String>,
        /// Allowed source CIDR (repeatable).
        #[arg(long = "cidr")]
        cidrs: Vec<String>,
    },
    /// Delete a key.
    Rm {
        /// Access key id.
        id: String,
    },
    /// Activate a key.
    Enable {
        /// Access key id.
        id: String,
    },
    /// Deactivate a key.
    Disable {
        /// Access key id.
        id: String,
    },
    /// Replace the root key pair; prints the new secret once.
    RotateRoot,
}

/// Service account commands.
#[derive(Debug, Subcommand)]
pub enum SaCmd {
    /// Create a service account for one bucket.
    Create {
        /// User name.
        name: String,
        /// Bucket.
        #[arg(long)]
        bucket: String,
        /// Read-only (default read-write).
        #[arg(long)]
        ro: bool,
    },
}

/// Group commands.
#[derive(Debug, Subcommand)]
pub enum GroupCmd {
    /// List groups.
    Ls,
    /// Create a group.
    Add {
        /// Name.
        name: String,
    },
    /// Show a group.
    Info {
        /// Name.
        name: String,
    },
    /// Delete a group.
    Rm {
        /// Name.
        name: String,
    },
    /// Add a user to a group.
    AddUser {
        /// Group.
        group: String,
        /// User.
        user: String,
    },
    /// Remove a user from a group.
    RmUser {
        /// Group.
        group: String,
        /// User.
        user: String,
    },
    /// Inline policies.
    #[command(subcommand)]
    Policy(InlineCmd),
    /// Attach a managed policy.
    Attach {
        /// Group.
        group: String,
        /// Managed policy.
        policy: String,
    },
    /// Detach a managed policy.
    Detach {
        /// Group.
        group: String,
        /// Managed policy.
        policy: String,
    },
}

/// Managed policy commands.
#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// List managed policies.
    Ls,
    /// Create from a JSON file (`-` = stdin).
    Create {
        /// Name.
        name: String,
        /// File.
        file: String,
    },
    /// Show a policy.
    Info {
        /// Name.
        name: String,
    },
    /// Replace the document.
    Update {
        /// Name.
        name: String,
        /// File.
        file: String,
    },
    /// Delete (must be detached).
    Rm {
        /// Name.
        name: String,
    },
}

/// Role commands.
#[derive(Debug, Subcommand)]
pub enum RoleCmd {
    /// List roles.
    Ls,
    /// Create a role with a trust policy file.
    Create {
        /// Name.
        name: String,
        /// Trust policy file.
        #[arg(long)]
        trust: String,
        /// Maximum session duration in seconds.
        #[arg(long)]
        max_session: Option<u64>,
    },
    /// Show a role.
    Info {
        /// Name.
        name: String,
    },
    /// Delete a role (its sessions are revoked).
    Rm {
        /// Name.
        name: String,
    },
    /// Replace the trust policy.
    Trust {
        /// Role.
        name: String,
        /// File.
        file: String,
    },
    /// Inline policies.
    #[command(subcommand)]
    Policy(InlineCmd),
    /// Attach a managed policy.
    Attach {
        /// Role.
        role: String,
        /// Managed policy.
        policy: String,
    },
    /// Detach a managed policy.
    Detach {
        /// Role.
        role: String,
        /// Managed policy.
        policy: String,
    },
}

/// STS session commands.
#[derive(Debug, Subcommand)]
pub enum SessionCmd {
    /// List sessions.
    Ls,
    /// Revoke a session by its access key id.
    Revoke {
        /// Temporary access key id.
        id: String,
    },
    /// Delete expired sessions.
    PurgeExpired,
}

/// Bucket commands.
#[derive(Debug, Subcommand)]
pub enum BucketCmd {
    /// List buckets with usage, quota and retention.
    Ls,
    /// Show one bucket.
    Info {
        /// Bucket.
        bucket: String,
    },
    /// Set (bytes, or `none`) the quota.
    Quota {
        /// Bucket.
        bucket: String,
        /// Bytes, or `none`.
        quota: String,
    },
    /// Show or set retention windows.
    Retention {
        /// Bucket.
        bucket: String,
        /// Trash retention in days.
        #[arg(long)]
        trash_days: Option<u32>,
        /// History (PITR) retention in days.
        #[arg(long)]
        history_days: Option<u32>,
    },
    /// Show the Object Lock configuration.
    Lock {
        /// Bucket.
        bucket: String,
    },
}

/// Trash commands.
#[derive(Debug, Subcommand)]
pub enum TrashCmd {
    /// List soft-deleted versions.
    Ls(TrashLs),
    /// Restore a soft-deleted version; without `--key`, undo the delete of the whole bucket
    /// (the bucket and every version of every key).
    Restore {
        /// Bucket.
        #[arg(long)]
        bucket: String,
        /// Key (omit to restore a deleted bucket with all its versions).
        #[arg(long)]
        key: Option<String>,
        /// Version (default newest deleted).
        #[arg(long)]
        version: Option<String>,
    },
    /// Restore a trashed bucket by id.
    RestoreBucket {
        /// Bucket id.
        #[arg(long)]
        id: String,
        /// New name.
        #[arg(long = "as")]
        as_name: Option<String>,
    },
    /// Irreversibly purge trash entries.
    Purge {
        /// Bucket.
        #[arg(long)]
        bucket: String,
        /// Key.
        #[arg(long)]
        key: Option<String>,
        /// Version.
        #[arg(long)]
        version: Option<String>,
        /// Prefix.
        #[arg(long)]
        prefix: Option<String>,
        /// Only entries deleted before this time (RFC 3339).
        #[arg(long)]
        older_than: Option<String>,
        /// Confirm the irreversible purge.
        #[arg(long)]
        yes: bool,
    },
}

/// `trash ls` filters.
#[derive(Debug, Args)]
pub struct TrashLs {
    /// Bucket.
    #[arg(long)]
    pub bucket: Option<String>,
    /// Prefix.
    #[arg(long)]
    pub prefix: Option<String>,
    /// Deleted after (RFC 3339).
    #[arg(long)]
    pub after: Option<String>,
    /// Deleted before (RFC 3339).
    #[arg(long)]
    pub before: Option<String>,
    /// Deleted by principal id.
    #[arg(long)]
    pub by: Option<String>,
    /// Page size.
    #[arg(long)]
    pub limit: Option<u32>,
}

/// PITR commands.
#[derive(Debug, Subcommand)]
pub enum PitrCmd {
    /// Restore a bucket or prefix to a point in time.
    Restore {
        /// Bucket.
        #[arg(long)]
        bucket: String,
        /// Target time (RFC 3339).
        #[arg(long)]
        as_of: String,
        /// Prefix.
        #[arg(long)]
        prefix: Option<String>,
        /// Restore into this bucket.
        #[arg(long)]
        target_bucket: Option<String>,
        /// Restore under this prefix.
        #[arg(long)]
        target_prefix: Option<String>,
        /// Only show what would change.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show changes between two points in time.
    Diff {
        /// Bucket.
        #[arg(long)]
        bucket: String,
        /// From (RFC 3339).
        #[arg(long)]
        from: String,
        /// To (RFC 3339, default now).
        #[arg(long)]
        to: Option<String>,
        /// Prefix.
        #[arg(long)]
        prefix: Option<String>,
    },
}

/// Backup commands.
#[derive(Debug, Subcommand)]
pub enum BackupCmd {
    /// Start a backup into `<backup.dir>/<set>` (incremental unless the set is new or --full).
    Start {
        /// Set name, e.g. `2026-W46`.
        #[arg(long)]
        set: String,
        /// Upload every blob again.
        #[arg(long)]
        full: bool,
        /// Wait for it to finish; exit non-zero if it fails.
        #[arg(long)]
        wait: bool,
    },
    /// The running or most recent backup.
    Status,
}

/// The `admin` subcommand for tidemark-cli to mount.
pub fn cli() -> clap::Command {
    AdminArgs::command()
}

/// Build the HTTP client from parsed `admin` arguments (flags or `TIDEMARK_*` env).
pub fn client_from_matches(m: &ArgMatches) -> Result<AdminClient> {
    let a = AdminArgs::from_arg_matches(m)?;
    client_from_args(&a)
}

fn client_from_args(a: &AdminArgs) -> Result<AdminClient> {
    let ak = a
        .access_key
        .clone()
        .context("--access-key or TIDEMARK_ACCESS_KEY is required")?;
    let sk = a
        .secret_key
        .clone()
        .context("--secret-key or TIDEMARK_SECRET_KEY is required")?;
    Ok(AdminClient::new(
        &a.endpoint,
        &ak,
        SecretString::new(sk),
        a.session_token.clone().map(SecretString::new),
        &a.region,
    )?)
}

/// Run a parsed `admin` command, printing to stdout.
pub async fn run(m: &ArgMatches, client: &AdminClient) -> Result<()> {
    let mut out = String::new();
    run_to(m, client, &mut out).await?;
    print!("{out}");
    Ok(())
}

fn read_doc(file: &str) -> Result<Value> {
    let text = if file == "-" {
        std::io::read_to_string(std::io::stdin())?
    } else {
        std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?
    };
    serde_json::from_str(&text).with_context(|| format!("{file} is not valid JSON"))
}

fn seg(s: &str) -> String {
    tidemark_auth::sigv4::uri_encode(s.as_bytes(), false)
}

/// Run a parsed `admin` command, appending the output to `out` (tests).
pub async fn run_to(m: &ArgMatches, c: &AdminClient, out: &mut String) -> Result<()> {
    let a = AdminArgs::from_arg_matches(m)?;
    let none: &[(&str, String)] = &[];
    let v = match &a.cmd {
        Cmd::Whoami => c.call("GET", "/whoami", none, None).await?,
        Cmd::Info => c.call("GET", "/info", none, None).await?,
        Cmd::User(u) => match u {
            UserCmd::Ls => c.call("GET", "/users", none, None).await?,
            UserCmd::Add { name } => {
                c.call("POST", "/users", none, Some(&json!({ "name": name })))
                    .await?
            }
            UserCmd::Info { name } => {
                c.call("GET", &format!("/users/{}", seg(name)), none, None)
                    .await?
            }
            UserCmd::Rm { name } => {
                c.call("DELETE", &format!("/users/{}", seg(name)), none, None)
                    .await?
            }
            UserCmd::Enable { name } => {
                c.call("POST", &format!("/users/{}/enable", seg(name)), none, None)
                    .await?
            }
            UserCmd::Disable { name } => {
                c.call("POST", &format!("/users/{}/disable", seg(name)), none, None)
                    .await?
            }
            UserCmd::Policy(p) => inline(c, "users", p).await?,
            UserCmd::Attach { user, policy } => {
                let p = format!("/users/{}/attached-policies/{}", seg(user), seg(policy));
                c.call("PUT", &p, none, None).await?
            }
            UserCmd::Detach { user, policy } => {
                let p = format!("/users/{}/attached-policies/{}", seg(user), seg(policy));
                c.call("DELETE", &p, none, None).await?
            }
        },
        Cmd::Key(k) => match k {
            KeyCmd::Ls { user } => {
                let q: Vec<(&str, String)> = user.iter().map(|u| ("user", u.clone())).collect();
                c.call("GET", "/access-keys", &q, None).await?
            }
            KeyCmd::Create {
                user,
                expires,
                cidrs,
            } => {
                let body = json!({ "expires_at": expires, "allowed_source_cidrs": cidrs });
                let p = format!("/users/{}/access-keys", seg(user));
                c.call("POST", &p, none, Some(&body)).await?
            }
            KeyCmd::Rm { id } => {
                c.call("DELETE", &format!("/access-keys/{}", seg(id)), none, None)
                    .await?
            }
            KeyCmd::Enable { id } => {
                let p = format!("/access-keys/{}/activate", seg(id));
                c.call("POST", &p, none, None).await?
            }
            KeyCmd::Disable { id } => {
                let p = format!("/access-keys/{}/deactivate", seg(id));
                c.call("POST", &p, none, None).await?
            }
            KeyCmd::RotateRoot => c.call("POST", "/root/rotate", none, None).await?,
        },
        Cmd::ServiceAccount(SaCmd::Create { name, bucket, ro }) => {
            let body = json!({ "name": name, "bucket": bucket, "read_only": ro });
            c.call("POST", "/service-accounts", none, Some(&body))
                .await?
        }
        Cmd::Group(g) => match g {
            GroupCmd::Ls => c.call("GET", "/groups", none, None).await?,
            GroupCmd::Add { name } => {
                c.call("POST", "/groups", none, Some(&json!({ "name": name })))
                    .await?
            }
            GroupCmd::Info { name } => {
                c.call("GET", &format!("/groups/{}", seg(name)), none, None)
                    .await?
            }
            GroupCmd::Rm { name } => {
                c.call("DELETE", &format!("/groups/{}", seg(name)), none, None)
                    .await?
            }
            GroupCmd::AddUser { group, user } => {
                let p = format!("/groups/{}/members/{}", seg(group), seg(user));
                c.call("PUT", &p, none, None).await?
            }
            GroupCmd::RmUser { group, user } => {
                let p = format!("/groups/{}/members/{}", seg(group), seg(user));
                c.call("DELETE", &p, none, None).await?
            }
            GroupCmd::Policy(p) => inline(c, "groups", p).await?,
            GroupCmd::Attach { group, policy } => {
                let p = format!("/groups/{}/attached-policies/{}", seg(group), seg(policy));
                c.call("PUT", &p, none, None).await?
            }
            GroupCmd::Detach { group, policy } => {
                let p = format!("/groups/{}/attached-policies/{}", seg(group), seg(policy));
                c.call("DELETE", &p, none, None).await?
            }
        },
        Cmd::Policy(p) => match p {
            PolicyCmd::Ls => c.call("GET", "/policies", none, None).await?,
            PolicyCmd::Create { name, file } => {
                let body = json!({ "name": name, "document": read_doc(file)? });
                c.call("POST", "/policies", none, Some(&body)).await?
            }
            PolicyCmd::Info { name } => {
                c.call("GET", &format!("/policies/{}", seg(name)), none, None)
                    .await?
            }
            PolicyCmd::Update { name, file } => {
                let body = json!({ "document": read_doc(file)? });
                let p = format!("/policies/{}", seg(name));
                c.call("PUT", &p, none, Some(&body)).await?
            }
            PolicyCmd::Rm { name } => {
                c.call("DELETE", &format!("/policies/{}", seg(name)), none, None)
                    .await?
            }
        },
        Cmd::Role(r) => match r {
            RoleCmd::Ls => c.call("GET", "/roles", none, None).await?,
            RoleCmd::Create {
                name,
                trust,
                max_session,
            } => {
                let body = json!({
                    "name": name, "trust_policy": read_doc(trust)?, "max_session_secs": max_session,
                });
                c.call("POST", "/roles", none, Some(&body)).await?
            }
            RoleCmd::Info { name } => {
                c.call("GET", &format!("/roles/{}", seg(name)), none, None)
                    .await?
            }
            RoleCmd::Rm { name } => {
                c.call("DELETE", &format!("/roles/{}", seg(name)), none, None)
                    .await?
            }
            RoleCmd::Trust { name, file } => {
                let body = json!({ "document": read_doc(file)? });
                let p = format!("/roles/{}/trust-policy", seg(name));
                c.call("PUT", &p, none, Some(&body)).await?
            }
            RoleCmd::Policy(p) => inline(c, "roles", p).await?,
            RoleCmd::Attach { role, policy } => {
                let p = format!("/roles/{}/attached-policies/{}", seg(role), seg(policy));
                c.call("PUT", &p, none, None).await?
            }
            RoleCmd::Detach { role, policy } => {
                let p = format!("/roles/{}/attached-policies/{}", seg(role), seg(policy));
                c.call("DELETE", &p, none, None).await?
            }
        },
        Cmd::Session(s) => match s {
            SessionCmd::Ls => c.call("GET", "/sessions", none, None).await?,
            SessionCmd::Revoke { id } => {
                c.call("DELETE", &format!("/sessions/{}", seg(id)), none, None)
                    .await?
            }
            SessionCmd::PurgeExpired => {
                c.call("POST", "/sessions/purge-expired", none, None)
                    .await?
            }
        },
        Cmd::Bucket(b) => match b {
            BucketCmd::Ls => c.call("GET", "/buckets", none, None).await?,
            BucketCmd::Info { bucket } => {
                c.call("GET", &format!("/buckets/{}", seg(bucket)), none, None)
                    .await?
            }
            BucketCmd::Quota { bucket, quota } => {
                let q = if quota.eq_ignore_ascii_case("none") {
                    None
                } else {
                    Some(parse_size(quota)?)
                };
                let p = format!("/buckets/{}/quota", seg(bucket));
                c.call("PUT", &p, none, Some(&json!({ "quota_bytes": q })))
                    .await?
            }
            BucketCmd::Retention {
                bucket,
                trash_days,
                history_days,
            } => {
                let p = format!("/buckets/{}/retention", seg(bucket));
                if trash_days.is_none() && history_days.is_none() {
                    c.call("GET", &p, none, None).await?
                } else {
                    let body = json!({ "trash_days": trash_days, "history_days": history_days });
                    c.call("PUT", &p, none, Some(&body)).await?
                }
            }
            BucketCmd::Lock { bucket } => {
                let v = c
                    .call("GET", &format!("/buckets/{}", seg(bucket)), none, None)
                    .await?;
                v["object_lock"].clone()
            }
        },
        Cmd::Trash(t) => match t {
            TrashCmd::Ls(l) => {
                let mut q: Vec<(&str, String)> = Vec::new();
                for (k, v) in [
                    ("bucket", &l.bucket),
                    ("prefix", &l.prefix),
                    ("deleted_after", &l.after),
                    ("deleted_before", &l.before),
                    ("by", &l.by),
                ] {
                    if let Some(v) = v {
                        q.push((k, v.clone()));
                    }
                }
                if let Some(n) = l.limit {
                    q.push(("limit", n.to_string()));
                }
                c.call("GET", "/trash", &q, None).await?
            }
            TrashCmd::Restore {
                bucket,
                key,
                version,
            } => match key {
                Some(key) => {
                    let body = json!({ "bucket": bucket, "key": key, "version_id": version });
                    c.call("POST", "/trash/restore", none, Some(&body)).await?
                }
                None => {
                    if version.is_some() {
                        bail!("--version needs --key");
                    }
                    let body = json!({ "bucket": bucket, "all_versions": true });
                    c.call("POST", "/trash/restore-bucket", none, Some(&body))
                        .await?
                }
            },
            TrashCmd::RestoreBucket { id, as_name } => {
                let body = json!({ "bucket_id": id, "as_name": as_name });
                c.call("POST", "/trash/restore-bucket", none, Some(&body))
                    .await?
            }
            TrashCmd::Purge {
                bucket,
                key,
                version,
                prefix,
                older_than,
                yes,
            } => {
                if !yes {
                    bail!("purge is irreversible; re-run with --yes");
                }
                let body = json!({
                    "bucket": bucket, "key": key, "version_id": version, "prefix": prefix,
                    "older_than": older_than, "confirm": true,
                });
                c.call("POST", "/trash/purge", none, Some(&body)).await?
            }
        },
        Cmd::Pitr(p) => match p {
            PitrCmd::Restore {
                bucket,
                as_of,
                prefix,
                target_bucket,
                target_prefix,
                dry_run,
            } => {
                let body = json!({
                    "bucket": bucket, "as_of": as_of, "prefix": prefix,
                    "target_bucket": target_bucket, "target_prefix": target_prefix,
                    "dry_run": dry_run,
                });
                c.call("POST", "/pitr/restore", none, Some(&body)).await?
            }
            PitrCmd::Diff {
                bucket,
                from,
                to,
                prefix,
            } => {
                let mut q = vec![("bucket", bucket.clone()), ("from", from.clone())];
                if let Some(t) = to {
                    q.push(("to", t.clone()));
                }
                if let Some(p) = prefix {
                    q.push(("prefix", p.clone()));
                }
                c.call("GET", "/pitr/diff", &q, None).await?
            }
        },
        Cmd::Backup(BackupCmd::Status) => c.call("GET", "/backup", none, None).await?,
        Cmd::Backup(BackupCmd::Start { set, full, wait }) => {
            let body = json!({ "set": set, "full": full });
            let mut v = c.call("POST", "/backup", none, Some(&body)).await?;
            while *wait && v["state"] == "running" {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                v = c.call("GET", "/backup", none, None).await?;
            }
            if v["state"] == "failed" {
                anyhow::bail!(
                    "backup into set {set} failed: {}",
                    v["error"].as_str().unwrap_or("unknown error")
                );
            }
            v
        }
    };
    if a.json {
        writeln!(out, "{}", serde_json::to_string_pretty(&v)?)?;
    } else {
        render(&v, out);
    }
    Ok(())
}

async fn inline(c: &AdminClient, kind: &str, cmd: &InlineCmd) -> Result<Value> {
    Ok(match cmd {
        InlineCmd::Put { owner, name, file } => {
            let body = json!({ "document": read_doc(file)? });
            let p = format!("/{kind}/{}/policies/{}", seg(owner), seg(name));
            c.call("PUT", &p, &[], Some(&body)).await?
        }
        InlineCmd::Rm { owner, name } => {
            let p = format!("/{kind}/{}/policies/{}", seg(owner), seg(name));
            c.call("DELETE", &p, &[], None).await?
        }
    })
}

/// Parse `123`, `10K`, `5MiB`, `2G`, `1T` (binary units) into bytes.
pub fn parse_size(s: &str) -> Result<u64> {
    let t = s.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (n, unit) = t.split_at(split);
    let n: u64 = n.parse().with_context(|| format!("invalid size {s:?}"))?;
    let mul: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        _ => bail!("invalid size unit in {s:?}"),
    };
    n.checked_mul(mul).context("size overflows u64")
}

fn scalar(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(scalar).collect::<Vec<_>>().join(","),
        Value::Object(_) => v.to_string(),
        other => other.to_string(),
    }
}

/// Human rendering: a table for `{"items": [...]}` / arrays of objects, `key: value` lines for
/// objects, `ok` for acknowledgements.
pub fn render(v: &Value, out: &mut String) {
    let items = v.get("items").or(v.get("entries")).unwrap_or(v);
    match items {
        Value::Array(rows) if rows.iter().all(Value::is_object) => {
            if rows.is_empty() {
                let _ = writeln!(out, "(none)");
                return;
            }
            let mut cols: Vec<String> = Vec::new();
            for r in rows {
                for (k, val) in r.as_object().into_iter().flatten() {
                    if !val.is_object() && !cols.contains(k) {
                        cols.push(k.clone());
                    }
                }
            }
            cols.retain(|c| c != "document" && c != "trust_policy");
            const FIRST: &[&str] = &[
                "name",
                "access_key_id",
                "bucket",
                "key",
                "version_id",
                "principal",
            ];
            cols.sort_by_key(|c| FIRST.iter().position(|f| f == c).unwrap_or(FIRST.len()));
            let cells: Vec<Vec<String>> = rows
                .iter()
                .map(|r| cols.iter().map(|c| scalar(&r[c.as_str()])).collect())
                .collect();
            let widths: Vec<usize> = cols
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    cells
                        .iter()
                        .map(|r| r[i].len())
                        .chain([c.len()])
                        .max()
                        .unwrap_or(0)
                })
                .collect();
            let line = |vals: Vec<&str>, out: &mut String| {
                let s: Vec<String> = vals
                    .iter()
                    .zip(&widths)
                    .map(|(v, w)| format!("{v:<w$}"))
                    .collect();
                let _ = writeln!(out, "{}", s.join("  ").trim_end());
            };
            line(
                cols.iter()
                    .map(|c| c.to_ascii_uppercase())
                    .collect::<Vec<_>>()
                    .iter()
                    .map(String::as_str)
                    .collect(),
                out,
            );
            for r in &cells {
                line(r.iter().map(String::as_str).collect(), out);
            }
        }
        Value::Object(m) if m.len() == 1 && m.get("ok") == Some(&Value::Bool(true)) => {
            let _ = writeln!(out, "ok");
        }
        Value::Object(m) => {
            let w = m.keys().map(String::len).max().unwrap_or(0);
            for (k, val) in m {
                let _ = writeln!(out, "{k:<w$}  {}", scalar(val));
            }
            if m.contains_key("secret_access_key") {
                let _ = writeln!(out, "\nThe secret is shown only once; store it now.");
            }
        }
        other => {
            let _ = writeln!(out, "{}", scalar(other));
        }
    }
}
