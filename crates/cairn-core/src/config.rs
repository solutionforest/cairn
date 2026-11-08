//! Server configuration: TOML file plus `CAIRN_<SECTION>_<FIELD>` environment overlay.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Reading the file failed.
    #[error("reading config {path}: {source}")]
    Io {
        /// Path.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// TOML parse failure.
    #[error("parsing config: {0}")]
    Parse(String),
    /// An env var could not be applied.
    #[error("environment variable {var}: {msg}")]
    Env {
        /// Variable name.
        var: String,
        /// Problem.
        msg: String,
    },
}

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `[server]`
    pub server: ServerConfig,
    /// `[storage]`
    pub storage: StorageConfig,
    /// `[retention]`
    pub retention: RetentionConfig,
    /// `[auth]`
    pub auth: AuthConfig,
    /// `[limits]`
    pub limits: LimitsConfig,
    /// `[events]`
    pub events: EventsConfig,
    /// `[mcp]`
    pub mcp: McpConfig,
    /// `[metrics]`
    pub metrics: MetricsConfig,
    /// `[log]`
    pub log: LogConfig,
    /// `[audit]`
    pub audit: AuditConfig,
}

/// `[server]` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address, e.g. `0.0.0.0:9000`.
    pub listen: String,
    /// Base domain for virtual-host-style buckets (`bucket.<domain>`); path-style always works.
    pub domain: Option<String>,
    /// Region name reported to clients.
    pub region: String,
    /// TLS certificate chain (PEM).
    pub tls_cert: Option<PathBuf>,
    /// TLS private key (PEM).
    pub tls_key: Option<PathBuf>,
    /// How long in-flight requests may drain after SIGTERM / ctrl-c.
    #[serde(with = "duration_serde")]
    pub shutdown_grace: Duration,
    /// Reverse proxies (CIDRs) whose `X-Forwarded-For` / `X-Forwarded-Proto` are trusted.
    pub trusted_proxies: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: "127.0.0.1:9000".into(),
            domain: None,
            region: "us-east-1".into(),
            tls_cert: None,
            tls_key: None,
            shutdown_grace: Duration::from_secs(30),
            trusted_proxies: Vec::new(),
        }
    }
}

/// `[storage]` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Data directory root.
    pub data_dir: PathBuf,
    /// fsync blobs before rename (disable only for tests).
    pub fsync: bool,
    /// Re-hash blobs while streaming GETs.
    pub verify_on_read: bool,
    /// Encrypt every blob at rest with a key derived from the master key.
    pub encrypt_at_rest: bool,
    /// Free space (bytes) kept under the data directory; writes that would eat into it get
    /// `507`. `0` disables the guard.
    pub min_free: u64,
    /// Run the background scrubber (re-hash blobs, mark damage).
    pub scrub: bool,
    /// Scrubber read budget in bytes per second (0 = unthrottled).
    pub scrub_bytes_per_sec: u64,
    /// Pause between scrub passes once every blob has been verified.
    #[serde(with = "duration_serde")]
    pub scrub_idle: Duration,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            data_dir: PathBuf::from("./data"),
            fsync: true,
            verify_on_read: false,
            encrypt_at_rest: false,
            min_free: 1 << 30,
            scrub: false,
            scrub_bytes_per_sec: 50 * 1024 * 1024,
            scrub_idle: Duration::from_secs(3600),
        }
    }
}

/// `[retention]` section: server-wide soft-delete defaults (DESIGN §7.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    /// How long soft-deleted versions stay restorable.
    #[serde(with = "duration_serde")]
    pub soft_delete: Duration,
    /// How long superseded (shadow) versions are kept.
    #[serde(with = "duration_serde")]
    pub shadow_history: Duration,
    /// Minimum number of versions kept per key regardless of age.
    pub min_versions_kept: u32,
    /// Extra delay between refcount reaching 0 and unlinking the blob.
    #[serde(with = "duration_serde")]
    pub gc_grace: Duration,
    /// GC loop interval.
    #[serde(with = "duration_serde")]
    pub gc_interval: Duration,
    /// Lifecycle worker interval.
    #[serde(with = "duration_serde")]
    pub lifecycle_interval: Duration,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        RetentionConfig {
            soft_delete: Duration::from_secs(30 * 86400),
            shadow_history: Duration::from_secs(30 * 86400),
            min_versions_kept: 1,
            gc_grace: Duration::from_secs(3600),
            gc_interval: Duration::from_secs(60),
            lifecycle_interval: Duration::from_secs(3600),
        }
    }
}

/// `[auth]` section.
#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Root access key id (`CAIRN_ROOT_ACCESS_KEY`).
    pub root_access_key: Option<String>,
    /// Root secret key (`CAIRN_ROOT_SECRET`).
    pub root_secret_key: Option<String>,
    /// Allow unsigned requests (they are still subject to policy in phase 2).
    pub allow_anonymous: bool,
    /// Trusted OIDC identity providers for `AssumeRoleWithWebIdentity` (`[[auth.oidc_providers]]`).
    pub oidc_providers: Vec<OidcProviderEntry>,
}

/// One `[[auth.oidc_providers]]` entry (mirrors `cairn_auth::OidcProviderConfig`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct OidcProviderEntry {
    /// Issuer URL (exact match with the token's `iss`).
    pub issuer: String,
    /// Accepted `aud` values (at least one).
    pub audiences: Vec<String>,
    /// JWKS endpoint (`https://`).
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Inline JWKS JSON document, used instead of `jwks_url`.
    #[serde(default)]
    pub jwks: Option<String>,
    /// Claim name → session tag key.
    #[serde(default)]
    pub claim_tags: std::collections::BTreeMap<String, String>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("root_access_key", &self.root_access_key)
            .field(
                "root_secret_key",
                &self.root_secret_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("allow_anonymous", &self.allow_anonymous)
            .field("oidc_providers", &self.oidc_providers)
            .finish()
    }
}

/// `[limits]` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Max single PUT size in bytes.
    pub max_object_size: u64,
    /// Max part size.
    pub max_part_size: u64,
    /// Min part size (all but last part).
    pub min_part_size: u64,
    /// Max parts per upload.
    pub max_parts: u32,
    /// Max user metadata bytes.
    pub max_metadata_size: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_object_size: 5 * 1024 * 1024 * 1024,
            max_part_size: 5 * 1024 * 1024 * 1024,
            min_part_size: 5 * 1024 * 1024,
            max_parts: 10_000,
            max_metadata_size: 2048,
        }
    }
}

/// `[events]` section (DESIGN §10).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EventsConfig {
    /// Run delivery workers for the configured sinks.
    pub enabled: bool,
    /// Serve the live SSE stream at `/_cairn/v1/events` (records every event in the outbox).
    pub sse: bool,
    /// Events buffered per SSE subscriber before it is told it lagged.
    pub sse_buffer: usize,
    /// Delivery attempts per batch before it is dead-lettered.
    pub max_attempts: u32,
    /// Sink definitions (`[[events.sinks]]`), passed verbatim to `cairn_events::SinkConfig`.
    pub sinks: Vec<toml::Table>,
}

impl Default for EventsConfig {
    fn default() -> Self {
        EventsConfig {
            enabled: true,
            sse: false,
            sse_buffer: 1024,
            max_attempts: 8,
            sinks: Vec::new(),
        }
    }
}

/// `[mcp]` section (phase 3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    /// Serve MCP over streamable HTTP at `/_cairn/mcp`.
    pub enabled: bool,
}

/// `[metrics]` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Serve `/metrics`.
    pub enabled: bool,
    /// How often storage gauges (blob count/bytes, trash bytes) are recomputed.
    #[serde(with = "duration_serde")]
    pub stats_interval: Duration,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        MetricsConfig {
            enabled: true,
            stats_interval: Duration::from_secs(300),
        }
    }
}

/// `[audit]` section: JSONL audit log of mutating and denied requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Write the audit log.
    pub enabled: bool,
    /// File path (default `<data_dir>/audit/audit.jsonl`).
    pub path: Option<PathBuf>,
    /// Rotate when the file reaches this many bytes.
    pub max_bytes: u64,
    /// Rotated files kept (`audit.jsonl.1` … `.N`).
    pub keep: u32,
    /// Also record successful reads (default: mutating and denied requests only).
    pub all_requests: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            enabled: true,
            path: None,
            max_bytes: 100 * 1024 * 1024,
            keep: 5,
            all_requests: false,
        }
    }
}

/// `[log]` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// `tracing` env-filter directive.
    pub level: String,
    /// Emit JSON lines.
    pub json: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            level: "info".into(),
            json: false,
        }
    }
}

impl Config {
    /// Parse TOML text.
    pub fn from_toml(s: &str) -> Result<Config, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Load from a file (if given and present) then apply the process environment.
    pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
        let base = match path {
            Some(p) if p.exists() => {
                let s = std::fs::read_to_string(p).map_err(|e| ConfigError::Io {
                    path: p.into(),
                    source: e,
                })?;
                Config::from_toml(&s)?
            }
            _ => Config::default(),
        };
        base.with_env(std::env::vars())
    }

    /// Apply `CAIRN_<SECTION>_<FIELD>=value` overrides (plus `CAIRN_ROOT_ACCESS_KEY`,
    /// `CAIRN_ROOT_SECRET`, `CAIRN_DATA_DIR` aliases). Unknown `CAIRN_*` names are ignored.
    pub fn with_env(
        self,
        vars: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Config, ConfigError> {
        let mut tree =
            toml::Value::try_from(&self).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let root = tree.as_table_mut().expect("config serialises to a table");
        for (var, val) in vars {
            let Some(rest) = var.strip_prefix("CAIRN_") else {
                continue;
            };
            let rest = rest.to_ascii_lowercase();
            let (section, field) = match rest.as_str() {
                "root_access_key" => ("auth".to_string(), "root_access_key".to_string()),
                "root_secret" | "root_secret_key" => {
                    ("auth".to_string(), "root_secret_key".to_string())
                }
                "data_dir" => ("storage".to_string(), "data_dir".to_string()),
                _ => match rest.split_once('_') {
                    Some((s, f)) => (s.to_string(), f.to_string()),
                    None => continue,
                },
            };
            let Some(sec) = root.get_mut(&section).and_then(|v| v.as_table_mut()) else {
                continue;
            };
            let typed = match sec.get(&field) {
                Some(toml::Value::Boolean(_)) => match val.to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => toml::Value::Boolean(true),
                    "0" | "false" | "no" | "off" => toml::Value::Boolean(false),
                    _ => {
                        return Err(ConfigError::Env {
                            var,
                            msg: "expected a boolean".into(),
                        });
                    }
                },
                Some(toml::Value::Integer(_)) => {
                    toml::Value::Integer(val.parse().map_err(|_| ConfigError::Env {
                        var: var.clone(),
                        msg: "expected an integer".into(),
                    })?)
                }
                Some(toml::Value::Array(_)) => toml::Value::Array(
                    val.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| toml::Value::String(s.to_string()))
                        .collect(),
                ),
                Some(_) => toml::Value::String(val),
                None if known_optional(&section, &field) => toml::Value::String(val),
                None => continue,
            };
            sec.insert(field, typed);
        }
        tree.try_into()
            .map_err(|e: toml::de::Error| ConfigError::Parse(e.to_string()))
    }

    /// Path of the metadata database.
    pub fn meta_path(&self) -> PathBuf {
        self.storage.data_dir.join("meta").join("cairn.redb")
    }

    /// Path of the master key file.
    pub fn master_key_path(&self) -> PathBuf {
        self.storage.data_dir.join("keys").join("master.key")
    }

    /// Semantic checks beyond parsing; returns every problem found.
    pub fn validate(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.server.listen.parse::<std::net::SocketAddr>().is_err() {
            out.push(format!(
                "server.listen {:?} is not an ip:port address",
                self.server.listen
            ));
        }
        if self.server.tls_cert.is_some() != self.server.tls_key.is_some() {
            out.push("server.tls_cert and server.tls_key must be set together".into());
        }
        for p in [&self.server.tls_cert, &self.server.tls_key]
            .into_iter()
            .flatten()
        {
            if !p.exists() {
                out.push(format!("TLS file {} does not exist", p.display()));
            }
        }
        match (&self.auth.root_access_key, &self.auth.root_secret_key) {
            (Some(a), Some(s)) => {
                if a.len() < 3 || a.len() > 128 {
                    out.push("auth.root_access_key must be 3..=128 characters".into());
                }
                if s.len() < 8 {
                    out.push("auth.root_secret_key must be at least 8 characters".into());
                }
            }
            (None, None) => {}
            _ => out.push(
                "auth.root_access_key and auth.root_secret_key must be set together (or CAIRN_ROOT_ACCESS_KEY / CAIRN_ROOT_SECRET)"
                    .into(),
            ),
        }
        for c in &self.server.trusted_proxies {
            if parse_cidr(c).is_none() {
                out.push(format!(
                    "server.trusted_proxies: {c:?} is not an IP or CIDR"
                ));
            }
        }
        for (i, p) in self.auth.oidc_providers.iter().enumerate() {
            if p.issuer.is_empty() || p.audiences.is_empty() {
                out.push(format!(
                    "auth.oidc_providers[{i}] needs an issuer and at least one audience"
                ));
            }
        }
        for (i, s) in self.events.sinks.iter().enumerate() {
            if !s.get("id").is_some_and(|v| v.is_str()) {
                out.push(format!("events.sinks[{i}] needs a string id"));
            }
        }
        if self.limits.min_part_size > self.limits.max_part_size {
            out.push("limits.min_part_size exceeds limits.max_part_size".into());
        }
        if self.limits.max_parts == 0 || self.limits.max_parts > 10_000 {
            out.push("limits.max_parts must be 1..=10000".into());
        }
        out
    }

    /// TOML rendering with secrets masked (for `cairn config check` and logs).
    pub fn to_redacted_toml(&self) -> String {
        let mut c = self.clone();
        if c.auth.root_secret_key.is_some() {
            c.auth.root_secret_key = Some("********".into());
        }
        toml::to_string_pretty(&c).unwrap_or_default()
    }
}

fn known_optional(section: &str, field: &str) -> bool {
    matches!(
        (section, field),
        ("server", "domain" | "tls_cert" | "tls_key")
            | ("auth", "root_access_key" | "root_secret_key")
            | ("audit", "path")
    )
}

/// Parse `1.2.3.4`, `1.2.3.0/24`, `::1` or `fd00::/8` into (network address, prefix length).
pub fn parse_cidr(s: &str) -> Option<(std::net::IpAddr, u8)> {
    let (ip, len) = match s.trim().split_once('/') {
        Some((ip, len)) => (ip, Some(len)),
        None => (s.trim(), None),
    };
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match len {
        Some(l) => l.parse::<u8>().ok().filter(|l| *l <= max)?,
        None => max,
    };
    Some((ip, len))
}

/// Whether `ip` is inside the CIDR `(net, len)` from [`parse_cidr`].
pub fn cidr_contains(net: (std::net::IpAddr, u8), ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match (net.0, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(net.1)).unwrap_or(0);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(net.1)).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// Parse durations like `30d`, `12h`, `15m`, `10s`, `500ms`, or a bare number of seconds.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let idx = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(idx);
    let n: u64 = num.parse().ok()?;
    let secs = |m: u64| Some(Duration::from_secs(n.checked_mul(m)?));
    match unit.trim() {
        "" | "s" => secs(1),
        "ms" => Some(Duration::from_millis(n)),
        "m" => secs(60),
        "h" => secs(3600),
        "d" => secs(86400),
        "w" => secs(7 * 86400),
        _ => None,
    }
}

/// Render a duration in the most compact unit `parse_duration` accepts.
pub fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    if d.subsec_nanos() != 0 {
        return format!("{}ms", d.as_millis());
    }
    for (m, u) in [(86400, "d"), (3600, "h"), (60, "m")] {
        if s != 0 && s.is_multiple_of(m) {
            return format!("{}{u}", s / m);
        }
    }
    format!("{s}s")
}

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::format_duration(*d))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Int(n) => Ok(Duration::from_secs(n)),
            Raw::Str(s) => super::parse_duration(&s)
                .ok_or_else(|| serde::de::Error::custom(format!("invalid duration {s:?}"))),
        }
    }
}

/// Every configuration key (`section.field`) with a one-line description; `cairn config schema`
/// renders it with defaults taken from `Config::default()` (a test keeps it complete).
pub const KEY_DOCS: &[(&str, &str)] = &[
    ("server.listen", r#"Listen address (`ip:port`)."#),
    (
        "server.domain",
        r#"Base domain for virtual-host-style buckets (`bucket.<domain>`); path style always works."#,
    ),
    (
        "server.region",
        r#"Region name reported to clients and stamped on events."#,
    ),
    (
        "server.tls_cert",
        r#"PEM certificate chain; enables HTTPS together with `tls_key`. Reloaded on SIGHUP."#,
    ),
    ("server.tls_key", r#"PEM private key."#),
    (
        "server.shutdown_grace",
        r#"How long in-flight requests may drain after SIGTERM."#,
    ),
    (
        "server.trusted_proxies",
        r#"CIDRs of reverse proxies whose `X-Forwarded-For` / `X-Forwarded-Proto` are trusted (comma-separated in env)."#,
    ),
    (
        "storage.data_dir",
        r#"Data directory root (`meta/`, `blobs/`, `tmp/`, `keys/`, `audit/`)."#,
    ),
    (
        "storage.fsync",
        r#"fsync blobs before rename (disable only for tests)."#,
    ),
    (
        "storage.verify_on_read",
        r#"Re-hash blobs while streaming GETs."#,
    ),
    (
        "storage.encrypt_at_rest",
        r#"Encrypt every blob with a key derived from `keys/master.key`."#,
    ),
    (
        "storage.min_free",
        r#"Bytes kept free under the data directory; writes that would eat into it get `507 InsufficientStorage`. `0` disables."#,
    ),
    (
        "storage.scrub",
        r#"Run the background scrubber (re-hash blobs, record damage)."#,
    ),
    (
        "storage.scrub_bytes_per_sec",
        r#"Scrubber read budget in bytes/s (0 = unthrottled)."#,
    ),
    ("storage.scrub_idle", r#"Pause between scrub passes."#),
    (
        "retention.soft_delete",
        r#"How long soft-deleted versions stay restorable (server default; per-bucket override via admin API)."#,
    ),
    (
        "retention.shadow_history",
        r#"How long superseded versions are kept for PITR."#,
    ),
    (
        "retention.min_versions_kept",
        r#"Minimum versions kept per key regardless of age."#,
    ),
    (
        "retention.gc_grace",
        r#"Delay between a blob's refcount reaching 0 and unlinking it."#,
    ),
    ("retention.gc_interval", r#"GC worker interval."#),
    (
        "retention.lifecycle_interval",
        r#"Lifecycle worker interval."#,
    ),
    (
        "auth.root_access_key",
        r#"Bootstrap/reset root access key id (`CAIRN_ROOT_ACCESS_KEY`). Optional after `cairn init`: the root credential lives in the credential store."#,
    ),
    (
        "auth.root_secret_key",
        r#"Bootstrap/reset root secret (`CAIRN_ROOT_SECRET`). Never printed by `cairn config check`."#,
    ),
    (
        "auth.allow_anonymous",
        r#"Reserved; anonymous access is granted only by bucket policies."#,
    ),
    (
        "auth.oidc_providers",
        r#"`[[auth.oidc_providers]]` entries: `issuer`, `audiences`, `jwks_url` or `jwks` (inline JSON string), `claim_tags`. Enables `AssumeRoleWithWebIdentity`."#,
    ),
    ("limits.max_object_size", r#"Largest single PUT in bytes."#),
    (
        "limits.max_part_size",
        r#"Largest multipart part in bytes."#,
    ),
    (
        "limits.min_part_size",
        r#"Smallest multipart part (all but the last)."#,
    ),
    ("limits.max_parts", r#"Most parts per upload (1..=10000)."#),
    (
        "limits.max_metadata_size",
        r#"Largest user metadata in bytes."#,
    ),
    (
        "events.enabled",
        r#"Run delivery workers for `[[events.sinks]]`."#,
    ),
    (
        "events.sse",
        r#"Serve the live SSE stream at `/_cairn/v1/events` (every event is recorded in the outbox)."#,
    ),
    (
        "events.sse_buffer",
        r#"Events buffered per SSE subscriber before it receives `event: lagged`."#,
    ),
    (
        "events.max_attempts",
        r#"Delivery attempts per batch before dead-lettering."#,
    ),
    (
        "events.sinks",
        r#"`[[events.sinks]]` entries: `id`, `url`, `arns`, `auth = { mode = "hmac"|"bearer"|"sigv4-lambda"|"cf-access"|"none", … }`, `batch_size`, `timeout_secs`. Destination ARN `arn:cairn:sink::<id>`."#,
    ),
    (
        "mcp.enabled",
        r#"Serve MCP over streamable HTTP at `/_cairn/mcp`."#,
    ),
    (
        "metrics.enabled",
        r#"Serve Prometheus metrics at `GET /metrics` (unauthenticated; restrict at the network layer)."#,
    ),
    (
        "metrics.stats_interval",
        r#"How often storage gauges (blob count/bytes, live/trash bytes) are recomputed."#,
    ),
    (
        "log.level",
        r#"`tracing` env-filter directive (`RUST_LOG` wins)."#,
    ),
    ("log.json", r#"Emit JSON log lines."#),
    (
        "audit.enabled",
        r#"Write the JSONL audit log (mutating and denied requests, STS calls)."#,
    ),
    (
        "audit.path",
        r#"Audit file (default `<data_dir>/audit/audit.jsonl`)."#,
    ),
    ("audit.max_bytes", r#"Rotate the audit file at this size."#),
    ("audit.keep", r#"Rotated audit files kept (`.1` … `.N`)."#),
    ("audit.all_requests", r#"Also record successful reads."#),
];

fn flatten(prefix: &str, v: &toml::Value, out: &mut Vec<(String, String)>) {
    match v {
        toml::Value::Table(t) => {
            for (k, v) in t {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                if prefix.is_empty() {
                    flatten(&key, v, out);
                } else {
                    out.push((key, v.to_string()));
                }
            }
        }
        other => out.push((prefix.to_string(), other.to_string())),
    }
}

/// `(key, default as TOML)` for every key present in `Config::default()`.
pub fn default_values() -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(v) = toml::Value::try_from(Config::default()) {
        flatten("", &v, &mut out);
    }
    out
}

/// Markdown reference of every key (the generated `docs/CONFIG.md`).
pub fn schema_markdown() -> String {
    let defaults = default_values();
    let mut s = String::from(
        "# Cairn configuration reference\n\n\
         Generated by `cairn config schema` from `cairn_core::config` — do not edit by hand.\n\n\
         Every key can be set in `cairn.toml` (section `[a]`, key `b` for `a.b`) or overridden with\n\
         the environment variable `CAIRN_<SECTION>_<KEY>` (upper case; arrays comma-separated).\n\
         Aliases: `CAIRN_ROOT_ACCESS_KEY`, `CAIRN_ROOT_SECRET`, `CAIRN_DATA_DIR`. Durations accept\n\
         `500ms`, `30s`, `15m`, `12h`, `30d`, `1w` or a number of seconds.\n",
    );
    let mut section = "";
    for (key, doc) in KEY_DOCS {
        let sec = key.split('.').next().unwrap_or("");
        if sec != section {
            section = sec;
            s.push_str(&format!(
                "\n## `[{sec}]`\n\n| Key | Default | Description |\n|-----|---------|-------------|\n"
            ));
        }
        let def = defaults
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| format!("`{}`", v.replace('|', "\\|")))
            .unwrap_or_else(|| "unset".into());
        let name = key.split_once('.').map_or(*key, |(_, f)| f);
        s.push_str(&format!(
            "| `{name}` | {def} | {} |\n",
            doc.replace('|', "\\|")
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_and_defaults() {
        let c = Config::from_toml(
            r#"
            [server]
            listen = "0.0.0.0:9000"
            domain = "s3.local"
            [retention]
            soft_delete = "7d"
            gc_grace = 60
            "#,
        )
        .unwrap();
        assert_eq!(c.server.listen, "0.0.0.0:9000");
        assert_eq!(c.server.domain.as_deref(), Some("s3.local"));
        assert_eq!(c.retention.soft_delete, Duration::from_secs(7 * 86400));
        assert_eq!(c.retention.gc_grace, Duration::from_secs(60));
        assert_eq!(c.limits.max_parts, 10_000);
        assert!(Config::from_toml("[server]\nbogus = 1").is_err());
        assert_eq!(c.server.shutdown_grace, Duration::from_secs(30));
        assert!(c.validate().is_empty(), "{:?}", c.validate());
        let mut half = c.clone();
        half.auth.root_access_key = Some("rootkey".into());
        assert!(!half.validate().is_empty());
        let mut ok = c.clone();
        ok.auth.root_access_key = Some("rootkey".into());
        ok.auth.root_secret_key = Some("s3cr3t-value".into());
        assert_eq!(ok.validate(), Vec::<String>::new());
        let shown = ok.to_redacted_toml();
        assert!(!shown.contains("s3cr3t-value"));
        assert_eq!(Config::from_toml(&shown).unwrap().server, ok.server);
    }

    #[test]
    fn env_overlay() {
        let vars = [
            ("CAIRN_SERVER_LISTEN", "0.0.0.0:1"),
            ("CAIRN_STORAGE_FSYNC", "false"),
            ("CAIRN_LIMITS_MAX_PARTS", "5"),
            ("CAIRN_RETENTION_SOFT_DELETE", "1h"),
            ("CAIRN_ROOT_ACCESS_KEY", "AK"),
            ("CAIRN_ROOT_SECRET", "SK"),
            ("CAIRN_SERVER_DOMAIN", "example.com"),
            ("CAIRN_DATA_DIR", "/srv/cairn"),
            ("CAIRN_NOPE_THING", "x"),
            ("HOME", "/root"),
        ]
        .map(|(a, b)| (a.to_string(), b.to_string()));
        let c = Config::default().with_env(vars).unwrap();
        assert_eq!(c.server.listen, "0.0.0.0:1");
        assert!(!c.storage.fsync);
        assert_eq!(c.limits.max_parts, 5);
        assert_eq!(c.retention.soft_delete, Duration::from_secs(3600));
        assert_eq!(c.auth.root_access_key.as_deref(), Some("AK"));
        assert_eq!(c.auth.root_secret_key.as_deref(), Some("SK"));
        assert_eq!(c.server.domain.as_deref(), Some("example.com"));
        assert_eq!(c.storage.data_dir, PathBuf::from("/srv/cairn"));
        let bad =
            Config::default().with_env([("CAIRN_STORAGE_FSYNC".to_string(), "maybe".to_string())]);
        assert!(bad.is_err());
    }

    #[test]
    fn every_key_is_documented() {
        let docs: Vec<&str> = KEY_DOCS.iter().map(|(k, _)| *k).collect();
        for (k, _) in default_values() {
            assert!(docs.contains(&k.as_str()), "{k} missing from KEY_DOCS");
        }
        let mut sorted = docs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), docs.len(), "duplicate KEY_DOCS entry");
        for k in &docs {
            let (sec, field) = k.split_once('.').unwrap();
            let probe = format!("[{sec}]\n{field} = 12345");
            if let Err(e) = Config::from_toml(&probe) {
                assert!(!e.to_string().contains("unknown field"), "{k}: {e}");
            }
        }
        assert!(schema_markdown().contains("| `listen` |"));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30d"), Some(Duration::from_secs(2_592_000)));
        assert_eq!(parse_duration("0s"), Some(Duration::ZERO));
        assert_eq!(parse_duration("15"), Some(Duration::from_secs(15)));
        assert_eq!(parse_duration("1y"), None);
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h");
        assert!(
            !format!(
                "{:?}",
                AuthConfig {
                    root_secret_key: Some("s3cr3t".into()),
                    ..Default::default()
                }
            )
            .contains("s3cr3t")
        );
    }
}
