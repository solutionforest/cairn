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
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            data_dir: PathBuf::from("./data"),
            fsync: true,
            verify_on_read: false,
            encrypt_at_rest: false,
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
}

impl Default for RetentionConfig {
    fn default() -> Self {
        RetentionConfig {
            soft_delete: Duration::from_secs(30 * 86400),
            shadow_history: Duration::from_secs(30 * 86400),
            min_versions_kept: 1,
            gc_grace: Duration::from_secs(3600),
            gc_interval: Duration::from_secs(60),
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

/// `[events]` section (phase 3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct EventsConfig {
    /// Enable the durable outbox.
    pub enabled: bool,
}

/// `[mcp]` section (phase 3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    /// Serve MCP at `/mcp`.
    pub enabled: bool,
}

/// `[metrics]` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Serve `/metrics`.
    pub enabled: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        MetricsConfig { enabled: true }
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
            _ => out.push(
                "auth.root_access_key and auth.root_secret_key are required (or CAIRN_ROOT_ACCESS_KEY / CAIRN_ROOT_SECRET)"
                    .into(),
            ),
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
    )
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
        assert!(!c.validate().is_empty());
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
