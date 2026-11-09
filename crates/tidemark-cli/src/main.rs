#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! `tidemark` binary: `init`, `serve`, `config check|schema`, `migrate`, `admin`, `mcp --stdio`,
//! `fsck`, `scrub`, `backup`, `restore`, `trash`, `pitr`.

use anyhow::Context as _;
use clap::{CommandFactory as _, FromArgMatches as _, Parser, Subcommand, ValueEnum};
use rand::Rng as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tidemark_core::Config;
use tidemark_server::tidemark_engine::{TidemarkEngine, backup, fsck, scrub};

mod recover;

#[derive(Parser)]
#[command(
    name = "tidemark",
    version,
    about = "Tidemark: an S3-compatible object store"
)]
struct Cli {
    /// Log output format.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

/// Where an offline command finds the data directory.
#[derive(clap::Args, Clone)]
struct Target {
    /// Path to `tidemark.toml`.
    #[arg(long, short, env = "TIDEMARK_CONFIG")]
    config: Option<PathBuf>,
    /// Data directory (overrides the config).
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a data directory, a `tidemark.toml` and the root credential (printed once).
    Init {
        /// Data directory to create.
        #[arg(long)]
        data_dir: PathBuf,
        /// Listen address written to the config.
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: String,
    },
    /// Run the server.
    Serve {
        /// Path to `tidemark.toml` (`TIDEMARK_*` environment variables override it).
        #[arg(long, short, env = "TIDEMARK_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Configuration utilities.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Run (or with `--dry-run`, only report) metadata schema migrations. The server must be
    /// stopped; `tidemark serve` also migrates on start.
    Migrate {
        #[command(flatten)]
        target: Target,
        /// Report what would change without writing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Serve MCP over stdin/stdout (credentials from `TIDEMARK_ACCESS_KEY_ID` /
    /// `TIDEMARK_SECRET_ACCESS_KEY` / `TIDEMARK_SESSION_TOKEN`). The server must not be running on the
    /// same data directory.
    Mcp {
        /// Use the stdio transport (the only one this subcommand offers).
        #[arg(long)]
        stdio: bool,
        #[command(flatten)]
        target: Target,
    },
    /// Check metadata ↔ blob consistency (server stopped). Exit 0 clean, 1 findings, 2 error.
    Fsck {
        #[command(flatten)]
        target: Target,
        /// Re-hash blobs: `none`, `sample:<n>` or `full`.
        #[arg(long, default_value = "none")]
        verify: String,
        /// Fix what is safe to fix.
        #[arg(long)]
        repair: bool,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify blob hashes (server stopped; the server runs it in the background with
    /// `storage.scrub = true`).
    Scrub {
        #[command(flatten)]
        target: Target,
        /// Read budget in bytes per second (0 = unthrottled).
        #[arg(long, default_value_t = 50 * 1024 * 1024)]
        rate: u64,
        /// Blobs verified concurrently.
        #[arg(long, default_value_t = 2)]
        concurrency: usize,
        /// One pass, then exit (default: one pass).
        #[arg(long)]
        once: bool,
    },
    /// Back up metadata and blobs to a directory or `s3://bucket/prefix`.
    Backup {
        #[command(subcommand)]
        sub: Option<BackupCmd>,
        #[command(flatten)]
        target: Target,
        /// Destination directory or `s3://bucket/prefix`.
        #[arg(long)]
        to: Option<String>,
        #[command(flatten)]
        remote: Remote,
        /// File holding the encryption passphrase.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Also save `keys/` (requires a passphrase).
        #[arg(long)]
        include_keys: bool,
        /// Upload every blob instead of only new ones.
        #[arg(long)]
        full: bool,
    },
    /// Undelete objects and buckets (soft-deleted or superseded versions).
    Trash {
        #[command(subcommand)]
        cmd: recover::TrashCmd,
    },
    /// Point-in-time recovery: restore or diff a bucket against any instant in its window.
    Pitr {
        #[command(subcommand)]
        cmd: recover::PitrCmd,
    },
    /// Restore a backup into an empty data directory.
    Restore {
        /// Backup set directory or `s3://bucket/prefix`.
        #[arg(long)]
        from: String,
        /// Data directory to create.
        #[arg(long)]
        data_dir: PathBuf,
        /// Manifest id (default: newest).
        #[arg(long)]
        id: Option<String>,
        #[command(flatten)]
        remote: Remote,
        /// File holding the encryption passphrase.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    /// List manifest ids in a backup set, oldest first.
    Ls {
        /// Backup set directory or `s3://bucket/prefix`.
        #[arg(long)]
        from: String,
        #[command(flatten)]
        remote: Remote,
    },
}

/// Remote S3 endpoint for `s3://` backup sets (credentials from `AWS_ACCESS_KEY_ID` /
/// `AWS_SECRET_ACCESS_KEY`).
#[derive(clap::Args, Clone)]
struct Remote {
    /// S3 endpoint URL (default: AWS).
    #[arg(long)]
    endpoint: Option<String>,
    /// Signing region.
    #[arg(long, default_value = "us-east-1")]
    region: String,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Validate a config file and print the effective configuration with secrets masked.
    Check {
        /// Path to `tidemark.toml`.
        #[arg(long, short, env = "TIDEMARK_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Print the configuration reference (Markdown; the source of `docs/CONFIG.md`).
    Schema,
}

fn init_tracing(format: LogFormat, level: &str, stderr: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let b = tracing_subscriber::fmt().with_env_filter(filter);
    match (format, stderr) {
        (LogFormat::Json, false) => b.json().init(),
        (LogFormat::Text, false) => b.init(),
        (LogFormat::Json, true) => b.json().with_writer(std::io::stderr).init(),
        (LogFormat::Text, true) => b.with_writer(std::io::stderr).init(),
    }
}

fn random_string(len: usize, alphabet: &[u8]) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| alphabet[rng.random_range(0..alphabet.len())] as char)
        .collect()
}

/// Root credentials in the shapes DESIGN §8.1 describes (`TDMK…` 20-char key id).
fn generate_root_credentials() -> (String, String) {
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const SECRET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    (
        format!("TDMK{}", random_string(16, UPPER)),
        random_string(40, SECRET),
    )
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("tidemark")
        .build()?)
}

/// Install the root credential into the credential store of `cfg`'s data directory.
async fn bootstrap_root(cfg: &Config, ak: &str, sk: &str) -> anyhow::Result<()> {
    tidemark_server::run_migrations(cfg).await?;
    let meta =
        tidemark_server::tidemark_engine::tidemark_meta::RedbMetaStore::open(&cfg.meta_path())?;
    let store = tidemark_auth::CredentialStore::new(
        Arc::new(tidemark_auth::MetaCredentialBackend::new(meta.clone())),
        tidemark_server::iam_master_key(cfg)?,
    );
    let r = store
        .ensure_root(ak, &tidemark_auth::SecretString::new(sk))
        .await;
    meta.shutdown();
    r.context("storing the root credential")
}

/// `tidemark init`: returns the config path and the generated root credential (if generated).
fn init(data_dir: &Path, listen: &str) -> anyhow::Result<(PathBuf, Option<(String, String)>)> {
    let cfg_path = data_dir.join("tidemark.toml");
    anyhow::ensure!(
        !cfg_path.exists(),
        "{} already exists; refusing to overwrite it",
        cfg_path.display()
    );
    for d in ["meta", "blobs", "tmp", "keys"] {
        std::fs::create_dir_all(data_dir.join(d))
            .with_context(|| format!("creating {}", data_dir.join(d).display()))?;
    }
    let data_dir = data_dir
        .canonicalize()
        .with_context(|| format!("resolving {}", data_dir.display()))?;
    let env_ak = std::env::var("TIDEMARK_ROOT_ACCESS_KEY").ok();
    let env_sk = std::env::var("TIDEMARK_ROOT_SECRET").ok();
    let (ak, sk, generated) = match (env_ak, env_sk) {
        (Some(a), Some(s)) => (a, s, false),
        _ => {
            let (a, s) = generate_root_credentials();
            (a, s, true)
        }
    };
    let mut cfg = Config::default();
    cfg.server.listen = listen.to_string();
    cfg.storage.data_dir = data_dir.clone();
    let problems = cfg.validate();
    anyhow::ensure!(
        problems.is_empty(),
        "invalid settings: {}",
        problems.join("; ")
    );
    tidemark_server::load_or_create_master_key(&cfg.master_key_path())?;
    runtime()?.block_on(bootstrap_root(&cfg, &ak, &sk))?;
    let text = format!(
        "# Tidemark configuration generated by `tidemark init`. The root credential lives in the\n# credential store (meta/), sealed with keys/master.key; it is not in this file.\n# Every key can be overridden with TIDEMARK_<SECTION>_<FIELD>; see docs/CONFIG.md.\n\n{}",
        toml::to_string_pretty(&cfg)?
    );
    tidemark_server::write_private(&cfg_path, text.as_bytes())
        .with_context(|| format!("writing {}", cfg_path.display()))?;
    Ok((cfg_path, generated.then_some((ak, sk))))
}

fn load(path: Option<&Path>) -> anyhow::Result<Config> {
    if let Some(p) = path {
        anyhow::ensure!(p.exists(), "config file {} not found", p.display());
    }
    Config::load(path).context("loading configuration")
}

fn load_target(t: &Target) -> anyhow::Result<Config> {
    let mut cfg = load(t.config.as_deref())?;
    if let Some(d) = &t.data_dir {
        cfg.storage.data_dir = d.clone();
    }
    anyhow::ensure!(
        cfg.meta_path().exists(),
        "no Tidemark data directory at {} (missing meta/tidemark.redb)",
        cfg.storage.data_dir.display()
    );
    Ok(cfg)
}

async fn open_offline(cfg: &Config) -> anyhow::Result<TidemarkEngine> {
    tidemark_server::open_engine(cfg, Default::default()).await
}

fn location(s: &str, r: &Remote) -> anyhow::Result<backup::BackupLocation> {
    match s.strip_prefix("s3://") {
        Some(rest) => {
            let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
            anyhow::ensure!(!bucket.is_empty(), "s3:// location needs a bucket");
            Ok(backup::BackupLocation::S3(
                tidemark_blob::remote_s3::S3Endpoint {
                    endpoint: r.endpoint.clone(),
                    region: r.region.clone(),
                    bucket: bucket.to_string(),
                    prefix: prefix.to_string(),
                    access_key: std::env::var("AWS_ACCESS_KEY_ID")
                        .context("AWS_ACCESS_KEY_ID is required for s3:// locations")?,
                    secret_key: std::env::var("AWS_SECRET_ACCESS_KEY")
                        .context("AWS_SECRET_ACCESS_KEY is required for s3:// locations")?,
                    path_style: r.endpoint.is_some(),
                },
            ))
        }
        None => Ok(backup::BackupLocation::Dir(PathBuf::from(s))),
    }
}

fn passphrase(p: Option<&Path>) -> anyhow::Result<Option<zeroize::Zeroizing<String>>> {
    p.map(|p| {
        let s = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        Ok(zeroize::Zeroizing::new(
            s.trim_end_matches(['\r', '\n']).to_string(),
        ))
    })
    .transpose()
}

fn verify_mode(s: &str) -> anyhow::Result<fsck::VerifyMode> {
    Ok(match s {
        "none" => fsck::VerifyMode::None,
        "full" => fsck::VerifyMode::Full,
        other => match other.strip_prefix("sample:").and_then(|n| n.parse().ok()) {
            Some(n) => fsck::VerifyMode::Sample(n),
            None => anyhow::bail!("--verify must be none, sample:<n> or full"),
        },
    })
}

fn json<T: serde::Serialize>(v: &T) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(v)?)
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    match cli.cmd {
        Cmd::Init { data_dir, listen } => {
            let (p, creds) = init(&data_dir, &listen)?;
            println!("Initialised {}", data_dir.display());
            println!("Config:     {}", p.display());
            match creds {
                Some((ak, sk)) => {
                    println!();
                    println!("Root credentials (shown once; stored only as a sealed secret):");
                    println!("  access key: {ak}");
                    println!("  secret key: {sk}");
                }
                None => println!(
                    "Root credential taken from TIDEMARK_ROOT_ACCESS_KEY / TIDEMARK_ROOT_SECRET."
                ),
            }
            println!();
            println!(
                "Start the server with: tidemark serve --config {}",
                p.display()
            );
            Ok(0)
        }
        Cmd::Config {
            cmd: ConfigCmd::Schema,
        } => {
            print!("{}", tidemark_core::config::schema_markdown());
            Ok(0)
        }
        Cmd::Config {
            cmd: ConfigCmd::Check { config },
        } => {
            let cfg = load(config.as_deref())?;
            print!("{}", cfg.to_redacted_toml());
            let problems = cfg.validate();
            if problems.is_empty() {
                eprintln!("configuration OK");
                Ok(0)
            } else {
                for p in &problems {
                    eprintln!("error: {p}");
                }
                anyhow::bail!("{} configuration problem(s)", problems.len())
            }
        }
        Cmd::Serve { config } => {
            let cfg = load(config.as_deref())?;
            let format = if cfg.log.json {
                LogFormat::Json
            } else {
                cli.log_format
            };
            init_tracing(format, &cfg.log.level, false);
            runtime()?.block_on(async move {
                let server = tidemark_server::Server::bind(cfg).await?;
                server.run().await
            })?;
            Ok(0)
        }
        Cmd::Migrate { target, dry_run } => {
            let mut cfg = load(target.config.as_deref())?;
            if let Some(d) = &target.data_dir {
                cfg.storage.data_dir = d.clone();
            }
            let rep = runtime()?.block_on(
                tidemark_server::tidemark_engine::tidemark_meta::migrate::migrate(
                    &cfg.meta_path(),
                    dry_run,
                ),
            )?;
            let from = rep
                .from
                .map_or_else(|| "none (new database)".to_string(), |v| v.to_string());
            println!("schema version: {from} -> {}", rep.to);
            if rep.steps.is_empty() {
                println!("no migrations needed");
            }
            for s in &rep.steps {
                println!("{} {s}", if dry_run { "would apply" } else { "applied" });
            }
            if let Some(b) = &rep.backup {
                println!("pre-upgrade snapshot: {}", b.display());
            }
            if dry_run {
                println!("dry run: nothing was written");
            }
            Ok(0)
        }
        Cmd::Mcp { stdio, target } => {
            anyhow::ensure!(
                stdio,
                "only `tidemark mcp --stdio` is supported here; HTTP MCP is served by `tidemark serve` when [mcp] enabled"
            );
            let cfg = load_target(&target)?;
            init_tracing(cli.log_format, &cfg.log.level, true);
            runtime()?.block_on(async move {
                let engine = open_offline(&cfg).await?;
                let store = tidemark_server::credential_store(&cfg, &engine).await?;
                let policies =
                    Arc::new(tidemark_auth::BucketPolicyStore::new(engine.meta().clone()));
                let r = tidemark_mcp::serve_stdio(tidemark_mcp::McpState::new(
                    engine.clone(),
                    store,
                    policies,
                ))
                .await;
                engine.shutdown();
                r.map_err(anyhow::Error::from)
            })?;
            Ok(0)
        }
        Cmd::Fsck {
            target,
            verify,
            repair,
            json: as_json,
        } => {
            let cfg = load_target(&target)?;
            init_tracing(cli.log_format, "warn", true);
            let opts = fsck::FsckOptions {
                verify: verify_mode(&verify)?,
                repair,
                ..Default::default()
            };
            let rep = runtime()?.block_on(async move {
                let e = open_offline(&cfg).await?;
                let r = e.fsck(opts).await;
                e.shutdown();
                Ok::<_, anyhow::Error>(r?)
            })?;
            if as_json {
                println!("{}", json(&rep)?);
            } else {
                println!("{}", json(&rep)?);
                println!(
                    "{}",
                    if rep.is_clean() {
                        "clean"
                    } else {
                        "findings reported"
                    }
                );
            }
            Ok(if rep.is_clean() { 0 } else { 1 })
        }
        Cmd::Scrub {
            target,
            rate,
            concurrency,
            once: _,
        } => {
            let cfg = load_target(&target)?;
            init_tracing(cli.log_format, "warn", true);
            let sc = scrub::ScrubConfig {
                bytes_per_sec: rate,
                max_concurrent: concurrency.max(1),
                ..Default::default()
            };
            let rep = runtime()?.block_on(async move {
                let e = open_offline(&cfg).await?;
                let r = scrub::Scrubber::new(e.clone(), sc).run_pass().await;
                e.shutdown();
                Ok::<_, anyhow::Error>(r?)
            })?;
            println!("{}", json(&rep)?);
            Ok(if rep.corrupt.is_empty() && rep.missing.is_empty() {
                0
            } else {
                1
            })
        }
        Cmd::Backup {
            sub: Some(BackupCmd::Ls { from, remote }),
            ..
        } => {
            let loc = location(&from, &remote)?;
            for id in runtime()?.block_on(backup::list_backups(&loc))? {
                println!("{id}");
            }
            Ok(0)
        }
        Cmd::Backup {
            sub: None,
            target,
            to,
            remote,
            passphrase_file,
            include_keys,
            full,
        } => {
            let to = to.context("--to is required")?;
            let cfg = load_target(&target)?;
            init_tracing(cli.log_format, "warn", true);
            let loc = location(&to, &remote)?;
            let opts = backup::BackupOptions {
                mode: if full {
                    backup::BackupMode::Full
                } else {
                    backup::BackupMode::Incremental
                },
                passphrase: passphrase(passphrase_file.as_deref())?,
                include_keys,
                ..Default::default()
            };
            let rep = runtime()?.block_on(async move {
                let e = open_offline(&cfg).await?;
                let r = backup::backup(&e, &loc, &opts).await;
                e.shutdown();
                Ok::<_, anyhow::Error>(r?)
            })?;
            println!("{}", json(&rep)?);
            Ok(0)
        }
        Cmd::Trash { cmd } => {
            init_tracing(cli.log_format, "warn", true);
            runtime()?.block_on(recover::trash(cmd))
        }
        Cmd::Pitr { cmd } => {
            init_tracing(cli.log_format, "warn", true);
            runtime()?.block_on(recover::pitr(cmd))
        }
        Cmd::Restore {
            from,
            data_dir,
            id,
            remote,
            passphrase_file,
        } => {
            init_tracing(cli.log_format, "warn", true);
            let loc = location(&from, &remote)?;
            let opts = backup::RestoreOptions {
                manifest: id,
                passphrase: passphrase(passphrase_file.as_deref())?,
            };
            let rep = runtime()?.block_on(backup::restore(&loc, &data_dir, &opts))?;
            println!("{}", json(&rep)?);
            Ok(0)
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cmd = Cli::command().subcommand(tidemark_admin::cli::cli().name("admin"));
    let m = cmd.get_matches();
    if let Some(("admin", am)) = m.subcommand() {
        let client = tidemark_admin::cli::client_from_matches(am)?;
        return runtime()?.block_on(tidemark_admin::cli::run(am, &client));
    }
    let cli = Cli::from_arg_matches(&m)
        .map_err(|e| e.exit())
        .unwrap_or_else(|never| never);
    let code = run(cli)?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_valid_private_config_without_secret() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let (p, creds) = init(&data, "127.0.0.1:0").unwrap();
        let (ak, sk) = creds.expect("generated credentials");
        assert!(ak.starts_with("TDMK"));
        assert_eq!(sk.len(), 40);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            !text.contains(&sk),
            "secret must not be written to tidemark.toml"
        );
        let cfg = Config::load(Some(&p)).unwrap();
        assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
        assert!(cfg.auth.root_secret_key.is_none());
        for sub in ["meta/tidemark.redb", "blobs", "tmp", "keys/master.key"] {
            assert!(data.join(sub).exists(), "{sub}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "config must not be group/world readable");
        }
        assert!(
            init(&data, "127.0.0.1:0").is_err(),
            "init must not overwrite"
        );
    }
}
