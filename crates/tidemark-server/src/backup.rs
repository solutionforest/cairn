//! Backups made by the running server (`POST /_tidemark/v1/backup`). The CLI's `tidemark backup`
//! needs the metadata database to itself, so a live server can only be backed up from inside.
//! One job at a time, in the background; the most recent job is kept for `GET /backup`.

use crate::metrics::Metrics;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tidemark_admin::AdminError;
use tidemark_admin::engine::{BackupJob, BackupRequest};
use tidemark_core::Ts;
use tidemark_core::config::BackupConfig;
use tidemark_engine::TidemarkEngine;
use tidemark_engine::backup::{self, BackupLocation, BackupMode, BackupOptions};

/// Runs server-side backups into `backup.dir`.
pub struct BackupRunner {
    engine: TidemarkEngine,
    dir: PathBuf,
    passphrase_file: Option<PathBuf>,
    include_keys: bool,
    metrics: Arc<Metrics>,
    job: Arc<Mutex<Option<BackupJob>>>,
}

impl BackupRunner {
    /// `None` when `backup.dir` is unset.
    pub fn new(
        engine: TidemarkEngine,
        cfg: &BackupConfig,
        metrics: Arc<Metrics>,
    ) -> Option<Arc<BackupRunner>> {
        let dir = cfg.dir.clone()?;
        Some(Arc::new(BackupRunner {
            engine,
            dir,
            passphrase_file: cfg.passphrase_file.clone(),
            include_keys: cfg.include_keys,
            metrics,
            job: Arc::new(Mutex::new(None)),
        }))
    }

    /// Set the last-success gauge from the newest manifest already in `backup.dir`, so a restart
    /// does not look like a missed backup.
    pub async fn load_last_success(&self) {
        if let Some(t) = newest_backup(&self.dir).await {
            self.metrics.backup_last_success.set(t);
        }
    }

    fn job(&self) -> std::sync::MutexGuard<'_, Option<BackupJob>> {
        self.job.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The running or most recent job.
    pub fn status(&self) -> Option<BackupJob> {
        self.job().clone()
    }

    /// Start a backup into `<dir>/<set>` unless one is running.
    pub fn start(self: &Arc<Self>, r: BackupRequest) -> Result<BackupJob, AdminError> {
        r.validate()?;
        let passphrase = match &self.passphrase_file {
            None => None,
            Some(p) => Some(read_passphrase(p).map_err(|e| {
                AdminError::internal(format!("reading backup.passphrase_file: {e}"))
            })?),
        };
        let job = {
            let mut cur = self.job();
            if cur.as_ref().is_some_and(|j| j.state == "running") {
                return Err(AdminError::conflict(format!(
                    "a backup into set {:?} is already running",
                    cur.as_ref().map(|j| j.set.as_str()).unwrap_or_default()
                )));
            }
            let job = BackupJob {
                set: r.set.clone(),
                state: "running".into(),
                started_at: Ts::now().to_rfc3339(),
                ..Default::default()
            };
            *cur = Some(job.clone());
            job
        };
        let opts = BackupOptions {
            mode: if r.full {
                BackupMode::Full
            } else {
                BackupMode::Incremental
            },
            include_keys: self.include_keys && passphrase.is_some(),
            passphrase,
            ..Default::default()
        };
        let me = self.clone();
        let dest = BackupLocation::Dir(self.dir.join(&r.set));
        tokio::spawn(async move {
            tracing::info!(set = %r.set, full = r.full, "backup started");
            let res = backup::backup(&me.engine, &dest, &opts).await;
            let mut cur = me.job();
            let Some(job) = cur.as_mut() else { return };
            job.finished_at = Some(Ts::now().to_rfc3339());
            match res {
                Ok(rep) => {
                    tracing::info!(set = %r.set, id = %rep.id, uploaded = rep.blobs_uploaded, "backup finished");
                    job.state = "succeeded".into();
                    job.report = serde_json::to_value(&rep).ok();
                    me.metrics.backup_last_success.set(Ts::now().secs());
                    me.metrics
                        .backup_runs
                        .with_label_values(&["succeeded"])
                        .inc();
                }
                Err(e) => {
                    tracing::error!(set = %r.set, error = %e, "backup failed");
                    job.state = "failed".into();
                    job.error = Some(e.to_string());
                    me.metrics.backup_runs.with_label_values(&["failed"]).inc();
                }
            }
        });
        Ok(job)
    }
}

fn read_passphrase(p: &Path) -> std::io::Result<zeroize::Zeroizing<String>> {
    let s = zeroize::Zeroizing::new(std::fs::read_to_string(p)?);
    Ok(zeroize::Zeroizing::new(
        s.trim_end_matches(['\r', '\n']).to_string(),
    ))
}

/// Unix time of the newest manifest in any set under `dir` (manifest ids start with
/// `YYYYmmddTHHMMSS`, UTC).
async fn newest_backup(dir: &Path) -> Option<i64> {
    let mut newest: Option<String> = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        if let Ok(ids) = backup::list_backups(&BackupLocation::Dir(e.path())).await
            && let Some(last) = ids.into_iter().next_back()
            && newest.as_ref().is_none_or(|n| &last > n)
        {
            newest = Some(last);
        }
    }
    let id = newest?;
    let dt = jiff::civil::DateTime::strptime("%Y%m%dT%H%M%S", id.get(..15)?).ok()?;
    Some(
        dt.to_zoned(jiff::tz::TimeZone::UTC)
            .ok()?
            .timestamp()
            .as_second(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn newest_backup_reads_manifest_ids() {
        let d = tempfile::tempdir().unwrap();
        for (set, id) in [
            ("2026-W45", "20261103T010000.000000Z-ab12"),
            ("2026-W46", "20261110T120000.000000Z-cd34"),
            ("2026-W46", "20261110T080000.000000Z-ef56"),
        ] {
            let m = d.path().join(set).join("manifests");
            std::fs::create_dir_all(&m).unwrap();
            std::fs::write(m.join(format!("{id}.json")), "{}").unwrap();
        }
        std::fs::write(d.path().join("stray-file"), "").unwrap();
        assert_eq!(newest_backup(d.path()).await, Some(1_794_312_000));
        assert_eq!(newest_backup(&d.path().join("missing")).await, None);
    }
}
