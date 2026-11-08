//! Audit log: one JSON object per line for mutating and denied requests (DESIGN §8.3,
//! PRODUCTION-READINESS D3). Records never contain bodies, secrets, signatures or tokens.
//! A dedicated thread appends and rotates by size (`audit.jsonl` → `.1` … `.keep`).

use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};

/// One audit record.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// RFC 3339 time.
    pub time: String,
    /// Request id (`x-amz-request-id`).
    pub request_id: String,
    /// Interface: `s3`, `sts`, `admin`, `mcp`.
    pub api: &'static str,
    /// Principal id when resolved.
    pub principal: Option<String>,
    /// Access key id that signed the request (not secret).
    pub access_key: Option<String>,
    /// Operation, e.g. `PutObject` or `POST /_cairn/v1/users`.
    pub action: String,
    /// Bucket/key ARN or admin path.
    pub resource: String,
    /// HTTP status.
    pub status: u16,
    /// Client address.
    pub source_ip: Option<String>,
    /// Time to response head in milliseconds.
    pub latency_ms: u64,
}

/// Handle to the writer thread (cheap to clone).
#[derive(Clone)]
pub struct AuditLog {
    tx: SyncSender<AuditRecord>,
    path: PathBuf,
}

struct Writer {
    path: PathBuf,
    file: File,
    size: u64,
    max: u64,
    keep: u32,
}

impl Writer {
    fn open(path: &Path) -> std::io::Result<(File, u64)> {
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            o.mode(0o600);
        }
        let f = o.open(path)?;
        let size = f.metadata()?.len();
        Ok((f, size))
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let _ = self.file.sync_all();
        let name = |i: u32| PathBuf::from(format!("{}.{i}", self.path.display()));
        if self.keep == 0 {
            std::fs::remove_file(&self.path)?;
        } else {
            let _ = std::fs::remove_file(name(self.keep));
            for i in (1..self.keep).rev() {
                let _ = std::fs::rename(name(i), name(i + 1));
            }
            std::fs::rename(&self.path, name(1))?;
        }
        let (f, size) = Writer::open(&self.path)?;
        self.file = f;
        self.size = size;
        Ok(())
    }

    fn write(&mut self, r: &AuditRecord) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(r).map_err(std::io::Error::other)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.size += line.len() as u64;
        if self.size >= self.max {
            self.rotate()?;
        }
        Ok(())
    }
}

impl AuditLog {
    /// Start the writer thread appending to `path`.
    pub fn start(path: &Path, max_bytes: u64, keep: u32) -> std::io::Result<AuditLog> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let (file, size) = Writer::open(path)?;
        let mut w = Writer {
            path: path.to_path_buf(),
            file,
            size,
            max: max_bytes.max(4096),
            keep,
        };
        let (tx, rx) = sync_channel::<AuditRecord>(8192);
        std::thread::Builder::new()
            .name("cairn-audit".into())
            .spawn(move || {
                while let Ok(r) = rx.recv() {
                    if let Err(e) = w.write(&r) {
                        tracing::error!(error = %e, "audit log write failed");
                    }
                }
                let _ = w.file.sync_all();
            })?;
        Ok(AuditLog {
            tx,
            path: path.to_path_buf(),
        })
    }

    /// Queue a record; returns `false` if it had to be dropped.
    pub fn record(&self, r: AuditRecord) -> bool {
        match self.tx.try_send(r) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// The active log file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(i: usize) -> AuditRecord {
        AuditRecord {
            time: "t".into(),
            request_id: format!("{i:016X}"),
            api: "s3",
            principal: Some("root".into()),
            access_key: None,
            action: "PutObject".into(),
            resource: "arn:aws:s3:::b/k".into(),
            status: 200,
            source_ip: None,
            latency_ms: 1,
        }
    }

    #[test]
    fn rotates_by_size_and_keeps_n_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("audit").join("audit.jsonl");
        let log = AuditLog::start(&p, 4096, 2).unwrap();
        for i in 0..200 {
            assert!(log.record(rec(i)));
        }
        drop(log);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(p.exists());
        assert!(PathBuf::from(format!("{}.1", p.display())).exists());
        assert!(PathBuf::from(format!("{}.2", p.display())).exists());
        assert!(!PathBuf::from(format!("{}.3", p.display())).exists());
        let text = std::fs::read_to_string(&p).unwrap();
        for l in text.lines() {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["action"], "PutObject");
        }
    }
}
