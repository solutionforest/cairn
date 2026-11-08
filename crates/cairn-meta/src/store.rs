//! redb-backed store, transactions and the group-commit writer thread.

use crate::{MetaError, Table};
use redb::{ReadableDatabase, ReadableTable};
use std::ops::Bound;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};

/// Scan callback control.
pub enum Flow {
    /// Keep iterating.
    Continue,
    /// Stop the scan.
    Stop,
    /// Restart the scan at this key (inclusive); used to skip subtrees.
    Seek(Vec<u8>),
}

/// Scan callback type.
pub type ScanFn<'a> = dyn FnMut(&[u8], &[u8]) -> Result<Flow, MetaError> + 'a;

/// Read access shared by read and write transactions.
pub trait Reader {
    /// Point lookup.
    fn get(&self, t: Table, key: &[u8]) -> Result<Option<Vec<u8>>, MetaError>;

    /// Ordered scan over `[start, end)`-style bounds, calling `f` for each entry.
    fn scan(
        &self,
        t: Table,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        f: &mut ScanFn<'_>,
    ) -> Result<(), MetaError>;

    /// Scan every key with `prefix`.
    fn scan_prefix(&self, t: Table, prefix: &[u8], f: &mut ScanFn<'_>) -> Result<(), MetaError> {
        let end = crate::keys::prefix_successor(prefix);
        let end_b = end.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
        self.scan(t, Bound::Included(prefix), end_b, f)
    }
}

fn run_scan<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    start: Bound<&[u8]>,
    end: Bound<&[u8]>,
    f: &mut ScanFn<'_>,
) -> Result<(), MetaError> {
    let mut start_owned: Bound<Vec<u8>> = match start {
        Bound::Included(s) => Bound::Included(s.to_vec()),
        Bound::Excluded(s) => Bound::Excluded(s.to_vec()),
        Bound::Unbounded => Bound::Unbounded,
    };
    'outer: loop {
        let s = match &start_owned {
            Bound::Included(v) => Bound::Included(v.as_slice()),
            Bound::Excluded(v) => Bound::Excluded(v.as_slice()),
            Bound::Unbounded => Bound::Unbounded,
        };
        if let (Bound::Included(a) | Bound::Excluded(a), Bound::Included(b) | Bound::Excluded(b)) =
            (s, end)
            && a > b
        {
            return Ok(());
        }
        let range = table.range::<&[u8]>((s, end))?;
        for item in range {
            let (k, v) = item?;
            match f(k.value(), v.value())? {
                Flow::Continue => {}
                Flow::Stop => return Ok(()),
                Flow::Seek(next) => {
                    start_owned = Bound::Included(next);
                    continue 'outer;
                }
            }
        }
        return Ok(());
    }
}

/// A read-only snapshot.
pub struct ReadTxn {
    inner: redb::ReadTransaction,
}

impl Reader for ReadTxn {
    fn get(&self, t: Table, key: &[u8]) -> Result<Option<Vec<u8>>, MetaError> {
        let table = self.inner.open_table(t.def())?;
        Ok(table.get(key)?.map(|g| g.value().to_vec()))
    }

    fn scan(
        &self,
        t: Table,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        f: &mut ScanFn<'_>,
    ) -> Result<(), MetaError> {
        let table = self.inner.open_table(t.def())?;
        run_scan(&table, start, end, f)
    }
}

/// A write transaction handed to write jobs on the writer thread.
pub struct WriteTxn {
    inner: redb::WriteTransaction,
}

impl WriteTxn {
    /// Insert or replace.
    pub fn put(&self, t: Table, key: &[u8], val: &[u8]) -> Result<(), MetaError> {
        let mut table = self.inner.open_table(t.def())?;
        table.insert(key, val)?;
        Ok(())
    }

    /// Remove; returns whether the key existed.
    pub fn del(&self, t: Table, key: &[u8]) -> Result<bool, MetaError> {
        let mut table = self.inner.open_table(t.def())?;
        Ok(table.remove(key)?.is_some())
    }
}

impl Reader for WriteTxn {
    fn get(&self, t: Table, key: &[u8]) -> Result<Option<Vec<u8>>, MetaError> {
        let table = self.inner.open_table(t.def())?;
        Ok(table.get(key)?.map(|g| g.value().to_vec()))
    }

    fn scan(
        &self,
        t: Table,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        f: &mut ScanFn<'_>,
    ) -> Result<(), MetaError> {
        let table = self.inner.open_table(t.def())?;
        run_scan(&table, start, end, f)
    }
}

struct Job {
    run: Box<dyn FnMut(&WriteTxn) -> bool + Send>,
    done: Box<dyn FnOnce(Result<(), MetaError>) + Send>,
}

/// The metadata store interface used by the engine and auth crates.
pub trait MetaStore: Send + Sync {
    /// Begin a read snapshot.
    fn read(&self) -> Result<ReadTxn, MetaError>;
}

/// redb implementation of [`MetaStore`].
#[derive(Clone)]
pub struct RedbMetaStore {
    db: Arc<redb::Database>,
    tx: Arc<Mutex<Option<mpsc::Sender<Job>>>>,
    writer: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}

/// Max jobs folded into one commit.
const MAX_BATCH: usize = 128;

impl RedbMetaStore {
    /// Open (or create) the database at `path` and start the writer thread.
    pub fn open(path: &Path) -> Result<RedbMetaStore, MetaError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| MetaError::Db(e.to_string()))?;
        }
        let db = Arc::new(redb::Database::create(path)?);
        {
            let w = db.begin_write()?;
            for t in Table::ALL {
                w.open_table(t.def())?;
            }
            w.commit()?;
        }
        let (tx, rx) = mpsc::channel::<Job>();
        let wdb = db.clone();
        let handle = std::thread::Builder::new()
            .name("cairn-meta-writer".into())
            .spawn(move || writer_loop(&wdb, rx))
            .map_err(|e| MetaError::Db(e.to_string()))?;
        Ok(RedbMetaStore {
            db,
            tx: Arc::new(Mutex::new(Some(tx))),
            writer: Arc::new(Mutex::new(Some(handle))),
        })
    }

    /// Run `f` inside a write transaction on the serialised writer; resolves after commit.
    /// `f` may be re-run (on a fresh transaction) if another job in the same group commit failed,
    /// so it must be a deterministic function of the database state it reads.
    pub async fn write<T, E, F>(&self, mut f: F) -> Result<T, E>
    where
        F: FnMut(&WriteTxn) -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: From<MetaError> + Send + 'static,
    {
        let slot: Arc<Mutex<Option<Result<T, E>>>> = Arc::new(Mutex::new(None));
        let (otx, orx) = tokio::sync::oneshot::channel::<Result<T, E>>();
        let s1 = slot.clone();
        let job = Job {
            run: Box::new(move |txn| {
                let r = f(txn);
                let ok = r.is_ok();
                *s1.lock().unwrap() = Some(r);
                ok
            }),
            done: Box::new(move |commit| {
                let r = slot.lock().unwrap().take();
                let out = match (r, commit) {
                    (Some(Ok(v)), Ok(())) => Ok(v),
                    (Some(Ok(_)), Err(e)) => Err(E::from(e)),
                    (Some(Err(e)), _) => Err(e),
                    (None, Err(e)) => Err(E::from(e)),
                    (None, Ok(())) => Err(E::from(MetaError::Panicked)),
                };
                let _ = otx.send(out);
            }),
        };
        {
            let guard = self.tx.lock().unwrap();
            let Some(tx) = guard.as_ref() else {
                return Err(E::from(MetaError::Closed));
            };
            tx.send(job).map_err(|_| E::from(MetaError::Closed))?;
        }
        orx.await.map_err(|_| E::from(MetaError::Closed))?
    }

    /// Stop the writer thread after draining queued jobs.
    pub fn shutdown(&self) {
        self.tx.lock().unwrap().take();
        if let Some(h) = self.writer.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}

impl MetaStore for RedbMetaStore {
    fn read(&self) -> Result<ReadTxn, MetaError> {
        Ok(ReadTxn {
            inner: self.db.begin_read()?,
        })
    }
}

fn run_job(job: &mut Job, txn: &WriteTxn) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (job.run)(txn))).unwrap_or(false)
}

fn writer_loop(db: &redb::Database, rx: mpsc::Receiver<Job>) {
    while let Ok(first) = rx.recv() {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(j) => batch.push(j),
                Err(_) => break,
            }
        }
        run_batch(db, batch);
    }
}

fn begin(db: &redb::Database) -> Result<WriteTxn, MetaError> {
    Ok(WriteTxn {
        inner: db.begin_write()?,
    })
}

fn run_batch(db: &redb::Database, mut batch: Vec<Job>) {
    if batch.len() > 1 {
        match begin(db) {
            Ok(txn) => {
                let all_ok = batch.iter_mut().all(|j| run_job(j, &txn));
                if all_ok {
                    let res = txn.inner.commit().map_err(MetaError::from);
                    for j in batch {
                        (j.done)(res.clone());
                    }
                    return;
                }
                let _ = txn.inner.abort();
            }
            Err(e) => {
                for j in batch {
                    (j.done)(Err(e.clone()));
                }
                return;
            }
        }
    }
    for mut j in batch {
        let res = begin(db).and_then(|txn| {
            if run_job(&mut j, &txn) {
                txn.inner.commit().map_err(MetaError::from)
            } else {
                let _ = txn.inner.abort();
                Ok(())
            }
        });
        (j.done)(res);
    }
}
