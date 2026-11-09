//! Blob tiering (DESIGN §12.1): hot blobs stay in the local [`FsBlobStore`], cold blobs move to a
//! [`ColdStore`] (remote S3 via [`RemoteBlobStore`], or a directory via [`DirColdStore`]).
//!
//! A blob moved by [`TieredBlobStore::tier_tick`] leaves a small stub file next to where the hot
//! file was (`blobs/ab/cd/<hex>.cold`, text `tidemark-cold 1 <size> <encrypted>`), so `exists`,
//! `size` and the GC/fsck walks never need the network. Reads of a cold blob are transparent:
//! plaintext ranges are fetched with ranged GETs, encrypted blobs are fetched whole into `tmp/`
//! and decrypted locally, and with [`TierPolicy::rehydrate_on_read`] the blob moves back to the
//! hot tier on first read. The file's mtime is the "last access" clock: blob files are immutable,
//! so reads bump it (at most once per [`TierPolicy::touch_interval`]).

use crate::crypto::{self, ChunkCipher, HEADER};
use crate::remote_s3::{RemoteS3, is_not_found};
use crate::{BlobError, BlobReader, BlobStore, BlobWriter, DataKey, FsBlobStore, WriteOpts};
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tidemark_core::BlobId;
use tokio::io::AsyncReadExt;

/// Remote object storage for cold blobs. Names are `<hex>` or `<hex>.enc` (the stored file bytes,
/// so encrypted blobs stay encrypted at rest on the remote too).
pub trait ColdStore: Send + Sync + 'static {
    /// Upload a local file as `name` (overwrite allowed; content is immutable per name).
    fn put_file(
        &self,
        name: &str,
        path: &Path,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;
    /// Download `name` into a local file. Missing → `io::ErrorKind::NotFound`.
    fn get_file(
        &self,
        name: &str,
        path: &Path,
    ) -> impl Future<Output = Result<(), BlobError>> + Send;
    /// Stream a byte range of `name`.
    fn get_range(
        &self,
        name: &str,
        range: Range<u64>,
    ) -> impl Future<Output = Result<BlobReader, BlobError>> + Send;
    /// Delete `name` (idempotent).
    fn delete(&self, name: &str) -> impl Future<Output = Result<(), BlobError>> + Send;
}

/// Cold tier on a remote S3 bucket.
#[derive(Debug, Clone)]
pub struct RemoteBlobStore {
    s3: RemoteS3,
}

impl RemoteBlobStore {
    /// Cold tier on `s3` (bucket + prefix).
    pub fn new(s3: RemoteS3) -> RemoteBlobStore {
        RemoteBlobStore { s3 }
    }

    /// The remote bucket.
    pub fn remote(&self) -> &RemoteS3 {
        &self.s3
    }
}

impl ColdStore for RemoteBlobStore {
    async fn put_file(&self, name: &str, path: &Path) -> Result<(), BlobError> {
        self.s3.put_path(name, path).await
    }
    async fn get_file(&self, name: &str, path: &Path) -> Result<(), BlobError> {
        self.s3.get_to_path(name, path).await
    }
    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<BlobReader, BlobError> {
        self.s3.get_range(name, range).await
    }
    async fn delete(&self, name: &str) -> Result<(), BlobError> {
        self.s3.delete(name).await
    }
}

/// Cold tier in a local directory (a mounted NAS / object-store gateway, and the test fake).
#[derive(Debug, Clone)]
pub struct DirColdStore {
    root: PathBuf,
}

impl DirColdStore {
    /// Create `root` if needed.
    pub fn open(root: &Path) -> io::Result<DirColdStore> {
        std::fs::create_dir_all(root)?;
        Ok(DirColdStore {
            root: root.to_path_buf(),
        })
    }

    /// Path of a stored name.
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl ColdStore for DirColdStore {
    async fn put_file(&self, name: &str, path: &Path) -> Result<(), BlobError> {
        let tmp = self.root.join(format!(".{name}.{}", uuid::Uuid::new_v4()));
        tokio::fs::copy(path, &tmp).await?;
        tokio::fs::File::open(&tmp).await?.sync_all().await?;
        tokio::fs::rename(&tmp, self.path(name)).await?;
        Ok(())
    }
    async fn get_file(&self, name: &str, path: &Path) -> Result<(), BlobError> {
        tokio::fs::copy(self.path(name), path).await?;
        Ok(())
    }
    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<BlobReader, BlobError> {
        let mut file = tokio::fs::File::open(self.path(name)).await?;
        let size = file.metadata().await?.len();
        if range.start > range.end || range.end > size {
            return Err(BlobError::BadRange(range, size));
        }
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            if let Err(e) = crate::read_plain(&mut file, range, &tx).await {
                let _ = tx.send(Err(e)).await;
            }
        });
        Ok(BlobReader { rx })
    }
    async fn delete(&self, name: &str) -> Result<(), BlobError> {
        match tokio::fs::remove_file(self.path(name)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// When a hot blob becomes cold. With both limits unset nothing is ever moved.
#[derive(Debug, Clone)]
pub struct TierPolicy {
    /// Move blobs not read or written for at least this long.
    pub min_idle: Option<Duration>,
    /// Only move blobs at least this large (bytes as stored).
    pub min_size: Option<u64>,
    /// Bring a cold blob back to the hot tier on its first read.
    pub rehydrate_on_read: bool,
    /// Minimum interval between "last access" (mtime) updates of a hot blob.
    pub touch_interval: Duration,
}

impl Default for TierPolicy {
    fn default() -> Self {
        TierPolicy {
            min_idle: Some(Duration::from_secs(30 * 86_400)),
            min_size: None,
            rehydrate_on_read: false,
            touch_interval: Duration::from_secs(3600),
        }
    }
}

impl TierPolicy {
    /// Whether a blob of `size` bytes idle for `idle` should move to the cold tier.
    pub fn eligible(&self, size: u64, idle: Duration) -> bool {
        if self.min_idle.is_none() && self.min_size.is_none() {
            return false;
        }
        self.min_idle.is_none_or(|m| idle >= m) && self.min_size.is_none_or(|m| size >= m)
    }
}

/// What one [`TieredBlobStore::tier_tick`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TierStats {
    /// Hot blob files examined.
    pub scanned: u64,
    /// Blobs moved to the cold tier.
    pub moved: u64,
    /// Stored bytes moved.
    pub bytes_moved: u64,
    /// Stubs removed because the blob was hot again (re-written after being frozen).
    pub stale_stubs_removed: u64,
    /// Blobs that failed to move (logged; retried next tick).
    pub errors: u64,
}

/// Contents of a `.cold` stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdStub {
    /// Plaintext size.
    pub size: u64,
    /// Stored encrypted (`.enc` layout).
    pub encrypted: bool,
}

impl ColdStub {
    fn encode(&self) -> String {
        format!(
            "tidemark-cold 1 {} {}\n",
            self.size,
            u8::from(self.encrypted)
        )
    }

    fn parse(s: &str) -> Option<ColdStub> {
        let mut it = s.split_whitespace();
        if it.next()? != "tidemark-cold" || it.next()? != "1" {
            return None;
        }
        let size = it.next()?.parse().ok()?;
        let encrypted = it.next()? == "1";
        Some(ColdStub { size, encrypted })
    }
}

/// Name of a blob in the cold store.
pub fn cold_name(id: &BlobId, encrypted: bool) -> String {
    if encrypted {
        format!("{}.enc", id.to_hex())
    } else {
        id.to_hex()
    }
}

/// Hot local tier + cold remote tier behind the [`BlobStore`] contract.
pub struct TieredBlobStore<C: ColdStore> {
    hot: FsBlobStore,
    cold: Arc<C>,
    policy: TierPolicy,
}

impl<C: ColdStore> Clone for TieredBlobStore<C> {
    fn clone(&self) -> Self {
        TieredBlobStore {
            hot: self.hot.clone(),
            cold: self.cold.clone(),
            policy: self.policy.clone(),
        }
    }
}

impl<C: ColdStore> TieredBlobStore<C> {
    /// Combine a hot store and a cold store.
    pub fn new(hot: FsBlobStore, cold: C, policy: TierPolicy) -> TieredBlobStore<C> {
        TieredBlobStore {
            hot,
            cold: Arc::new(cold),
            policy,
        }
    }

    /// The hot tier.
    pub fn hot(&self) -> &FsBlobStore {
        &self.hot
    }

    /// The cold tier.
    pub fn cold(&self) -> &C {
        &self.cold
    }

    /// The tiering policy.
    pub fn policy(&self) -> &TierPolicy {
        &self.policy
    }

    /// Stub path of a blob (`blobs/ab/cd/<hex>.cold`).
    pub fn stub_path(&self, id: &BlobId) -> PathBuf {
        stub_path(&self.hot, id)
    }

    /// Read a blob's stub, if it has one.
    pub fn stub(&self, id: &BlobId) -> io::Result<Option<ColdStub>> {
        read_stub(&self.hot, id)
    }

    /// Whether the blob exists in either tier (no network I/O). Use this instead of
    /// [`FsBlobStore::exists_sync`] inside metadata write jobs once tiering is on.
    pub fn exists_sync(&self, id: &BlobId) -> bool {
        self.hot.exists_sync(id) || self.stub_path(id).exists()
    }

    /// Whether the blob currently lives only in the cold tier.
    pub fn is_cold(&self, id: &BlobId) -> bool {
        !self.hot.exists_sync(id) && self.stub_path(id).exists()
    }

    fn tmp_file(&self) -> PathBuf {
        self.hot
            .inner
            .tmp
            .join(format!("cold-{}", uuid::Uuid::new_v4()))
    }

    fn touch(&self, id: &BlobId) {
        let now = SystemTime::now();
        for p in [self.hot.plain_path(id), self.hot.enc_path(id)] {
            let Ok(f) = std::fs::File::open(&p) else {
                continue;
            };
            let stale = f
                .metadata()
                .and_then(|m| m.modified())
                .map(|m| now.duration_since(m).unwrap_or_default() >= self.policy.touch_interval)
                .unwrap_or(false);
            if stale {
                let _ = f.set_modified(now);
            }
        }
    }

    /// Move one hot blob to the cold tier. Returns `false` if it was not hot (or was deleted by GC
    /// while moving, in which case the cold copy is removed again).
    pub async fn freeze(&self, id: &BlobId) -> Result<bool, BlobError> {
        let (path, encrypted) = match self.hot.locate(id).await {
            Ok(x) => x,
            Err(BlobError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        let size = self.hot.size(id).await?;
        let name = cold_name(id, encrypted);
        self.cold.put_file(&name, &path).await?;
        let stub = ColdStub { size, encrypted };
        let (hot, sid) = (self.hot.clone(), *id);
        tokio::task::spawn_blocking(move || write_stub(&hot, &sid, &stub))
            .await
            .map_err(io::Error::other)??;
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            let _ = tokio::fs::remove_file(self.stub_path(id)).await;
            self.cold.delete(&name).await?;
            return Ok(false);
        }
        tokio::fs::remove_file(&path).await?;
        Ok(true)
    }

    /// Bring a cold blob back to the hot tier (verifying it) and drop the cold copy.
    /// Returns `false` if it was already hot.
    pub async fn rehydrate(&self, id: &BlobId) -> Result<bool, BlobError> {
        let stub = self.stub(id)?;
        if self.hot.exists_sync(id) {
            if let Some(s) = stub {
                self.drop_cold_copy(id, s.encrypted).await?;
            }
            return Ok(false);
        }
        let stub = stub.ok_or(BlobError::NotFound(*id))?;
        let tmp = self.tmp_file();
        let name = cold_name(id, stub.encrypted);
        let fetched = self.fetch_checked(id, &stub, &name, &tmp).await;
        if let Err(e) = fetched {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        let dest = if stub.encrypted {
            self.hot.enc_path(id)
        } else {
            self.hot.plain_path(id)
        };
        let dir = dest.parent().expect("blob path has parent").to_path_buf();
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::rename(&tmp, &dest).await?;
        if self.hot.inner.fsync {
            crate::sync_dir(&dir);
        }
        self.drop_cold_copy(id, stub.encrypted).await?;
        Ok(true)
    }

    async fn drop_cold_copy(&self, id: &BlobId, encrypted: bool) -> Result<(), BlobError> {
        self.cold.delete(&cold_name(id, encrypted)).await?;
        match tokio::fs::remove_file(self.stub_path(id)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn fetch_checked(
        &self,
        id: &BlobId,
        stub: &ColdStub,
        name: &str,
        tmp: &Path,
    ) -> Result<(), BlobError> {
        self.cold.get_file(name, tmp).await?;
        let len = tokio::fs::metadata(tmp).await?.len();
        let ok = if stub.encrypted {
            len == crate::encrypted_file_len(stub.size)
        } else {
            len == stub.size && hash_file(tmp).await? == *id.as_bytes()
        };
        if !ok {
            return Err(BlobError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cold copy of blob {id} failed verification"),
            )));
        }
        Ok(())
    }

    /// Move every hot blob the policy marks cold, at most `limit` per call. `now` is the clock
    /// used for idle time (tests pass a future instant).
    pub async fn tier_tick(&self, now: SystemTime, limit: usize) -> Result<TierStats, BlobError> {
        let root = self.hot.inner.root.clone();
        let files = tokio::task::spawn_blocking(move || walk_hot(&root))
            .await
            .map_err(io::Error::other)??;
        let mut st = TierStats::default();
        for f in files {
            if st.moved as usize >= limit {
                break;
            }
            st.scanned += 1;
            let idle = now.duration_since(f.modified).unwrap_or_default();
            let eligible = self.policy.eligible(f.len, idle);
            if !eligible {
                if let Ok(Some(s)) = self.stub(&f.id) {
                    match self.drop_cold_copy(&f.id, s.encrypted).await {
                        Ok(()) => st.stale_stubs_removed += 1,
                        Err(e) => {
                            tracing::warn!(blob = %f.id, error = %e, "removing stale cold copy failed");
                            st.errors += 1;
                        }
                    }
                }
                continue;
            }
            match self.freeze(&f.id).await {
                Ok(true) => {
                    st.moved += 1;
                    st.bytes_moved += f.len;
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(blob = %f.id, error = %e, "moving blob to cold tier failed");
                    st.errors += 1;
                }
            }
        }
        if st.moved > 0 || st.errors > 0 {
            tracing::info!(?st, "tier tick");
        }
        Ok(st)
    }

    async fn open_cold(
        &self,
        id: &BlobId,
        range: Range<u64>,
        key: Option<&DataKey>,
    ) -> Result<BlobReader, BlobError> {
        let stub = self.stub(id)?.ok_or(BlobError::NotFound(*id))?;
        if range.start > range.end || range.end > stub.size {
            return Err(BlobError::BadRange(range, stub.size));
        }
        let name = cold_name(id, stub.encrypted);
        if !stub.encrypted {
            return self.cold.get_range(&name, range).await;
        }
        let key = key.ok_or(BlobError::KeyRequired(*id))?.clone();
        let tmp = self.tmp_file();
        if let Err(e) = self.cold.get_file(&name, &tmp).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        let file = tokio::fs::File::open(&tmp).await;
        let _ = tokio::fs::remove_file(&tmp).await;
        open_encrypted(file?, id, range, key).await
    }
}

/// Decrypting reader over an open `.enc` file.
async fn open_encrypted(
    mut file: tokio::fs::File,
    id: &BlobId,
    range: Range<u64>,
    key: DataKey,
) -> Result<BlobReader, BlobError> {
    let mut hdr = [0u8; HEADER];
    file.read_exact(&mut hdr).await?;
    let (salt, size) = crypto::parse_header(&hdr)?;
    if range.start > range.end || range.end > size {
        return Err(BlobError::BadRange(range, size));
    }
    let cipher = ChunkCipher::new(&key, &salt, id.0);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        if let Err(e) = crate::read_encrypted(&mut file, &cipher, size, range, &tx).await {
            let _ = tx.send(Err(e)).await;
        }
    });
    Ok(BlobReader { rx })
}

async fn hash_file(p: &Path) -> io::Result<[u8; 32]> {
    let p = p.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut h = blake3::Hasher::new();
        h.update_reader(std::fs::File::open(p)?)?;
        Ok(*h.finalize().as_bytes())
    })
    .await
    .map_err(io::Error::other)?
}

async fn hash_reader(mut r: BlobReader) -> Result<Option<[u8; 32]>, BlobError> {
    use futures::StreamExt;
    let mut h = blake3::Hasher::new();
    while let Some(c) = r.next().await {
        match c {
            Ok(c) => {
                h.update(&c);
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(None),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Some(*h.finalize().as_bytes()))
}

fn stub_path(hot: &FsBlobStore, id: &BlobId) -> PathBuf {
    let mut p = hot.plain_path(id).into_os_string();
    p.push(".cold");
    PathBuf::from(p)
}

fn read_stub(hot: &FsBlobStore, id: &BlobId) -> io::Result<Option<ColdStub>> {
    match std::fs::read_to_string(stub_path(hot, id)) {
        Ok(s) => ColdStub::parse(&s).map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad cold stub for {id}"),
            )
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn write_stub(hot: &FsBlobStore, id: &BlobId, stub: &ColdStub) -> io::Result<()> {
    use std::io::Write;
    let dest = stub_path(hot, id);
    let tmp = hot.inner.tmp.join(format!("stub-{}", uuid::Uuid::new_v4()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(stub.encode().as_bytes())?;
        if hot.inner.fsync {
            f.sync_all()?;
        }
    }
    std::fs::rename(&tmp, &dest)?;
    if hot.inner.fsync
        && let Some(d) = dest.parent()
    {
        crate::sync_dir(d);
    }
    Ok(())
}

struct HotFile {
    id: BlobId,
    len: u64,
    modified: SystemTime,
}

fn walk_hot(root: &Path) -> io::Result<Vec<HotFile>> {
    let mut out = Vec::new();
    for l1 in dir_entries(root)? {
        for l2 in dir_entries(&l1)? {
            for f in dir_entries(&l2)? {
                let Some(name) = f.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let hex = name.strip_suffix(".enc").unwrap_or(name);
                let Ok(id) = hex.parse::<BlobId>() else {
                    continue;
                };
                let Ok(m) = std::fs::metadata(&f) else {
                    continue;
                };
                out.push(HotFile {
                    id,
                    len: m.len(),
                    modified: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                });
            }
        }
    }
    Ok(out)
}

fn dir_entries(p: &Path) -> io::Result<Vec<PathBuf>> {
    match std::fs::read_dir(p) {
        Ok(rd) => rd.map(|e| e.map(|e| e.path())).collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

impl<C: ColdStore> BlobStore for TieredBlobStore<C> {
    async fn begin_write(&self, opts: WriteOpts) -> Result<BlobWriter, BlobError> {
        self.hot.begin_write(opts).await
    }

    async fn open(
        &self,
        id: &BlobId,
        range: Range<u64>,
        key: Option<&DataKey>,
    ) -> Result<BlobReader, BlobError> {
        if self.hot.exists_sync(id) {
            self.touch(id);
            match self.hot.open(id, range.clone(), key).await {
                Err(BlobError::NotFound(_)) => {}
                r => return r,
            }
        }
        if self.policy.rehydrate_on_read && self.stub(id)?.is_some() {
            match self.rehydrate(id).await {
                Ok(_) => return self.hot.open(id, range, key).await,
                Err(e) if is_not_found(&e) && self.hot.exists_sync(id) => {
                    return self.hot.open(id, range, key).await;
                }
                Err(e) => return Err(e),
            }
        }
        self.open_cold(id, range, key).await
    }

    async fn exists(&self, id: &BlobId) -> bool {
        self.exists_sync(id)
    }

    async fn delete(&self, id: &BlobId) -> Result<(), BlobError> {
        self.hot.delete(id).await?;
        if let Some(s) = self.stub(id)? {
            self.drop_cold_copy(id, s.encrypted).await?;
        }
        Ok(())
    }

    async fn size(&self, id: &BlobId) -> Result<u64, BlobError> {
        match self.hot.size(id).await {
            Err(BlobError::NotFound(_)) => self
                .stub(id)?
                .map(|s| s.size)
                .ok_or(BlobError::NotFound(*id)),
            r => r,
        }
    }

    async fn verify(&self, id: &BlobId, key: Option<&DataKey>) -> Result<bool, BlobError> {
        if self.hot.exists_sync(id) {
            return self.hot.verify(id, key).await;
        }
        let stub = self.stub(id)?.ok_or(BlobError::NotFound(*id))?;
        let tmp = self.tmp_file();
        let name = cold_name(id, stub.encrypted);
        if let Err(e) = self.cold.get_file(&name, &tmp).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        let digest = if stub.encrypted {
            let key = key.ok_or(BlobError::KeyRequired(*id))?.clone();
            let file = tokio::fs::File::open(&tmp).await;
            let _ = tokio::fs::remove_file(&tmp).await;
            match open_encrypted(file?, id, 0..stub.size, key).await {
                Ok(r) => hash_reader(r).await?,
                Err(BlobError::Io(e)) if e.kind() == io::ErrorKind::InvalidData => None,
                Err(e) => return Err(e),
            }
        } else {
            let h = hash_file(&tmp).await;
            let _ = tokio::fs::remove_file(&tmp).await;
            Some(h?)
        };
        Ok(digest.is_some_and(|d| d == *id.as_bytes()))
    }
}
