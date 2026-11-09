#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Tidemark blob store: immutable BLAKE3-addressed files with 2-level fan-out, streaming
//! multi-hash writer (tmp → fsync → rename, dedup on existing hash), range reader, and optional
//! chunked AES-256-GCM at rest. Reference counts live in `tidemark-meta`, not here.

pub mod crypto;
pub mod hash;
pub mod remote_s3;
pub mod space;
pub mod tiered;

use bytes::Bytes;
pub use crypto::DataKey;
use crypto::{CHUNK, ChunkCipher, HEADER, TAG};
use futures::Stream;
use hash::MultiHasher;
use std::io::{self, SeekFrom};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use tidemark_core::{BlobId, ChecksumAlgo};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

/// Blob store errors.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// Filesystem failure.
    #[error("blob io: {0}")]
    Io(#[from] io::Error),
    /// Blob is missing.
    #[error("blob {0} not found")]
    NotFound(BlobId),
    /// Encrypted blob opened without a key.
    #[error("blob {0} is encrypted and no key was supplied")]
    KeyRequired(BlobId),
    /// Range outside the blob.
    #[error("range {0:?} outside blob of {1} bytes")]
    BadRange(Range<u64>, u64),
}

impl From<BlobError> for tidemark_core::S3Error {
    fn from(e: BlobError) -> Self {
        tidemark_core::S3Error::internal(e)
    }
}

/// Options for a new blob.
#[derive(Debug, Clone, Default)]
pub struct WriteOpts {
    /// Also compute SHA-256 (for `x-amz-content-sha256` / checksum verification).
    pub sha256: bool,
    /// Compute this `x-amz-checksum-*` algorithm.
    pub checksum: Option<ChecksumAlgo>,
    /// Encrypt at rest with this key.
    pub key: Option<DataKey>,
}

/// Result of a finished write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobDigest {
    /// Content address.
    pub blob_id: BlobId,
    /// MD5 (ETag).
    pub md5: [u8; 16],
    /// SHA-256 if requested.
    pub sha256: Option<[u8; 32]>,
    /// Plaintext size.
    pub size: u64,
    /// Requested checksum.
    pub checksum: Option<(ChecksumAlgo, Vec<u8>)>,
    /// The blob already existed; nothing new was stored.
    pub deduped: bool,
}

/// Blob storage contract (DESIGN §3 / BUILD-PLAN).
pub trait BlobStore: Send + Sync {
    /// Start a streaming write.
    fn begin_write(
        &self,
        opts: WriteOpts,
    ) -> impl Future<Output = Result<BlobWriter, BlobError>> + Send;
    /// Open a plaintext byte range.
    fn open(
        &self,
        id: &BlobId,
        range: Range<u64>,
        key: Option<&DataKey>,
    ) -> impl Future<Output = Result<BlobReader, BlobError>> + Send;
    /// Whether the blob exists.
    fn exists(&self, id: &BlobId) -> impl Future<Output = bool> + Send;
    /// Unlink the blob (idempotent).
    fn delete(&self, id: &BlobId) -> impl Future<Output = Result<(), BlobError>> + Send;
    /// Plaintext size.
    fn size(&self, id: &BlobId) -> impl Future<Output = Result<u64, BlobError>> + Send;
    /// Re-hash and compare to the id.
    fn verify(
        &self,
        id: &BlobId,
        key: Option<&DataKey>,
    ) -> impl Future<Output = Result<bool, BlobError>> + Send;
}

struct Inner {
    root: PathBuf,
    tmp: PathBuf,
    fsync: bool,
}

/// Filesystem blob store rooted at `<data_dir>`: `blobs/ab/cd/<hex>[.enc]` and `tmp/`.
#[derive(Clone)]
pub struct FsBlobStore {
    inner: Arc<Inner>,
}

impl FsBlobStore {
    /// Create directories and open the store.
    pub fn open(data_dir: &Path, fsync: bool) -> Result<FsBlobStore, BlobError> {
        let root = data_dir.join("blobs");
        let tmp = data_dir.join("tmp");
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&tmp)?;
        Ok(FsBlobStore {
            inner: Arc::new(Inner { root, tmp, fsync }),
        })
    }

    fn base_path(&self, id: &BlobId) -> PathBuf {
        let h = id.to_hex();
        self.inner.root.join(&h[..2]).join(&h[2..4]).join(h)
    }

    /// Plaintext file path.
    pub fn plain_path(&self, id: &BlobId) -> PathBuf {
        self.base_path(id)
    }

    /// Encrypted file path.
    pub fn enc_path(&self, id: &BlobId) -> PathBuf {
        let mut p = self.base_path(id).into_os_string();
        p.push(".enc");
        PathBuf::from(p)
    }

    /// Synchronous existence check (used inside metadata write jobs).
    pub fn exists_sync(&self, id: &BlobId) -> bool {
        self.plain_path(id).exists() || self.enc_path(id).exists()
    }

    /// Remove stale files in `tmp/` (call at startup).
    pub fn clean_tmp(&self) -> io::Result<usize> {
        let mut n = 0;
        for e in std::fs::read_dir(&self.inner.tmp)? {
            std::fs::remove_file(e?.path())?;
            n += 1;
        }
        Ok(n)
    }

    async fn locate(&self, id: &BlobId) -> Result<(PathBuf, bool), BlobError> {
        let enc = self.enc_path(id);
        if tokio::fs::try_exists(&enc).await.unwrap_or(false) {
            return Ok((enc, true));
        }
        let plain = self.plain_path(id);
        if tokio::fs::try_exists(&plain).await.unwrap_or(false) {
            return Ok((plain, false));
        }
        Err(BlobError::NotFound(*id))
    }
}

impl BlobStore for FsBlobStore {
    async fn begin_write(&self, opts: WriteOpts) -> Result<BlobWriter, BlobError> {
        let tmp_path = self.inner.tmp.join(uuid::Uuid::new_v4().to_string());
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;
        let stage = opts.key.clone().map(|final_key| Stage {
            cipher: ChunkCipher::new(&DataKey::random(), &[0; 32], [0; 32]),
            plain: Vec::with_capacity(CHUNK),
            index: 0,
            final_key,
        });
        Ok(BlobWriter {
            store: self.clone(),
            file: Some(file),
            tmp_path,
            hasher: Some(MultiHasher::new(opts.sha256, opts.checksum)),
            size: 0,
            stage,
            out: Vec::new(),
            out_pos: 0,
            finished: false,
        })
    }

    async fn open(
        &self,
        id: &BlobId,
        range: Range<u64>,
        key: Option<&DataKey>,
    ) -> Result<BlobReader, BlobError> {
        let (path, encrypted) = self.locate(id).await?;
        let mut file = tokio::fs::File::open(&path).await?;
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        if encrypted {
            let key = key.ok_or(BlobError::KeyRequired(*id))?.clone();
            let mut hdr = [0u8; HEADER];
            file.read_exact(&mut hdr).await?;
            let (salt, size) = crypto::parse_header(&hdr)?;
            if range.start > range.end || range.end > size {
                return Err(BlobError::BadRange(range, size));
            }
            let cipher = ChunkCipher::new(&key, &salt, id.0);
            tokio::spawn(async move {
                let r = read_encrypted(&mut file, &cipher, size, range, &tx).await;
                if let Err(e) = r {
                    let _ = tx.send(Err(e)).await;
                }
            });
        } else {
            let size = file.metadata().await?.len();
            if range.start > range.end || range.end > size {
                return Err(BlobError::BadRange(range, size));
            }
            tokio::spawn(async move {
                let r = read_plain(&mut file, range, &tx).await;
                if let Err(e) = r {
                    let _ = tx.send(Err(e)).await;
                }
            });
        }
        Ok(BlobReader { rx })
    }

    async fn exists(&self, id: &BlobId) -> bool {
        self.locate(id).await.is_ok()
    }

    async fn delete(&self, id: &BlobId) -> Result<(), BlobError> {
        for p in [self.enc_path(id), self.plain_path(id)] {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    async fn size(&self, id: &BlobId) -> Result<u64, BlobError> {
        let (path, encrypted) = self.locate(id).await?;
        if encrypted {
            let mut f = tokio::fs::File::open(&path).await?;
            let mut hdr = [0u8; HEADER];
            f.read_exact(&mut hdr).await?;
            Ok(crypto::parse_header(&hdr)?.1)
        } else {
            Ok(tokio::fs::metadata(&path).await?.len())
        }
    }

    async fn verify(&self, id: &BlobId, key: Option<&DataKey>) -> Result<bool, BlobError> {
        use futures::StreamExt;
        let size = self.size(id).await?;
        let mut r = self.open(id, 0..size, key).await?;
        let mut h = blake3::Hasher::new();
        while let Some(chunk) = r.next().await {
            match chunk {
                Ok(c) => {
                    h.update(&c);
                }
                Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(h.finalize().as_bytes() == id.as_bytes())
    }
}

type Tx = tokio::sync::mpsc::Sender<io::Result<Bytes>>;

const READ_BUF: usize = 64 * 1024;

async fn read_plain(file: &mut tokio::fs::File, range: Range<u64>, tx: &Tx) -> io::Result<()> {
    file.seek(SeekFrom::Start(range.start)).await?;
    let mut left = range.end - range.start;
    while left > 0 {
        let n = left.min(READ_BUF as u64) as usize;
        let mut buf = vec![0u8; n];
        file.read_exact(&mut buf).await?;
        left -= n as u64;
        if tx.send(Ok(Bytes::from(buf))).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

async fn read_encrypted(
    file: &mut tokio::fs::File,
    c: &ChunkCipher,
    size: u64,
    range: Range<u64>,
    tx: &Tx,
) -> io::Result<()> {
    if range.start == range.end {
        return Ok(());
    }
    for idx in crypto::chunks_for(range.start, range.end) {
        let (off, len) = crypto::chunk_location(idx, size);
        file.seek(SeekFrom::Start(off)).await?;
        let mut ct = vec![0u8; len];
        file.read_exact(&mut ct).await?;
        let plain = c.open(idx, &ct)?;
        let chunk_start = idx * CHUNK as u64;
        let from = range.start.saturating_sub(chunk_start) as usize;
        let to = ((range.end - chunk_start) as usize).min(plain.len());
        if tx
            .send(Ok(Bytes::copy_from_slice(&plain[from..to])))
            .await
            .is_err()
        {
            return Ok(());
        }
    }
    Ok(())
}

/// Streaming plaintext reader (`Stream<Item = io::Result<Bytes>>`, `Send + Sync`).
pub struct BlobReader {
    rx: tokio::sync::mpsc::Receiver<io::Result<Bytes>>,
}

impl Stream for BlobReader {
    type Item = io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

struct Stage {
    cipher: ChunkCipher,
    plain: Vec<u8>,
    index: u64,
    final_key: DataKey,
}

/// Streaming blob writer: hashes everything written, then [`BlobWriter::finish`] commits it.
/// Dropping without finishing discards the temp file.
pub struct BlobWriter {
    store: FsBlobStore,
    file: Option<tokio::fs::File>,
    tmp_path: PathBuf,
    hasher: Option<MultiHasher>,
    size: u64,
    stage: Option<Stage>,
    out: Vec<u8>,
    out_pos: usize,
    finished: bool,
}

impl BlobWriter {
    /// Bytes accepted so far.
    pub fn len(&self) -> u64 {
        self.size
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("writer closed"))?;
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut *file).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn accept(&mut self, buf: &[u8]) {
        if let Some(h) = &mut self.hasher {
            h.update(buf);
        }
        self.size += buf.len() as u64;
        match &mut self.stage {
            None => self.out.extend_from_slice(buf),
            Some(st) => {
                st.plain.extend_from_slice(buf);
                while st.plain.len() >= CHUNK {
                    let rest = st.plain.split_off(CHUNK);
                    let ct = st.cipher.seal(st.index, &st.plain);
                    st.index += 1;
                    self.out.extend_from_slice(&ct);
                    st.plain = rest;
                }
            }
        }
    }

    /// Flush, fsync and move the blob into place (or drop it on a dedup hit).
    pub async fn finish(mut self) -> Result<BlobDigest, BlobError> {
        if let Some(st) = &mut self.stage
            && !st.plain.is_empty()
        {
            let ct = st.cipher.seal(st.index, &st.plain);
            st.index += 1;
            st.plain.clear();
            self.out.extend_from_slice(&ct);
        }
        let out = std::mem::take(&mut self.out);
        let mut file = self.file.take().expect("file present until finish");
        file.write_all(&out[self.out_pos..]).await?;
        file.flush().await?;
        if self.store.inner.fsync {
            file.sync_all().await?;
        }
        drop(file);
        let hs = self.hasher.take().expect("hasher").finish();
        let blob_id = BlobId(hs.blake3);
        let mut digest = BlobDigest {
            blob_id,
            md5: hs.md5,
            sha256: hs.sha256,
            size: self.size,
            checksum: hs.checksum,
            deduped: false,
        };
        if self.store.exists_sync(&blob_id) {
            digest.deduped = true;
            return Ok(digest);
        }
        let store = self.store.clone();
        let tmp = self.tmp_path.clone();
        let stage = self.stage.take();
        let size = self.size;
        tokio::task::spawn_blocking(move || commit_file(&store, &tmp, &blob_id, size, stage))
            .await
            .map_err(io::Error::other)??;
        self.finished = true;
        Ok(digest)
    }
}

fn sync_dir(p: &Path) {
    if let Ok(d) = std::fs::File::open(p) {
        let _ = d.sync_all();
    }
}

fn commit_file(
    store: &FsBlobStore,
    tmp: &Path,
    id: &BlobId,
    size: u64,
    stage: Option<Stage>,
) -> io::Result<()> {
    use std::io::{Read, Write};
    let dest = if stage.is_some() {
        store.enc_path(id)
    } else {
        store.plain_path(id)
    };
    let dir = dest.parent().expect("blob path has parent").to_path_buf();
    std::fs::create_dir_all(&dir)?;
    match stage {
        None => std::fs::rename(tmp, &dest)?,
        Some(st) => {
            let sealed = store
                .inner
                .tmp
                .join(format!("{}.enc", uuid::Uuid::new_v4()));
            let salt: [u8; 32] = rand::random();
            let fin = ChunkCipher::new(&st.final_key, &salt, id.0);
            {
                let mut src = std::io::BufReader::new(std::fs::File::open(tmp)?);
                let mut dst = std::io::BufWriter::new(std::fs::File::create(&sealed)?);
                dst.write_all(&crypto::header(&salt, size))?;
                for idx in 0..st.index {
                    let (_, len) = crypto::chunk_location(idx, size);
                    let mut ct = vec![0u8; len];
                    src.read_exact(&mut ct)?;
                    let plain = st.cipher.open(idx, &ct)?;
                    dst.write_all(&fin.seal(idx, &plain))?;
                }
                let f = dst.into_inner().map_err(|e| e.into_error())?;
                if store.inner.fsync {
                    f.sync_all()?;
                }
            }
            std::fs::remove_file(tmp)?;
            std::fs::rename(&sealed, &dest)?;
        }
    }
    if store.inner.fsync {
        sync_dir(&dir);
    }
    Ok(())
}

impl Drop for BlobWriter {
    fn drop(&mut self) {
        if !self.finished {
            let _ = std::fs::remove_file(&self.tmp_path);
        }
    }
}

impl AsyncWrite for BlobWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_drain(cx))?;
        self.accept(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("writer closed"))?;
        Pin::new(file).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// Size of an encrypted blob file for a plaintext size (for tests / fsck).
pub fn encrypted_file_len(size: u64) -> u64 {
    let chunks = size.div_ceil(CHUNK as u64);
    HEADER as u64 + size + chunks * TAG as u64
}
