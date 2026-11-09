//! `tidemark backup` / `tidemark restore` (DESIGN §9, PRODUCTION-READINESS C5).
//!
//! A backup set is a directory or an S3 prefix:
//!
//! ```text
//! tidemark-backup.json            set descriptor: format, optional KDF salt/params + key check
//! manifests/<id>.json          one per backup (sealed when encrypted)
//! meta/<id>.dump               logical dump of every metadata table from one redb read snapshot
//! blobs/ab/<hex>[.enc|.cold]   stored blob files, shared by all backups (content-addressed)
//! keys/<id>/<file>             data-dir keys (only with --include-keys, only when encrypted)
//! ```
//!
//! Consistency: the metadata dump and the blob list come from the same read transaction, so the
//! backup is the state of one commit. Blobs are immutable, so an incremental backup only uploads
//! blobs absent from the previous manifest. Encryption ("age-style", passphrase recipient):
//! argon2id(passphrase, set salt) → 32-byte key; each file gets a random 32-byte salt and a
//! BLAKE3-derived subkey, and is sealed as 64 KiB ChaCha20-Poly1305 chunks with a STREAM nonce
//! (counter ‖ last-chunk flag), so truncation, reordering and tampering are detected.
//! Restore verifies every file's BLAKE3 against the manifest and every plaintext blob against
//! its content address before it is moved into place.

use crate::TidemarkEngine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tidemark_blob::remote_s3::{RemoteS3, S3Endpoint, is_not_found};
use tidemark_core::{BlobId, Ts};
use tidemark_meta::{
    BlobRef, Flow, MetaError, MetaStore, ReadTxn, Reader, RedbMetaStore, Table, decode,
};
use zeroize::Zeroizing;

/// Backup / restore errors.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// Filesystem or transport failure.
    #[error("backup io: {0}")]
    Io(#[from] io::Error),
    /// Metadata store failure.
    #[error("backup metadata: {0}")]
    Meta(#[from] MetaError),
    /// Wrong passphrase, missing passphrase, or tampered ciphertext.
    #[error("backup crypto: {0}")]
    Crypto(String),
    /// Malformed or inconsistent backup set.
    #[error("backup format: {0}")]
    Format(String),
    /// A file failed hash verification.
    #[error("backup verification failed: {0}")]
    Verify(String),
}

impl From<tidemark_blob::BlobError> for BackupError {
    fn from(e: tidemark_blob::BlobError) -> Self {
        match e {
            tidemark_blob::BlobError::Io(io) => BackupError::Io(io),
            other => BackupError::Io(io::Error::other(other.to_string())),
        }
    }
}

impl From<BackupError> for tidemark_core::S3Error {
    fn from(e: BackupError) -> Self {
        tidemark_core::S3Error::internal(e)
    }
}

type Result<T, E = BackupError> = std::result::Result<T, E>;

/// Where a backup set lives.
#[derive(Debug, Clone)]
pub enum BackupLocation {
    /// A local (or mounted) directory.
    Dir(PathBuf),
    /// A bucket + prefix on any S3 endpoint.
    S3(S3Endpoint),
}

/// Full or incremental.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum BackupMode {
    /// Upload every blob again.
    Full,
    /// Upload only blobs absent from the newest manifest in the set (full if there is none).
    #[default]
    Incremental,
}

/// argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Backup options.
#[derive(Clone, Default)]
pub struct BackupOptions {
    /// Full or incremental.
    pub mode: BackupMode,
    /// Encrypt with this passphrase (required for every backup in an encrypted set).
    pub passphrase: Option<Zeroizing<String>>,
    /// KDF parameters used when a new encrypted set is created.
    pub kdf: KdfParams,
    /// Also back up `<data_dir>/keys/` (refused unless encrypted).
    pub include_keys: bool,
}

impl std::fmt::Debug for BackupOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupOptions")
            .field("mode", &self.mode)
            .field("encrypted", &self.passphrase.is_some())
            .field("kdf", &self.kdf)
            .field("include_keys", &self.include_keys)
            .finish()
    }
}

/// Restore options.
#[derive(Clone, Default)]
pub struct RestoreOptions {
    /// Manifest id to restore (default: newest).
    pub manifest: Option<String>,
    /// Passphrase of an encrypted set.
    pub passphrase: Option<Zeroizing<String>>,
}

/// One file in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Name inside the backup set.
    pub name: String,
    /// Size of the stored (pre-backup-encryption) file.
    pub size: u64,
    /// BLAKE3 (hex) of the stored file.
    pub blake3: String,
}

/// One blob in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobEntry {
    /// Blob id (hex).
    pub id: String,
    /// File name under the data dir's `blobs/ab/cd/` (`<hex>`, `<hex>.enc` or `<hex>.cold`).
    pub file: String,
    /// The stored file.
    pub entry: FileEntry,
    /// Backup that first uploaded it.
    pub added_in: String,
}

/// A backup manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version (1).
    pub format: u32,
    /// Backup id (sortable UTC timestamp + suffix).
    pub id: String,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// Mode actually used.
    pub mode: BackupMode,
    /// Previous manifest this one is incremental to.
    pub parent: Option<String>,
    /// Whether files are sealed.
    pub encrypted: bool,
    /// Metadata dump.
    pub meta: FileEntry,
    /// Rows in the dump.
    pub meta_rows: u64,
    /// Every blob needed to restore this backup.
    pub blobs: Vec<BlobEntry>,
    /// Key files (`keys/<id>/…`).
    pub keys: Vec<FileEntry>,
}

/// What a backup did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BackupReport {
    /// Manifest id.
    pub id: String,
    /// Mode used.
    pub mode: BackupMode,
    /// Blobs in the manifest.
    pub blobs_total: u64,
    /// Blobs uploaded by this run.
    pub blobs_uploaded: u64,
    /// Stored bytes uploaded.
    pub bytes_uploaded: u64,
    /// Metadata rows dumped.
    pub meta_rows: u64,
}

/// What a restore did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RestoreReport {
    /// Manifest restored.
    pub id: String,
    /// Metadata rows loaded.
    pub meta_rows: u64,
    /// Blobs restored and verified.
    pub blobs_restored: u64,
    /// Bytes restored.
    pub bytes_restored: u64,
    /// Key files restored.
    pub keys_restored: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SetDescriptor {
    format: u32,
    kdf: Option<KdfDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfDescriptor {
    algorithm: String,
    params: KdfParams,
    salt: String,
    check: String,
}

const SET_FILE: &str = "tidemark-backup.json";
const SEAL_MAGIC: &[u8; 6] = b"CRNBK1";
const SEAL_HEADER: usize = 6 + 32;
const SEAL_CHUNK: usize = 64 * 1024;
const SEAL_TAG: usize = 16;
const CHECK_PLAINTEXT: &[u8] = b"tidemark-backup-key-check-v1";
const DUMP_MAGIC: &[u8] = b"TIDEMARKMETA1\n";

type SetKey = Zeroizing<[u8; 32]>;

fn derive_key(pass: &str, salt: &[u8], p: KdfParams) -> Result<SetKey> {
    let params = argon2::Params::new(p.m_cost, p.t_cost, p.p_cost, Some(32))
        .map_err(|e| BackupError::Crypto(e.to_string()))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.as_bytes(), salt, out.as_mut())
        .map_err(|e| BackupError::Crypto(e.to_string()))?;
    Ok(out)
}

fn file_cipher(key: &[u8; 32], salt: &[u8; 32]) -> ChaCha20Poly1305 {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"tidemark-backup-file-v1");
    h.update(salt);
    let sub = Zeroizing::new(*h.finalize().as_bytes());
    ChaCha20Poly1305::new(Key::from_slice(sub.as_ref()))
}

fn stream_nonce(counter: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(last);
    n
}

/// Streaming sealer: `CRNBK1 ‖ salt ‖ chunk*` (see module docs).
struct SealWriter<W: Write> {
    out: W,
    cipher: ChaCha20Poly1305,
    aad: [u8; SEAL_HEADER],
    buf: Vec<u8>,
    counter: u32,
}

impl<W: Write> SealWriter<W> {
    fn new(mut out: W, key: &[u8; 32]) -> io::Result<Self> {
        let salt: [u8; 32] = rand::random();
        let mut aad = [0u8; SEAL_HEADER];
        aad[..6].copy_from_slice(SEAL_MAGIC);
        aad[6..].copy_from_slice(&salt);
        out.write_all(&aad)?;
        Ok(SealWriter {
            out,
            cipher: file_cipher(key, &salt),
            aad,
            buf: Vec::with_capacity(SEAL_CHUNK),
            counter: 0,
        })
    }

    fn seal(&mut self, last: bool) -> io::Result<()> {
        let n = stream_nonce(self.counter, last);
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: &self.buf,
                    aad: &self.aad,
                },
            )
            .map_err(|_| io::Error::other("seal failed"))?;
        self.out.write_all(&ct)?;
        self.buf.clear();
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| io::Error::other("file too large to seal"))?;
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        self.seal(true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for SealWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = SEAL_CHUNK - self.buf.len();
        let n = room.min(data.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == SEAL_CHUNK {
            self.seal(false)?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Decrypt a sealed stream from `src` into `dst`.
fn unseal(mut src: impl Read, mut dst: impl Write, key: &[u8; 32]) -> Result<()> {
    let mut aad = [0u8; SEAL_HEADER];
    src.read_exact(&mut aad)
        .map_err(|_| BackupError::Crypto("sealed file too short".into()))?;
    if &aad[..6] != SEAL_MAGIC {
        return Err(BackupError::Crypto("not a sealed backup file".into()));
    }
    let salt: [u8; 32] = aad[6..].try_into().expect("32 bytes");
    let cipher = file_cipher(key, &salt);
    let mut counter = 0u32;
    let mut buf = vec![0u8; SEAL_CHUNK + SEAL_TAG];
    loop {
        let n = read_full(&mut src, &mut buf)?;
        let last = n < buf.len();
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&stream_nonce(counter, last)),
                Payload {
                    msg: &buf[..n],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                BackupError::Crypto(
                    "authentication failed (wrong key, truncated or tampered)".into(),
                )
            })?;
        dst.write_all(&pt)?;
        if last {
            return Ok(());
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| BackupError::Format("sealed file too large".into()))?;
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn seal_bytes(key: &[u8; 32], data: &[u8]) -> io::Result<Vec<u8>> {
    let mut w = SealWriter::new(Vec::new(), key)?;
    w.write_all(data)?;
    w.finish()
}

fn unseal_bytes(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    unseal(data, &mut out, key)?;
    Ok(out)
}

/// Copy `src` to `dst` (optionally sealing) and return (bytes read, BLAKE3 hex of the input).
fn copy_hashing(src: &Path, dst: &Path, key: Option<&[u8; 32]>) -> io::Result<(u64, String)> {
    let mut r = HashingReader::new(BufReader::new(std::fs::File::open(src)?));
    let mut out = BufWriter::new(std::fs::File::create(dst)?);
    match key {
        Some(k) => {
            let mut w = SealWriter::new(&mut out, k)?;
            io::copy(&mut r, &mut w)?;
            w.finish()?;
        }
        None => {
            io::copy(&mut r, &mut out)?;
        }
    }
    out.flush()?;
    out.get_ref().sync_all()?;
    Ok(r.finish())
}

/// Reader that hashes (BLAKE3) and counts what passes through.
struct HashingReader<R: Read> {
    inner: R,
    h: blake3::Hasher,
    n: u64,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        HashingReader {
            inner,
            h: blake3::Hasher::new(),
            n: 0,
        }
    }
    fn finish(self) -> (u64, String) {
        (self.n, self.h.finalize().to_hex().to_string())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.h.update(&buf[..n]);
        self.n += n as u64;
        Ok(n)
    }
}

fn hash_file(p: &Path) -> io::Result<(u64, String)> {
    let mut h = blake3::Hasher::new();
    let n = io::copy(&mut BufReader::new(std::fs::File::open(p)?), &mut h)?;
    Ok((n, h.finalize().to_hex().to_string()))
}

/// Storage for a backup set.
#[async_trait::async_trait]
trait SetStore: Send + Sync {
    async fn put_file(&self, name: &str, src: &Path) -> Result<()>;
    async fn get_file(&self, name: &str, dst: &Path) -> Result<()>;
    async fn put_bytes(&self, name: &str, data: Vec<u8>) -> Result<()>;
    async fn get_bytes(&self, name: &str) -> Result<Option<Vec<u8>>>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

struct DirSet(PathBuf);

#[async_trait::async_trait]
impl SetStore for DirSet {
    async fn put_file(&self, name: &str, src: &Path) -> Result<()> {
        let dest = self.0.join(name);
        let parent = dest.parent().expect("has parent").to_path_buf();
        tokio::fs::create_dir_all(&parent).await?;
        let tmp = parent.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        tokio::fs::copy(src, &tmp).await?;
        tokio::fs::File::open(&tmp).await?.sync_all().await?;
        tokio::fs::rename(&tmp, &dest).await?;
        Ok(())
    }
    async fn get_file(&self, name: &str, dst: &Path) -> Result<()> {
        tokio::fs::copy(self.0.join(name), dst).await?;
        Ok(())
    }
    async fn put_bytes(&self, name: &str, data: Vec<u8>) -> Result<()> {
        let dest = self.0.join(name);
        let parent = dest.parent().expect("has parent").to_path_buf();
        tokio::fs::create_dir_all(&parent).await?;
        let tmp = parent.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&tmp, data).await?;
        tokio::fs::File::open(&tmp).await?.sync_all().await?;
        tokio::fs::rename(&tmp, &dest).await?;
        Ok(())
    }
    async fn get_bytes(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.0.join(name)).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let dir = self.0.join(prefix);
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(e) = rd.next_entry().await? {
            if let Some(n) = e.file_name().to_str()
                && !n.starts_with('.')
            {
                out.push(format!("{prefix}{n}"));
            }
        }
        out.sort();
        Ok(out)
    }
}

struct S3Set(RemoteS3);

#[async_trait::async_trait]
impl SetStore for S3Set {
    async fn put_file(&self, name: &str, src: &Path) -> Result<()> {
        Ok(self.0.put_path(name, src).await?)
    }
    async fn get_file(&self, name: &str, dst: &Path) -> Result<()> {
        Ok(self.0.get_to_path(name, dst).await?)
    }
    async fn put_bytes(&self, name: &str, data: Vec<u8>) -> Result<()> {
        Ok(self.0.put_bytes(name, data.into()).await?)
    }
    async fn get_bytes(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get_bytes(name).await?.map(|b| b.to_vec()))
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        match self.0.list(prefix).await {
            Ok(v) => Ok(v),
            Err(e) if is_not_found(&e) => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }
}

fn open_set(loc: &BackupLocation) -> Box<dyn SetStore> {
    match loc {
        BackupLocation::Dir(p) => Box::new(DirSet(p.clone())),
        BackupLocation::S3(ep) => Box::new(S3Set(RemoteS3::new(ep))),
    }
}

/// Load (or, when `create` is set, create) the set descriptor and derive the set key.
async fn set_key(
    store: &dyn SetStore,
    pass: Option<&Zeroizing<String>>,
    create: Option<KdfParams>,
) -> Result<Option<SetKey>> {
    let desc = match store.get_bytes(SET_FILE).await? {
        Some(b) => serde_json::from_slice::<SetDescriptor>(&b)
            .map_err(|e| BackupError::Format(format!("{SET_FILE}: {e}")))?,
        None => {
            let Some(params) = create else {
                return Err(BackupError::Format(format!("no {SET_FILE} at the source")));
            };
            let kdf = match pass {
                None => None,
                Some(p) => {
                    let salt: [u8; 16] = rand::random();
                    let key = derive_key(p, &salt, params)?;
                    Some(KdfDescriptor {
                        algorithm: "argon2id".into(),
                        params,
                        salt: hex::encode(salt),
                        check: hex::encode(seal_bytes(&key, CHECK_PLAINTEXT)?),
                    })
                }
            };
            let d = SetDescriptor { format: 1, kdf };
            store
                .put_bytes(
                    SET_FILE,
                    serde_json::to_vec_pretty(&d).expect("descriptor serialises"),
                )
                .await?;
            d
        }
    };
    if desc.format != 1 {
        return Err(BackupError::Format(format!(
            "unsupported backup set format {}",
            desc.format
        )));
    }
    match (desc.kdf, pass) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(BackupError::Crypto(
            "this backup set is not encrypted; use a new destination for encrypted backups".into(),
        )),
        (Some(_), None) => Err(BackupError::Crypto(
            "this backup set is encrypted; a passphrase is required".into(),
        )),
        (Some(k), Some(p)) => {
            let salt =
                hex::decode(&k.salt).map_err(|e| BackupError::Format(format!("kdf salt: {e}")))?;
            let key = derive_key(p, &salt, k.params)?;
            let check = hex::decode(&k.check)
                .map_err(|e| BackupError::Format(format!("kdf check: {e}")))?;
            match unseal_bytes(&key, &check) {
                Ok(v) if v == CHECK_PLAINTEXT => Ok(Some(key)),
                _ => Err(BackupError::Crypto("wrong passphrase".into())),
            }
        }
    }
}

fn manifest_name(id: &str) -> String {
    format!("manifests/{id}.json")
}

async fn load_manifest(store: &dyn SetStore, id: &str, key: Option<&SetKey>) -> Result<Manifest> {
    let raw = store
        .get_bytes(&manifest_name(id))
        .await?
        .ok_or_else(|| BackupError::Format(format!("manifest {id} not found")))?;
    let plain = match key {
        Some(k) => unseal_bytes(k, &raw)?,
        None => raw,
    };
    serde_json::from_slice(&plain).map_err(|e| BackupError::Format(format!("manifest {id}: {e}")))
}

async fn manifest_ids(store: &dyn SetStore) -> Result<Vec<String>> {
    let mut ids: Vec<String> = store
        .list("manifests/")
        .await?
        .into_iter()
        .filter_map(|n| {
            n.strip_prefix("manifests/")
                .and_then(|n| n.strip_suffix(".json"))
                .map(str::to_string)
        })
        .collect();
    ids.sort();
    Ok(ids)
}

/// Manifest ids in a backup set, oldest first.
pub async fn list_backups(src: &BackupLocation) -> Result<Vec<String>> {
    manifest_ids(open_set(src).as_ref()).await
}

fn table_name(t: Table) -> String {
    format!("{t:?}")
}

fn table_by_name(n: &str) -> Option<Table> {
    Table::ALL.iter().copied().find(|t| table_name(*t) == n)
}

/// A blob to back up: id + stored file under `blobs/`.
struct SnapBlob {
    id: BlobId,
    file: String,
    path: PathBuf,
}

/// Dump every table from one snapshot into `out`; return (rows, blobs referenced in it).
fn dump_snapshot(
    r: &ReadTxn,
    out: &mut dyn Write,
    blobs_root: &Path,
) -> Result<(u64, Vec<SnapBlob>)> {
    out.write_all(DUMP_MAGIC)?;
    let mut rows = 0u64;
    for t in Table::ALL {
        let name = table_name(*t);
        let mut err: Option<io::Error> = None;
        r.scan(*t, Bound::Unbounded, Bound::Unbounded, &mut |k, v| {
            let res = (|| -> io::Result<()> {
                out.write_all(&[name.len() as u8])?;
                out.write_all(name.as_bytes())?;
                out.write_all(&(k.len() as u32).to_be_bytes())?;
                out.write_all(k)?;
                out.write_all(&(v.len() as u32).to_be_bytes())?;
                out.write_all(v)
            })();
            match res {
                Ok(()) => {
                    rows += 1;
                    Ok(Flow::Continue)
                }
                Err(e) => {
                    err = Some(e);
                    Ok(Flow::Stop)
                }
            }
        })?;
        if let Some(e) = err {
            return Err(e.into());
        }
    }
    out.write_all(&[0])?;
    out.write_all(&rows.to_be_bytes())?;
    let mut blobs = Vec::new();
    let mut missing = Vec::new();
    r.scan(
        Table::Blobs,
        Bound::Unbounded,
        Bound::Unbounded,
        &mut |k, v| {
            let Ok(a) = <[u8; 32]>::try_from(k) else {
                return Ok(Flow::Continue);
            };
            let row: BlobRef = decode(v)?;
            if row.refcount == 0 {
                return Ok(Flow::Continue);
            }
            let id = BlobId(a);
            let hex = id.to_hex();
            let dir = blobs_root.join(&hex[..2]).join(&hex[2..4]);
            let found = [format!("{hex}.enc"), hex.clone(), format!("{hex}.cold")]
                .into_iter()
                .find(|f| dir.join(f).exists());
            match found {
                Some(file) => blobs.push(SnapBlob {
                    id,
                    path: dir.join(&file),
                    file,
                }),
                None => missing.push(id),
            }
            Ok(Flow::Continue)
        },
    )?;
    if !missing.is_empty() {
        return Err(BackupError::Verify(format!(
            "{} referenced blob(s) are missing from the data dir (first: {}); run `tidemark fsck`",
            missing.len(),
            missing[0]
        )));
    }
    Ok((rows, blobs))
}

fn backup_id(now: Ts) -> String {
    let t = now.to_jiff().strftime("%Y%m%dT%H%M%S%.6fZ").to_string();
    format!("{t}-{:04x}", rand::random::<u16>())
}

fn blob_set_name(file: &str) -> String {
    format!("blobs/{}/{file}", &file[..2])
}

/// Back up `engine`'s data directory to `dest` (see module docs). Safe while serving traffic.
pub async fn backup(
    engine: &TidemarkEngine,
    dest: &BackupLocation,
    opts: &BackupOptions,
) -> Result<BackupReport> {
    if opts.include_keys && opts.passphrase.is_none() {
        return Err(BackupError::Crypto(
            "--include-keys requires an encrypted backup (set a passphrase)".into(),
        ));
    }
    let store = open_set(dest);
    let key = set_key(store.as_ref(), opts.passphrase.as_ref(), Some(opts.kdf)).await?;
    let prev_id = manifest_ids(store.as_ref()).await?.pop();
    let prev = match (&prev_id, opts.mode) {
        (Some(id), BackupMode::Incremental) => {
            Some(load_manifest(store.as_ref(), id, key.as_ref()).await?)
        }
        _ => None,
    };
    let mode = if prev.is_some() {
        BackupMode::Incremental
    } else {
        BackupMode::Full
    };
    let now = Ts::now();
    let id = backup_id(now);
    let tmp_dir = engine.data_dir().join("tmp");
    let dump_tmp = tmp_dir.join(format!("backup-meta-{}", uuid::Uuid::new_v4()));
    let r = engine.meta().read()?;
    let (rows, snap, meta_entry) = {
        let (dump_path, key, blobs_root) = (
            dump_tmp.clone(),
            key.clone(),
            engine.data_dir().join("blobs"),
        );
        tokio::task::spawn_blocking(move || -> Result<_> {
            let f = std::fs::File::create(&dump_path)?;
            let mut hw = HashingWriter::new(BufWriter::new(f));
            let (rows, snap) = match &key {
                Some(k) => {
                    let mut sw = SealWriter::new(&mut hw, k)?;
                    let res = {
                        let mut plain_hash = HashingWriter::new(&mut sw);
                        let res = dump_snapshot(&r, &mut plain_hash, &blobs_root)?;
                        let (n, h) = plain_hash.finish();
                        (res, n, h)
                    };
                    sw.finish()?;
                    let ((rows, snap), n, h) = res;
                    hw.flush()?;
                    return Ok((rows, snap, (n, h)));
                }
                None => dump_snapshot(&r, &mut hw, &blobs_root)?,
            };
            hw.flush()?;
            let (n, h) = hw.finish();
            Ok((rows, snap, (n, h)))
        })
        .await
        .map_err(io::Error::other)?
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&dump_tmp);
        })?
    };
    let meta_name = format!("meta/{id}.dump");
    let put = store.put_file(&meta_name, &dump_tmp).await;
    let _ = tokio::fs::remove_file(&dump_tmp).await;
    put?;
    let prev_blobs: BTreeMap<String, BlobEntry> = prev
        .as_ref()
        .map(|m| {
            m.blobs
                .iter()
                .map(|b| (b.file.clone(), b.clone()))
                .collect()
        })
        .unwrap_or_default();
    let mut rep = BackupReport {
        id: id.clone(),
        mode,
        meta_rows: rows,
        ..Default::default()
    };
    let mut entries = Vec::with_capacity(snap.len());
    for b in snap {
        if let Some(e) = prev_blobs.get(&b.file) {
            entries.push(e.clone());
            continue;
        }
        let name = blob_set_name(&b.file);
        let plain_blob = !b.file.contains('.');
        let entry = if key.is_none() && plain_blob {
            let size = tokio::fs::metadata(&b.path).await?.len();
            store.put_file(&name, &b.path).await?;
            FileEntry {
                name,
                size,
                blake3: b.id.to_hex(),
            }
        } else {
            let tmp = tmp_dir.join(format!("backup-blob-{}", uuid::Uuid::new_v4()));
            let (src, t, k) = (b.path.clone(), tmp.clone(), key.clone());
            let res = tokio::task::spawn_blocking(move || copy_hashing(&src, &t, k.as_deref()))
                .await
                .map_err(io::Error::other)?;
            let res = match res {
                Ok((size, h)) => store.put_file(&name, &tmp).await.map(|_| (size, h)),
                Err(e) => Err(e.into()),
            };
            let _ = tokio::fs::remove_file(&tmp).await;
            let (size, blake3) = res?;
            if plain_blob && blake3 != b.id.to_hex() {
                return Err(BackupError::Verify(format!(
                    "blob {} on disk does not match its id; run `tidemark fsck --verify full`",
                    b.id
                )));
            }
            FileEntry { name, size, blake3 }
        };
        rep.blobs_uploaded += 1;
        rep.bytes_uploaded += entry.size;
        entries.push(BlobEntry {
            id: b.id.to_hex(),
            file: b.file,
            entry,
            added_in: id.clone(),
        });
    }
    rep.blobs_total = entries.len() as u64;
    let mut keys = Vec::new();
    if opts.include_keys {
        let kd = engine.data_dir().join("keys");
        if let Ok(mut rd) = tokio::fs::read_dir(&kd).await {
            while let Some(f) = rd.next_entry().await? {
                if !f.file_type().await?.is_file() {
                    continue;
                }
                let fname = f.file_name().to_string_lossy().to_string();
                let tmp = tmp_dir.join(format!("backup-key-{}", uuid::Uuid::new_v4()));
                let (src, t, k) = (f.path(), tmp.clone(), key.clone());
                let res = tokio::task::spawn_blocking(move || copy_hashing(&src, &t, k.as_deref()))
                    .await
                    .map_err(io::Error::other)?;
                let name = format!("keys/{id}/{fname}");
                let res = match res {
                    Ok(x) => store.put_file(&name, &tmp).await.map(|_| x),
                    Err(e) => Err(e.into()),
                };
                let _ = tokio::fs::remove_file(&tmp).await;
                let (size, blake3) = res?;
                keys.push(FileEntry { name, size, blake3 });
            }
        }
    }
    let manifest = Manifest {
        format: 1,
        id: id.clone(),
        created_at: now.to_rfc3339(),
        mode,
        parent: prev.map(|p| p.id),
        encrypted: key.is_some(),
        meta: FileEntry {
            name: meta_name,
            size: meta_entry.0,
            blake3: meta_entry.1,
        },
        meta_rows: rows,
        blobs: entries,
        keys,
    };
    let json = serde_json::to_vec_pretty(&manifest).expect("manifest serialises");
    let body = match &key {
        Some(k) => seal_bytes(k, &json)?,
        None => json,
    };
    store.put_bytes(&manifest_name(&id), body).await?;
    tracing::info!(?rep, "backup finished");
    Ok(rep)
}

/// Writer that hashes (BLAKE3) and counts what passes through.
struct HashingWriter<W: Write> {
    inner: W,
    h: blake3::Hasher,
    n: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        HashingWriter {
            inner,
            h: blake3::Hasher::new(),
            n: 0,
        }
    }
    fn finish(self) -> (u64, String) {
        (self.n, self.h.finalize().to_hex().to_string())
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(b)?;
        self.h.update(&b[..n]);
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Fetch `name` into `dst` as plaintext (unsealing if needed) and check size + BLAKE3.
async fn fetch_verified(
    store: &dyn SetStore,
    e: &FileEntry,
    dst: &Path,
    key: Option<&SetKey>,
) -> Result<()> {
    match key {
        None => store.get_file(&e.name, dst).await?,
        Some(k) => {
            let sealed = dst.with_extension("sealed");
            let got = store.get_file(&e.name, &sealed).await;
            if let Err(err) = got {
                let _ = tokio::fs::remove_file(&sealed).await;
                return Err(err);
            }
            let (s, d, k) = (sealed.clone(), dst.to_path_buf(), k.clone());
            let res = tokio::task::spawn_blocking(move || -> Result<()> {
                let r = BufReader::new(std::fs::File::open(&s)?);
                let mut w = BufWriter::new(std::fs::File::create(&d)?);
                unseal(r, &mut w, &k)?;
                w.flush()?;
                Ok(())
            })
            .await
            .map_err(io::Error::other)?;
            let _ = tokio::fs::remove_file(&sealed).await;
            res?;
        }
    }
    let p = dst.to_path_buf();
    let (n, h) = tokio::task::spawn_blocking(move || hash_file(&p))
        .await
        .map_err(io::Error::other)??;
    if n != e.size || h != e.blake3 {
        return Err(BackupError::Verify(format!(
            "{}: expected {} bytes / {}, got {n} bytes / {h}",
            e.name, e.size, e.blake3
        )));
    }
    Ok(())
}

/// Rebuild a data directory from a backup set. `dest_dir` must not contain a metadata database.
/// Every file is verified (BLAKE3 against the manifest; plaintext blobs against their id).
pub async fn restore(
    src: &BackupLocation,
    dest_dir: &Path,
    opts: &RestoreOptions,
) -> Result<RestoreReport> {
    let store = open_set(src);
    let key = set_key(store.as_ref(), opts.passphrase.as_ref(), None).await?;
    let id = match &opts.manifest {
        Some(id) => id.clone(),
        None => manifest_ids(store.as_ref())
            .await?
            .pop()
            .ok_or_else(|| BackupError::Format("no backups in this set".into()))?,
    };
    let m = load_manifest(store.as_ref(), &id, key.as_ref()).await?;
    if m.encrypted != key.is_some() {
        return Err(BackupError::Format(
            "manifest encryption flag disagrees with the set".into(),
        ));
    }
    let db = dest_dir.join("meta").join("tidemark.redb");
    if db.exists() {
        return Err(BackupError::Format(format!(
            "{} already exists; restore into an empty directory",
            db.display()
        )));
    }
    let tmp = dest_dir.join("tmp");
    tokio::fs::create_dir_all(&tmp).await?;
    tokio::fs::create_dir_all(dest_dir.join("blobs")).await?;
    let mut rep = RestoreReport {
        id: id.clone(),
        ..Default::default()
    };
    for b in &m.blobs {
        let hex = b.id.as_str();
        let id_ok = hex.parse::<BlobId>().is_ok()
            && hex.len() == 64
            && b.file.starts_with(hex)
            && [hex.to_string(), format!("{hex}.enc"), format!("{hex}.cold")].contains(&b.file);
        if !id_ok {
            return Err(BackupError::Format(format!("bad blob entry {}", b.file)));
        }
        let part = tmp.join(format!("restore-{}", uuid::Uuid::new_v4()));
        let got = fetch_verified(store.as_ref(), &b.entry, &part, key.as_ref()).await;
        if let Err(e) = got {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(e);
        }
        if b.file == hex && b.entry.blake3 != hex {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(BackupError::Verify(format!("blob {hex} content mismatch")));
        }
        let dir = dest_dir.join("blobs").join(&hex[..2]).join(&hex[2..4]);
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::rename(&part, dir.join(&b.file)).await?;
        rep.blobs_restored += 1;
        rep.bytes_restored += b.entry.size;
    }
    for k in &m.keys {
        let fname = k
            .name
            .rsplit('/')
            .next()
            .filter(|n| !n.is_empty() && *n != "..")
            .ok_or_else(|| BackupError::Format(format!("bad key entry {}", k.name)))?;
        let kd = dest_dir.join("keys");
        tokio::fs::create_dir_all(&kd).await?;
        let part = tmp.join(format!("restore-key-{}", uuid::Uuid::new_v4()));
        fetch_verified(store.as_ref(), k, &part, key.as_ref()).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o600)).await?;
        }
        tokio::fs::rename(&part, kd.join(fname)).await?;
        rep.keys_restored += 1;
    }
    let dump = tmp.join(format!("restore-meta-{}", uuid::Uuid::new_v4()));
    let got = fetch_verified(store.as_ref(), &m.meta, &dump, key.as_ref()).await;
    if let Err(e) = got {
        let _ = tokio::fs::remove_file(&dump).await;
        return Err(e);
    }
    let loaded = load_dump(&dump, &db).await;
    let _ = tokio::fs::remove_file(&dump).await;
    rep.meta_rows = loaded?;
    if rep.meta_rows != m.meta_rows {
        return Err(BackupError::Verify(format!(
            "metadata dump has {} rows, manifest says {}",
            rep.meta_rows, m.meta_rows
        )));
    }
    tracing::info!(?rep, "restore finished");
    Ok(rep)
}

type Row = (Table, Vec<u8>, Vec<u8>);

fn read_rows(r: &mut impl Read, max: usize) -> Result<(Vec<Row>, Option<u64>)> {
    let mut rows = Vec::new();
    while rows.len() < max {
        let mut len = [0u8; 1];
        r.read_exact(&mut len)?;
        if len[0] == 0 {
            let mut n = [0u8; 8];
            r.read_exact(&mut n)?;
            return Ok((rows, Some(u64::from_be_bytes(n))));
        }
        let mut name = vec![0u8; len[0] as usize];
        r.read_exact(&mut name)?;
        let name = String::from_utf8(name).map_err(|_| BackupError::Format("table name".into()))?;
        let t = table_by_name(&name)
            .ok_or_else(|| BackupError::Format(format!("unknown table {name} in dump")))?;
        let mut field = || -> Result<Vec<u8>> {
            let mut l = [0u8; 4];
            r.read_exact(&mut l)?;
            let mut v = vec![0u8; u32::from_be_bytes(l) as usize];
            r.read_exact(&mut v)?;
            Ok(v)
        };
        let k = field()?;
        let v = field()?;
        rows.push((t, k, v));
    }
    Ok((rows, None))
}

async fn load_dump(dump: &Path, db: &Path) -> Result<u64> {
    let mut r = BufReader::new(std::fs::File::open(dump)?);
    let mut magic = vec![0u8; DUMP_MAGIC.len()];
    r.read_exact(&mut magic)?;
    if magic != DUMP_MAGIC {
        return Err(BackupError::Format("not a tidemark metadata dump".into()));
    }
    let store = RedbMetaStore::open(db)?;
    let mut total = 0u64;
    let res: Result<u64> = async {
        loop {
            let (rows, end) = read_rows(&mut r, 4096)?;
            total += rows.len() as u64;
            if !rows.is_empty() {
                let rows = Arc::new(rows);
                store
                    .write(move |txn| -> Result<(), MetaError> {
                        for (t, k, v) in rows.iter() {
                            txn.put(*t, k, v)?;
                        }
                        Ok(())
                    })
                    .await?;
            }
            if let Some(n) = end {
                if n != total {
                    return Err(BackupError::Verify(format!(
                        "dump trailer says {n} rows, read {total}"
                    )));
                }
                return Ok(total);
            }
        }
    }
    .await;
    store.shutdown();
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trip_and_tamper_detection() {
        let key = [9u8; 32];
        for n in [
            0,
            1,
            SEAL_CHUNK - 1,
            SEAL_CHUNK,
            SEAL_CHUNK + 1,
            3 * SEAL_CHUNK,
        ] {
            let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let sealed = seal_bytes(&key, &data).unwrap();
            assert_eq!(unseal_bytes(&key, &sealed).unwrap(), data, "size {n}");
            assert!(unseal_bytes(&[8u8; 32], &sealed).is_err());
            let mut flipped = sealed.clone();
            let last = flipped.len() - 1;
            flipped[last] ^= 1;
            assert!(unseal_bytes(&key, &flipped).is_err());
            if n >= SEAL_CHUNK {
                let cut = SEAL_HEADER + SEAL_CHUNK + SEAL_TAG;
                assert!(
                    unseal_bytes(&key, &sealed[..cut]).is_err(),
                    "truncation at a chunk boundary is detected"
                );
            }
        }
        let a = seal_bytes(&key, b"same").unwrap();
        let b = seal_bytes(&key, b"same").unwrap();
        assert_ne!(a, b, "per-file salt");
    }

    #[test]
    fn table_names_round_trip() {
        for t in Table::ALL {
            assert_eq!(table_by_name(&table_name(*t)), Some(*t));
        }
    }
}
