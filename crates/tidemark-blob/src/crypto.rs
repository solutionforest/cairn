//! Chunked AES-256-GCM: 64 KiB plaintext chunks, nonce = 0u32 ‖ index, AAD = blob id ‖ index,
//! per-blob key = BLAKE3-derive(data key ‖ salt).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

/// Plaintext bytes per chunk.
pub const CHUNK: usize = 64 * 1024;
/// AEAD tag bytes per chunk.
pub const TAG: usize = 16;
/// Encrypted file header: magic(4) ‖ version(1) ‖ reserved(3) ‖ salt(32) ‖ plaintext size(8).
pub const HEADER: usize = 48;
const MAGIC: &[u8; 4] = b"CRNB";

/// A 256-bit data-encryption key.
#[derive(Clone)]
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    /// Wrap raw key bytes.
    pub fn new(k: [u8; 32]) -> DataKey {
        DataKey(Zeroizing::new(k))
    }

    /// A random key.
    pub fn random() -> DataKey {
        DataKey::new(rand::random())
    }

    /// Derive a purpose-specific key from a master key.
    pub fn derive(master: &[u8; 32], context: &str) -> DataKey {
        let mut h = blake3::Hasher::new_derive_key("tidemark data key v1");
        h.update(context.as_bytes());
        h.update(master);
        DataKey::new(*h.finalize().as_bytes())
    }

    fn blob_cipher(&self, salt: &[u8; 32]) -> Aes256Gcm {
        let mut h = blake3::Hasher::new_derive_key("tidemark blob chunk key v1");
        h.update(self.0.as_ref());
        h.update(salt);
        let k = Zeroizing::new(*h.finalize().as_bytes());
        Aes256Gcm::new_from_slice(k.as_ref()).expect("32-byte key")
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey([REDACTED])")
    }
}

fn nonce(index: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&index.to_be_bytes());
    n
}

fn aad(blob: &[u8; 32], index: u64) -> [u8; 40] {
    let mut a = [0u8; 40];
    a[..32].copy_from_slice(blob);
    a[32..].copy_from_slice(&index.to_be_bytes());
    a
}

/// A keyed chunk sealer/opener for one blob.
pub struct ChunkCipher {
    cipher: Aes256Gcm,
    blob: [u8; 32],
}

impl ChunkCipher {
    /// Cipher for `blob` using `key` and the file's `salt`.
    pub fn new(key: &DataKey, salt: &[u8; 32], blob: [u8; 32]) -> ChunkCipher {
        ChunkCipher {
            cipher: key.blob_cipher(salt),
            blob,
        }
    }

    /// Encrypt chunk `index`.
    pub fn seal(&self, index: u64, plain: &[u8]) -> Vec<u8> {
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce(index)),
                Payload {
                    msg: plain,
                    aad: &aad(&self.blob, index),
                },
            )
            .expect("AES-GCM encryption of bounded chunk cannot fail")
    }

    /// Decrypt and authenticate chunk `index`.
    pub fn open(&self, index: u64, ct: &[u8]) -> std::io::Result<Vec<u8>> {
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce(index)),
                Payload {
                    msg: ct,
                    aad: &aad(&self.blob, index),
                },
            )
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("blob chunk {index} failed authentication"),
                )
            })
    }
}

/// Build the encrypted file header.
pub fn header(salt: &[u8; 32], size: u64) -> [u8; HEADER] {
    let mut h = [0u8; HEADER];
    h[..4].copy_from_slice(MAGIC);
    h[4] = 1;
    h[8..40].copy_from_slice(salt);
    h[40..48].copy_from_slice(&size.to_be_bytes());
    h
}

/// Parse a header into (salt, plaintext size).
pub fn parse_header(h: &[u8]) -> std::io::Result<([u8; 32], u64)> {
    if h.len() < HEADER || &h[..4] != MAGIC || h[4] != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad encrypted blob header",
        ));
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&h[8..40]);
    let mut sz = [0u8; 8];
    sz.copy_from_slice(&h[40..48]);
    Ok((salt, u64::from_be_bytes(sz)))
}

/// File offset and ciphertext length of chunk `index` for a blob of `size` plaintext bytes.
pub fn chunk_location(index: u64, size: u64) -> (u64, usize) {
    let start = index * CHUNK as u64;
    let plain = (size - start).min(CHUNK as u64) as usize;
    (HEADER as u64 + index * (CHUNK + TAG) as u64, plain + TAG)
}

/// Chunks covering plaintext `range` (`start..end`, end exclusive): first..=last index.
pub fn chunks_for(start: u64, end: u64) -> std::ops::RangeInclusive<u64> {
    let first = start / CHUNK as u64;
    let last = if end == 0 {
        0
    } else {
        (end - 1) / CHUNK as u64
    };
    first..=last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_and_tamper() {
        let k = DataKey::random();
        let salt = [3u8; 32];
        let c = ChunkCipher::new(&k, &salt, [1; 32]);
        let ct = c.seal(5, b"secret");
        assert_eq!(c.open(5, &ct).unwrap(), b"secret");
        assert!(c.open(6, &ct).is_err(), "index bound into AAD/nonce");
        let other_blob = ChunkCipher::new(&k, &salt, [2; 32]);
        assert!(other_blob.open(5, &ct).is_err(), "blob id bound into AAD");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(c.open(5, &bad).is_err());
        let (s, n) = parse_header(&header(&salt, 77)).unwrap();
        assert_eq!((s, n), (salt, 77));
    }

    #[test]
    fn chunk_math() {
        let c = CHUNK as u64;
        assert_eq!(chunks_for(0, 1), 0..=0);
        assert_eq!(chunks_for(c - 1, c + 1), 0..=1);
        assert_eq!(chunks_for(c, 2 * c), 1..=1);
        assert_eq!(chunk_location(0, 10), (HEADER as u64, 10 + TAG));
        assert_eq!(
            chunk_location(1, c + 5),
            (HEADER as u64 + (CHUNK + TAG) as u64, 5 + TAG)
        );
    }
}
