//! One-pass multi-hasher: BLAKE3 (blob id) + MD5 (ETag) + optional SHA-256 + optional checksum.

use md5::Digest as _;
use tidemark_core::ChecksumAlgo;

/// Incremental `x-amz-checksum-*` state.
#[derive(Clone)]
pub enum ChecksumState {
    /// CRC32.
    Crc32(crc32fast::Hasher),
    /// CRC32C.
    Crc32c(u32),
    /// SHA-1.
    Sha1(sha1::Sha1),
    /// SHA-256.
    Sha256(sha2::Sha256),
    /// CRC64/NVME.
    Crc64(crc64fast_nvme::Digest),
}

impl ChecksumState {
    /// Fresh state for `algo`.
    pub fn new(algo: ChecksumAlgo) -> ChecksumState {
        match algo {
            ChecksumAlgo::Crc32 => ChecksumState::Crc32(crc32fast::Hasher::new()),
            ChecksumAlgo::Crc32c => ChecksumState::Crc32c(0),
            ChecksumAlgo::Sha1 => ChecksumState::Sha1(sha1::Sha1::new()),
            ChecksumAlgo::Sha256 => ChecksumState::Sha256(sha2::Sha256::new()),
            ChecksumAlgo::Crc64Nvme => ChecksumState::Crc64(crc64fast_nvme::Digest::new()),
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, b: &[u8]) {
        match self {
            ChecksumState::Crc32(h) => h.update(b),
            ChecksumState::Crc32c(c) => *c = crc32c::crc32c_append(*c, b),
            ChecksumState::Sha1(h) => h.update(b),
            ChecksumState::Sha256(h) => h.update(b),
            ChecksumState::Crc64(h) => h.write(b),
        }
    }

    /// Big-endian digest bytes.
    pub fn finish(self) -> Vec<u8> {
        match self {
            ChecksumState::Crc32(h) => h.finalize().to_be_bytes().to_vec(),
            ChecksumState::Crc32c(c) => c.to_be_bytes().to_vec(),
            ChecksumState::Sha1(h) => h.finalize().to_vec(),
            ChecksumState::Sha256(h) => h.finalize().to_vec(),
            ChecksumState::Crc64(h) => h.sum64().to_be_bytes().to_vec(),
        }
    }
}

/// Compute a checksum of a byte slice in one call.
pub fn checksum(algo: ChecksumAlgo, data: &[u8]) -> Vec<u8> {
    let mut s = ChecksumState::new(algo);
    s.update(data);
    s.finish()
}

/// Finished digests.
pub struct Hashes {
    /// BLAKE3 (blob id).
    pub blake3: [u8; 32],
    /// MD5.
    pub md5: [u8; 16],
    /// SHA-256 if requested.
    pub sha256: Option<[u8; 32]>,
    /// Requested checksum.
    pub checksum: Option<(ChecksumAlgo, Vec<u8>)>,
}

/// All hashes computed while streaming a blob.
pub struct MultiHasher {
    blake3: blake3::Hasher,
    md5: md5::Md5,
    sha256: Option<sha2::Sha256>,
    checksum: Option<(ChecksumAlgo, ChecksumState)>,
}

impl MultiHasher {
    /// New hasher.
    pub fn new(sha256: bool, checksum: Option<ChecksumAlgo>) -> MultiHasher {
        MultiHasher {
            blake3: blake3::Hasher::new(),
            md5: md5::Md5::new(),
            sha256: sha256.then(sha2::Sha256::new),
            checksum: checksum.map(|a| (a, ChecksumState::new(a))),
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, b: &[u8]) {
        self.blake3.update(b);
        self.md5.update(b);
        if let Some(h) = &mut self.sha256 {
            h.update(b);
        }
        if let Some((_, c)) = &mut self.checksum {
            c.update(b);
        }
    }

    /// Finish all hashes.
    pub fn finish(self) -> Hashes {
        Hashes {
            blake3: *self.blake3.finalize().as_bytes(),
            md5: self.md5.finalize().into(),
            sha256: self.sha256.map(|h| h.finalize().into()),
            checksum: self.checksum.map(|(a, c)| (a, c.finish())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(
            hex::encode(checksum(ChecksumAlgo::Crc32, b"123456789")),
            "cbf43926"
        );
        assert_eq!(
            hex::encode(checksum(ChecksumAlgo::Crc32c, b"123456789")),
            "e3069283"
        );
        assert_eq!(
            hex::encode(checksum(ChecksumAlgo::Crc64Nvme, b"123456789")),
            "ae8b14860a799888"
        );
        assert_eq!(
            hex::encode(checksum(ChecksumAlgo::Sha1, b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        let mut m = MultiHasher::new(true, Some(ChecksumAlgo::Crc32));
        m.update(b"hello ");
        m.update(b"world");
        let hs = m.finish();
        let (md5, sha, ck) = (hs.md5, hs.sha256, hs.checksum);
        assert_eq!(hex::encode(md5), "5eb63bbbe01eeed093cb22bb8f5acdc3");
        assert_eq!(
            hex::encode(sha.unwrap()),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(ck.unwrap().1, checksum(ChecksumAlgo::Crc32, b"hello world"));
    }
}
