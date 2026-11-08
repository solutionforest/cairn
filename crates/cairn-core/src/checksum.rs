//! `x-amz-checksum-*` algorithm identifiers.

use serde::{Deserialize, Serialize};

/// Checksum algorithms supported for `x-amz-checksum-*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChecksumAlgo {
    /// CRC32 (IEEE).
    Crc32,
    /// CRC32C (Castagnoli).
    Crc32c,
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// CRC64/NVME.
    Crc64Nvme,
}

impl ChecksumAlgo {
    /// The S3 algorithm name (`CRC32`, `CRC32C`, `SHA1`, `SHA256`, `CRC64NVME`).
    pub fn as_str(self) -> &'static str {
        match self {
            ChecksumAlgo::Crc32 => "CRC32",
            ChecksumAlgo::Crc32c => "CRC32C",
            ChecksumAlgo::Sha1 => "SHA1",
            ChecksumAlgo::Sha256 => "SHA256",
            ChecksumAlgo::Crc64Nvme => "CRC64NVME",
        }
    }

    /// Parse an S3 algorithm name (case-insensitive).
    pub fn parse(s: &str) -> Option<ChecksumAlgo> {
        Some(match s.to_ascii_uppercase().as_str() {
            "CRC32" => ChecksumAlgo::Crc32,
            "CRC32C" => ChecksumAlgo::Crc32c,
            "SHA1" => ChecksumAlgo::Sha1,
            "SHA256" => ChecksumAlgo::Sha256,
            "CRC64NVME" => ChecksumAlgo::Crc64Nvme,
            _ => return None,
        })
    }

    /// Whether S3 combines part checksums of this algorithm as a full-object CRC (vs composite).
    pub fn is_crc(self) -> bool {
        matches!(
            self,
            ChecksumAlgo::Crc32 | ChecksumAlgo::Crc32c | ChecksumAlgo::Crc64Nvme
        )
    }
}
