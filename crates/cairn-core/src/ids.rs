//! Identifiers: bucket names, object keys, bucket/version/blob ids, principals.

use crate::error::{S3Error, S3ErrorCode};
use crate::time::Ts;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A validated S3 bucket name (3–63 chars, DNS compatible).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BucketName(String);

impl BucketName {
    /// The name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_bucket_name(s: &str) -> bool {
    let b = s.as_bytes();
    if !(3..=63).contains(&b.len()) {
        return false;
    }
    if !b
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-')
    {
        return false;
    }
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !edge(b[0]) || !edge(b[b.len() - 1]) {
        return false;
    }
    if s.contains("..") || s.contains(".-") || s.contains("-.") {
        return false;
    }
    if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return false;
    }
    if s.starts_with("xn--")
        || s.starts_with("sthree-")
        || s.ends_with("-s3alias")
        || s.ends_with("--ol-s3")
    {
        return false;
    }
    true
}

impl TryFrom<&str> for BucketName {
    type Error = S3Error;
    fn try_from(s: &str) -> Result<Self, S3Error> {
        if valid_bucket_name(s) {
            Ok(BucketName(s.to_owned()))
        } else {
            Err(S3Error::new(
                S3ErrorCode::InvalidBucketName,
                "The specified bucket is not valid.",
            )
            .with_resource(s))
        }
    }
}

impl FromStr for BucketName {
    type Err = S3Error;
    fn from_str(s: &str) -> Result<Self, S3Error> {
        BucketName::try_from(s)
    }
}

impl fmt::Display for BucketName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated object key: 1..=1024 bytes of UTF-8 without NUL.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectKey(String);

impl ObjectKey {
    /// Maximum key length in bytes.
    pub const MAX_LEN: usize = 1024;

    /// The key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ObjectKey {
    type Error = S3Error;
    fn try_from(s: &str) -> Result<Self, S3Error> {
        if s.is_empty() {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Object key must not be empty.",
            ));
        }
        if s.len() > Self::MAX_LEN {
            return Err(S3Error::new(
                S3ErrorCode::KeyTooLongError,
                "Your key is too long.",
            ));
        }
        if s.as_bytes().contains(&0) {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Object key must not contain NUL.",
            ));
        }
        Ok(ObjectKey(s.to_owned()))
    }
}

impl FromStr for ObjectKey {
    type Err = S3Error;
    fn from_str(s: &str) -> Result<Self, S3Error> {
        ObjectKey::try_from(s)
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque 128-bit bucket identity; a recreated bucket gets a fresh id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BucketId(pub u128);

impl BucketId {
    /// A new random id.
    pub fn random() -> BucketId {
        BucketId(rand::random())
    }

    /// Big-endian bytes (key prefix).
    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// From big-endian bytes.
    pub fn from_bytes(b: [u8; 16]) -> BucketId {
        BucketId(u128::from_be_bytes(b))
    }
}

impl fmt::Display for BucketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl FromStr for BucketId {
    type Err = S3Error;
    fn from_str(s: &str) -> Result<Self, S3Error> {
        u128::from_str_radix(s, 16)
            .map(BucketId)
            .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "invalid bucket id"))
    }
}

/// 20-byte version id: 8-byte big-endian inverted `created_at` nanos ‖ 12 random bytes.
/// Byte order sorts newest first. Rendered to clients as 40 lowercase hex chars.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VersionId(pub [u8; 20]);

impl VersionId {
    /// New id for a version created at `at`.
    pub fn new(at: Ts) -> VersionId {
        let mut b = [0u8; 20];
        b[..8].copy_from_slice(&Self::inverted_prefix(at));
        let r: [u8; 12] = rand::random();
        b[8..].copy_from_slice(&r);
        VersionId(b)
    }

    /// The 8-byte inverted timestamp prefix used for ordering.
    pub fn inverted_prefix(at: Ts) -> [u8; 8] {
        let n = at.0.clamp(0, u64::MAX as i128) as u64;
        (u64::MAX - n).to_be_bytes()
    }

    /// Smallest id whose timestamp is `at` (seek target: all ids `>=` this were created at or before `at`).
    pub fn seek_at(at: Ts) -> VersionId {
        let mut b = [0u8; 20];
        b[..8].copy_from_slice(&Self::inverted_prefix(at));
        VersionId(b)
    }

    /// The creation timestamp encoded in the id (nanosecond precision, clamped to >= 0).
    pub fn created_at(&self) -> Ts {
        let mut p = [0u8; 8];
        p.copy_from_slice(&self.0[..8]);
        Ts((u64::MAX - u64::from_be_bytes(p)) as i128)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// From a byte slice of length 20.
    pub fn from_slice(b: &[u8]) -> Option<VersionId> {
        <[u8; 20]>::try_from(b).ok().map(VersionId)
    }
}

impl fmt::Display for VersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for VersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VersionId({self})")
    }
}

impl FromStr for VersionId {
    type Err = S3Error;
    fn from_str(s: &str) -> Result<Self, S3Error> {
        let mut b = [0u8; 20];
        hex::decode_to_slice(s, &mut b).map_err(|_| {
            S3Error::new(S3ErrorCode::InvalidArgument, "Invalid version id specified")
        })?;
        Ok(VersionId(b))
    }
}

/// 32-byte BLAKE3 hash of blob plaintext.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlobId(pub [u8; 32]);

impl BlobId {
    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobId({})", &self.to_hex()[..16])
    }
}

impl FromStr for BlobId {
    type Err = S3Error;
    fn from_str(s: &str) -> Result<Self, S3Error> {
        let mut b = [0u8; 32];
        hex::decode_to_slice(s, &mut b)
            .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "invalid blob id"))?;
        Ok(BlobId(b))
    }
}

/// Principal identifier: `root`, `user:<name>`, `role:<name>/<session>`, `anonymous`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PrincipalId(pub String);

impl PrincipalId {
    /// The root principal.
    pub fn root() -> PrincipalId {
        PrincipalId("root".into())
    }

    /// The anonymous principal.
    pub fn anonymous() -> PrincipalId {
        PrincipalId("anonymous".into())
    }

    /// A named user.
    pub fn user(name: &str) -> PrincipalId {
        PrincipalId(format!("user:{name}"))
    }

    /// An assumed role session.
    pub fn role(name: &str, session: &str) -> PrincipalId {
        PrincipalId(format!("role:{name}/{session}"))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the root principal.
    pub fn is_root(&self) -> bool {
        self.0 == "root"
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_names() {
        for ok in ["abc", "my-bucket", "my.bucket.1", "a1b", &"a".repeat(63)] {
            assert!(BucketName::try_from(ok).is_ok(), "{ok}");
        }
        for bad in [
            "ab",
            "ABC",
            "-abc",
            "abc-",
            "a..b",
            "a.-b",
            "192.168.1.1",
            "xn--abc",
            "abc-s3alias",
            "a_b",
            &"a".repeat(64),
        ] {
            let e = BucketName::try_from(bad).unwrap_err();
            assert_eq!(e.code, S3ErrorCode::InvalidBucketName, "{bad}");
        }
    }

    #[test]
    fn object_keys() {
        assert!(ObjectKey::try_from("a/b/c.txt").is_ok());
        assert!(ObjectKey::try_from(&*"k".repeat(1024)).is_ok());
        assert_eq!(
            ObjectKey::try_from(&*"k".repeat(1025)).unwrap_err().code,
            S3ErrorCode::KeyTooLongError
        );
        assert!(ObjectKey::try_from("").is_err());
        assert!(ObjectKey::try_from("a\0b").is_err());
    }

    #[test]
    fn version_ids_sort_newest_first() {
        let a = VersionId::new(Ts(1_000));
        let b = VersionId::new(Ts(2_000));
        assert!(b < a);
        assert_eq!(a.created_at(), Ts(1_000));
        assert!(VersionId::seek_at(Ts(1_000)) <= a);
        assert!(VersionId::seek_at(Ts(1_500)) > b);
        let s = a.to_string();
        assert_eq!(s.len(), 40);
        assert_eq!(s.parse::<VersionId>().unwrap(), a);
        assert!("null".parse::<VersionId>().is_err());
    }

    #[test]
    fn bucket_and_blob_ids() {
        let id = BucketId::random();
        assert_eq!(BucketId::from_bytes(id.to_bytes()), id);
        assert_eq!(id.to_string().parse::<BucketId>().unwrap(), id);
        let b = BlobId([7; 32]);
        assert_eq!(b.to_hex().parse::<BlobId>().unwrap(), b);
    }
}
