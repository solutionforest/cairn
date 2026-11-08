//! Secret handling: zeroizing strings, AES-256-GCM at-rest encryption, random generation.

use crate::error::AuthError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A secret string that is zeroed on drop and never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a secret.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// Reveal the secret (for signing / handing to s3s).
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// Constant-time comparison.
    pub fn ct_eq(&self, other: &str) -> bool {
        self.0.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// 32-byte master key used to encrypt secrets at rest.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// From raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// A fresh random key.
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        rand::rng().fill_bytes(&mut b);
        Self(b)
    }
    /// Key check value: first 8 bytes of SHA-256("cairn-kcv" ‖ key), for detecting a wrong key.
    pub fn check_value(&self) -> [u8; 8] {
        use sha2::Digest;
        let d = sha2::Sha256::new().chain_update(b"cairn-kcv").chain_update(self.0).finalize();
        let mut o = [0u8; 8];
        o.copy_from_slice(&d[..8]);
        o
    }

    /// Encrypt `plain`, binding it to `aad` (the record key).
    pub fn seal(&self, plain: &[u8], aad: &[u8]) -> Result<Sealed, AuthError> {
        let cipher = Aes256Gcm::new_from_slice(&self.0).map_err(|_| AuthError::Crypto)?;
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad })
            .map_err(|_| AuthError::Crypto)?;
        Ok(Sealed { nonce, ct })
    }

    /// Decrypt a [`Sealed`] value.
    pub fn open(&self, s: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        let cipher = Aes256Gcm::new_from_slice(&self.0).map_err(|_| AuthError::Crypto)?;
        cipher
            .decrypt(Nonce::from_slice(&s.nonce), Payload { msg: &s.ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| AuthError::Crypto)
    }

    /// Seal a secret string.
    pub fn seal_secret(&self, s: &SecretString, aad: &[u8]) -> Result<Sealed, AuthError> {
        self.seal(s.expose().as_bytes(), aad)
    }

    /// Open into a secret string.
    pub fn open_secret(&self, s: &Sealed, aad: &[u8]) -> Result<SecretString, AuthError> {
        let p = self.open(s, aad)?;
        let st = std::str::from_utf8(&p).map_err(|_| AuthError::Crypto)?;
        Ok(SecretString::new(st))
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// AES-256-GCM ciphertext with its nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// 96-bit random nonce.
    pub nonce: [u8; 12],
    /// Ciphertext ‖ tag.
    pub ct: Vec<u8>,
}

const AKID_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// New access key id: `CAIRN` + 15 chars of base32 (20 chars total).
pub fn generate_access_key_id() -> String {
    let mut rng = rand::rng();
    let mut s = String::with_capacity(20);
    s.push_str("CAIRN");
    for _ in 0..15 {
        s.push(AKID_ALPHABET[rng.random_range(0..AKID_ALPHABET.len())] as char);
    }
    s
}

/// New secret access key: 40 chars of base64url (30 random bytes).
pub fn generate_secret_key() -> SecretString {
    let mut b = Zeroizing::new([0u8; 30]);
    rand::rng().fill_bytes(b.as_mut());
    SecretString::new(URL_SAFE_NO_PAD.encode(b.as_ref()))
}

/// New session token: 48 random bytes, base64url (64 chars).
pub fn generate_session_token() -> SecretString {
    let mut b = Zeroizing::new([0u8; 48]);
    rand::rng().fill_bytes(b.as_mut());
    SecretString::new(URL_SAFE_NO_PAD.encode(b.as_ref()))
}

/// Random unique id with a prefix (e.g. `AIDA` users, `AROA` roles), 21 chars total.
pub fn generate_unique_id(prefix: &str) -> String {
    let mut rng = rand::rng();
    let mut s = prefix.to_string();
    while s.len() < 21 {
        s.push(AKID_ALPHABET[rng.random_range(0..AKID_ALPHABET.len())] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_shapes() {
        let id = generate_access_key_id();
        assert_eq!(id.len(), 20);
        assert!(id.starts_with("CAIRN"));
        assert!(id.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
        let s = generate_secret_key();
        assert_eq!(s.expose().len(), 40);
        assert!(s.expose().bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(generate_secret_key(), s);
        assert!(generate_session_token().expose().len() >= 43);
    }

    #[test]
    fn seal_roundtrip_and_tamper() {
        let k = MasterKey::new([7; 32]);
        let sec = SecretString::new("hunter2");
        let sealed = k.seal_secret(&sec, b"k/AK").unwrap();
        assert!(!sealed.ct.windows(7).any(|w| w == b"hunter2"));
        assert_eq!(k.open_secret(&sealed, b"k/AK").unwrap(), sec);
        assert!(matches!(k.open_secret(&sealed, b"k/OTHER"), Err(AuthError::Crypto)));
        assert!(MasterKey::new([8; 32]).open_secret(&sealed, b"k/AK").is_err());
        let mut bad = sealed.clone();
        bad.ct[0] ^= 1;
        assert!(k.open_secret(&bad, b"k/AK").is_err());
        assert_ne!(k.check_value(), MasterKey::new([8; 32]).check_value());
    }

    #[test]
    fn debug_redacts() {
        let s = SecretString::new("topsecret");
        assert!(!format!("{s:?}").contains("topsecret"));
        assert!(!format!("{:?}", MasterKey::new([1; 32])).contains('1'));
        assert!(s.ct_eq("topsecret") && !s.ct_eq("topsecreT"));
    }
}
