//! Per-component PEM export/import of public keys (`pem` feature).
//!
//! ML-KEM-1024, ML-DSA-87, and Ed25519 public keys are emitted as standard
//! `SubjectPublicKeyInfo` PEM ("PUBLIC KEY") blocks via each crate's native
//! support. X25519 has no PKCS#8/SPKI support upstream, so it is emitted as a
//! raw block ("X25519 PUBLIC KEY") holding the 32 raw public-key bytes.
//!
//! The document is the four blocks concatenated in a fixed order
//! (X25519, ML-KEM, ML-DSA, Ed25519). This is an interop convenience — the
//! compact [`PublicKeyBundle::to_bytes`](crate::PublicKeyBundle::to_bytes)
//! (`QSP2`) remains the primary, validated key format, and `from_pem`
//! round-trips through it so parsing enforces exactly the same checks.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::keys::PublicKeyBundle;
use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::pkcs8::{DecodePublicKey as _, EncodePublicKey as _};
use ml_dsa::{KeyExport as _, MlDsa87};
use ml_kem::pkcs8::{DecodePublicKey as _, EncodePublicKey as _};
use ml_kem::EncapsulationKey1024;

const X25519_PEM_LABEL: &str = "X25519 PUBLIC KEY";

impl PublicKeyBundle {
    /// Serialize the public keys as a concatenated multi-PEM document.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if any component fails to PEM-encode
    /// (not expected for a valid bundle).
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    pub fn to_pem(&self) -> Result<String> {
        let x25519 = pem_rfc7468::encode_string(
            X25519_PEM_LABEL,
            pem_rfc7468::LineEnding::LF,
            self.x25519.as_bytes(),
        )
        .map_err(|_| Error::InvalidKey)?;

        let mlkem = self
            .mlkem
            .to_public_key_pem(Default::default())
            .map_err(|_| Error::InvalidKey)?;
        let mldsa = self
            .mldsa
            .to_public_key_pem(Default::default())
            .map_err(|_| Error::InvalidKey)?;
        let ed25519 = self
            .ed25519
            .to_public_key_pem(Default::default())
            .map_err(|_| Error::InvalidKey)?;

        let mut out =
            String::with_capacity(x25519.len() + mlkem.len() + mldsa.len() + ed25519.len());
        out.push_str(&x25519);
        out.push_str(&mlkem);
        out.push_str(&mldsa);
        out.push_str(&ed25519);
        Ok(out)
    }

    /// Parse a public-key bundle from a [`PublicKeyBundle::to_pem`] document.
    ///
    /// The four blocks must appear in order (X25519, ML-KEM, ML-DSA, Ed25519).
    /// Every component is validated (the result round-trips through the
    /// canonical `QSP2` parser).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] on any malformed block, wrong count,
    /// wrong order, or component that fails validation.
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    pub fn from_pem(pem: &str) -> Result<Self> {
        let blocks = split_pem_blocks(pem);
        if blocks.len() != 4 {
            return Err(Error::InvalidKey);
        }

        // Block 0: X25519 raw block.
        let (label, x25519_der) =
            pem_rfc7468::decode_vec(blocks[0].as_bytes()).map_err(|_| Error::InvalidKey)?;
        if label != X25519_PEM_LABEL || x25519_der.len() != X25519_PK_LEN {
            return Err(Error::InvalidKey);
        }

        // Blocks 1-3: standard SPKI, parsed by their respective crates.
        let mlkem =
            EncapsulationKey1024::from_public_key_pem(&blocks[1]).map_err(|_| Error::InvalidKey)?;
        let mldsa = ml_dsa::VerifyingKey::<MlDsa87>::from_public_key_pem(&blocks[2])
            .map_err(|_| Error::InvalidKey)?;
        let ed25519 = ed25519_dalek::VerifyingKey::from_public_key_pem(&blocks[3])
            .map_err(|_| Error::InvalidKey)?;

        // Reassemble the canonical QSP2 bytes and reuse its validated parser,
        // so PEM import enforces exactly the same checks as `from_bytes`.
        let mut bytes = Vec::with_capacity(PUBLIC_BUNDLE_LEN);
        bytes.extend_from_slice(&MAGIC_PUBLIC_BUNDLE);
        bytes.push(WIRE_VERSION);
        bytes.push(SUITE_ID);
        bytes.extend_from_slice(&x25519_der);
        bytes.extend_from_slice(&mlkem.to_bytes());
        bytes.extend_from_slice(&ed25519.to_bytes());
        bytes.extend_from_slice(&mldsa.encode());
        Self::from_bytes(&bytes)
    }
}

/// Split a concatenated PEM document into its constituent block strings,
/// each a complete `-----BEGIN…-----END-----` unit.
fn split_pem_blocks(pem: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() && current.is_empty() {
            continue;
        }
        current.push_str(trimmed);
        current.push('\n');
        if trimmed.starts_with("-----END") {
            blocks.push(core::mem::take(&mut current));
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use crate::HybridCrypto;
    use crate::PublicKeyBundle;

    #[test]
    fn pem_roundtrip() {
        let kp = HybridCrypto::generate().unwrap();
        let pem = kp.public_keys().to_pem().unwrap();
        assert!(pem.contains("BEGIN X25519 PUBLIC KEY"));
        assert!(pem.contains("BEGIN PUBLIC KEY"));
        let parsed = PublicKeyBundle::from_pem(&pem).unwrap();
        assert_eq!(&parsed, kp.public_keys());
    }

    #[test]
    fn rejects_wrong_block_count() {
        let kp = HybridCrypto::generate().unwrap();
        let pem = kp.public_keys().to_pem().unwrap();
        // Drop the last block (Ed25519).
        let cut = pem.rfind("-----BEGIN PUBLIC KEY").unwrap();
        assert!(PublicKeyBundle::from_pem(&pem[..cut]).is_err());
    }

    #[test]
    fn rejects_reordered_blocks() {
        let kp = HybridCrypto::generate().unwrap();
        let pem = kp.public_keys().to_pem().unwrap();
        let blocks = super::split_pem_blocks(&pem);
        // Swap ML-KEM and Ed25519 (blocks 1 and 3): SPKI parse mismatches.
        let reordered = alloc::format!("{}{}{}{}", blocks[0], blocks[3], blocks[2], blocks[1]);
        assert!(PublicKeyBundle::from_pem(&reordered).is_err());
    }

    #[test]
    fn tampered_x25519_yields_different_key() {
        use alloc::string::String;
        let kp = HybridCrypto::generate().unwrap();
        let pem = kp.public_keys().to_pem().unwrap();
        // Flip one base64 char on the first body line of the X25519 block.
        // X25519 has no point validation — every 32-byte string is a valid
        // u-coordinate — so this parses to a *different* bundle, not an error.
        let body = pem.find('\n').unwrap() + 1;
        let tampered: String = pem
            .char_indices()
            .map(|(i, c)| if i == body { flip(c) } else { c })
            .collect();
        // Err is also acceptable (e.g. if base64 became invalid); a successful
        // parse must at least differ from the original.
        if let Ok(parsed) = PublicKeyBundle::from_pem(&tampered) {
            assert_ne!(&parsed, kp.public_keys());
        }
    }

    fn flip(c: char) -> char {
        match c {
            'A'..='Y' | 'a'..='y' | '0'..='8' => ((c as u8) + 1) as char,
            _ => 'A',
        }
    }
}
