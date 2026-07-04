//! Wire types: [`Envelope`] and [`HybridSignature`].

use crate::constants::*;
use crate::error::{Error, Result};
use crate::wire::{read_header, take, write_header};

/// An encrypted message: hybrid KEM ciphertext plus AEAD-protected payload.
///
/// Wire layout (`QSE2`):
///
/// ```text
/// magic[4] | version u8 | suite u8 | epk_x25519[32] | ct_mlkem[1568] | nonce[12] | aead_ct[..]
/// ```
///
/// Everything before `aead_ct` is authenticated as AEAD associated data, so
/// no header field can be modified without failing decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Sender's ephemeral X25519 public key.
    pub(crate) epk_x25519: [u8; X25519_PK_LEN],
    /// ML-KEM-1024 ciphertext.
    pub(crate) ct_mlkem: Box<[u8; MLKEM1024_CT_LEN]>,
    /// AES-256-GCM nonce.
    pub(crate) nonce: [u8; NONCE_LEN],
    /// AES-256-GCM ciphertext (plaintext length + 16-byte tag).
    pub(crate) ciphertext: Vec<u8>,
}

impl Envelope {
    /// Serialize to the v2 envelope format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_AAD_LEN + self.ciphertext.len());
        self.write_aad(&mut out);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Write the authenticated prefix (header through nonce) to `out`.
    pub(crate) fn write_aad(&self, out: &mut Vec<u8>) {
        let start = out.len();
        write_header(out, MAGIC_ENVELOPE);
        out.extend_from_slice(&self.epk_x25519);
        out.extend_from_slice(self.ct_mlkem.as_ref());
        out.extend_from_slice(&self.nonce);
        debug_assert_eq!(out.len() - start, ENVELOPE_AAD_LEN);
    }

    /// Parse a v2 envelope.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEnvelope`] on malformed input,
    /// [`Error::LegacyV1Artifact`] for 0.1.x JSON artifacts, and
    /// version/suite errors for unknown formats.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut rest = read_header(bytes, MAGIC_ENVELOPE, Error::InvalidEnvelope)?;
        let epk_x25519 = take(&mut rest, Error::InvalidEnvelope)?;
        let ct_mlkem: [u8; MLKEM1024_CT_LEN] = take(&mut rest, Error::InvalidEnvelope)?;
        let nonce = take(&mut rest, Error::InvalidEnvelope)?;
        if rest.len() < TAG_LEN {
            return Err(Error::InvalidEnvelope);
        }
        Ok(Self {
            epk_x25519,
            ct_mlkem: Box::new(ct_mlkem),
            nonce,
            ciphertext: rest.to_vec(),
        })
    }
}

/// A hybrid signature: Ed25519 and ML-DSA-87, both always present.
///
/// Wire layout (`QSS2`, fixed 4697 bytes):
///
/// ```text
/// magic[4] | version u8 | suite u8 | ed25519_sig[64] | mldsa_sig[4627]
/// ```
///
/// Verification requires **both** components to be valid; there is no way to
/// strip the post-quantum signature and still verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 signature over the framed message.
    pub(crate) ed25519: [u8; ED25519_SIG_LEN],
    /// ML-DSA-87 signature over the framed message.
    pub(crate) mldsa: Box<[u8; MLDSA87_SIG_LEN]>,
}

impl HybridSignature {
    /// Serialize to the v2 signature format (fixed 4697 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        write_header(&mut out, MAGIC_SIGNATURE);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(self.mldsa.as_ref());
        debug_assert_eq!(out.len(), SIGNATURE_LEN);
        out
    }

    /// Parse a v2 signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] on malformed input,
    /// [`Error::LegacyV1Artifact`] for 0.1.x JSON artifacts, and
    /// version/suite errors for unknown formats.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut rest = read_header(bytes, MAGIC_SIGNATURE, Error::InvalidSignature)?;
        let ed25519 = take(&mut rest, Error::InvalidSignature)?;
        let mldsa: [u8; MLDSA87_SIG_LEN] = take(&mut rest, Error::InvalidSignature)?;
        if !rest.is_empty() {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            ed25519,
            mldsa: Box::new(mldsa),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_envelope() -> Envelope {
        Envelope {
            epk_x25519: [1; X25519_PK_LEN],
            ct_mlkem: Box::new([2; MLKEM1024_CT_LEN]),
            nonce: [3; NONCE_LEN],
            ciphertext: vec![4; 40],
        }
    }

    #[test]
    fn envelope_roundtrip() {
        let env = dummy_envelope();
        let bytes = env.to_bytes();
        assert_eq!(bytes.len(), ENVELOPE_AAD_LEN + 40);
        assert_eq!(Envelope::from_bytes(&bytes).unwrap(), env);
    }

    #[test]
    fn envelope_rejects_truncation() {
        let bytes = dummy_envelope().to_bytes();
        // Anything shorter than AAD + tag must fail.
        for len in [
            0,
            5,
            HEADER_LEN,
            ENVELOPE_AAD_LEN,
            ENVELOPE_AAD_LEN + TAG_LEN - 1,
        ] {
            assert!(Envelope::from_bytes(&bytes[..len]).is_err(), "len={len}");
        }
    }

    #[test]
    fn signature_roundtrip() {
        let sig = HybridSignature {
            ed25519: [5; ED25519_SIG_LEN],
            mldsa: Box::new([6; MLDSA87_SIG_LEN]),
        };
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), SIGNATURE_LEN);
        assert_eq!(HybridSignature::from_bytes(&bytes).unwrap(), sig);
    }

    #[test]
    fn signature_rejects_wrong_length() {
        let sig = HybridSignature {
            ed25519: [5; ED25519_SIG_LEN],
            mldsa: Box::new([6; MLDSA87_SIG_LEN]),
        };
        let bytes = sig.to_bytes();
        assert_eq!(
            HybridSignature::from_bytes(&bytes[..bytes.len() - 1]).unwrap_err(),
            Error::InvalidSignature
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            HybridSignature::from_bytes(&long).unwrap_err(),
            Error::InvalidSignature
        );
    }
}
