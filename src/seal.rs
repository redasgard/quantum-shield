//! Authenticated hybrid encryption: [`seal`] and [`open`].

use crate::constants::*;
use crate::error::{Error, Result};
use crate::hybrid_kem::{self, KemCiphertext};
use crate::keys::{KeyPair, PublicKeyBundle};
use crate::types::Envelope;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};

/// Encrypt `plaintext` for `recipient`.
///
/// A fresh hybrid KEM (X25519 + ML-KEM-1024) run derives a one-time
/// AES-256-GCM key; the entire envelope header (format version, suite,
/// both KEM components, and nonce) is bound into the authentication tag
/// as associated data.
///
/// # Errors
///
/// Returns [`Error::MessageTooLarge`] for plaintexts over
/// [`MAX_PLAINTEXT_LEN`] and [`Error::RandomnessUnavailable`] if the OS RNG
/// fails.
pub fn seal(plaintext: &[u8], recipient: &PublicKeyBundle) -> Result<Envelope> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(Error::MessageTooLarge {
            len: plaintext.len(),
            max: MAX_PLAINTEXT_LEN,
        });
    }

    let (kem_ct, ss) = hybrid_kem::encapsulate(recipient)?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    // Envelope with empty ciphertext: gives us the exact AAD prefix.
    let mut envelope = Envelope {
        epk_x25519: kem_ct.epk_x25519,
        ct_mlkem: kem_ct.ct_mlkem,
        nonce,
        ciphertext: Vec::new(),
    };
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_LEN);
    envelope.write_aad(&mut aad);

    let cipher = Aes256Gcm::new((&*ss).into());
    envelope.ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::MessageTooLarge {
            len: plaintext.len(),
            max: MAX_PLAINTEXT_LEN,
        })?;

    Ok(envelope)
}

/// Decrypt an [`Envelope`] with `keypair`.
///
/// # Errors
///
/// Returns [`Error::DecryptionFailed`] for *any* cryptographic failure —
/// wrong recipient, tampered header, tampered ciphertext — with no further
/// detail, by design.
pub fn open(keypair: &KeyPair, envelope: &Envelope) -> Result<Vec<u8>> {
    let kem_ct = KemCiphertext {
        epk_x25519: envelope.epk_x25519,
        ct_mlkem: envelope.ct_mlkem.clone(),
    };
    let ss = hybrid_kem::decapsulate(keypair, &kem_ct);

    let mut aad = Vec::with_capacity(ENVELOPE_AAD_LEN);
    envelope.write_aad(&mut aad);

    let cipher = Aes256Gcm::new((&*ss).into());
    cipher
        .decrypt(
            (&envelope.nonce).into(),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let msg = b"attack at dawn";
        let env = seal(msg, kp.public_keys()).unwrap();
        assert_eq!(open(&kp, &env).unwrap(), msg);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let env = seal(b"", kp.public_keys()).unwrap();
        assert_eq!(open(&kp, &env).unwrap(), b"");
    }

    #[test]
    fn wrong_recipient_fails() {
        let alice = KeyPair::generate().unwrap();
        let mallory = KeyPair::generate().unwrap();
        let env = seal(b"secret", alice.public_keys()).unwrap();
        assert_eq!(open(&mallory, &env).unwrap_err(), Error::DecryptionFailed);
    }

    #[test]
    fn oversized_plaintext_rejected() {
        let kp = KeyPair::generate().unwrap();
        let big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        assert!(matches!(
            seal(&big, kp.public_keys()).unwrap_err(),
            Error::MessageTooLarge { .. }
        ));
    }
}
