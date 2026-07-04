//! Multi-recipient envelopes (`QSM2`).
//!
//! The payload is encrypted once under a random content-encryption key (CEK);
//! the CEK is then wrapped separately for each recipient using that
//! recipient's **full hybrid** shared secret (X25519 + ML-KEM-1024, via
//! [`hybrid_kem::encapsulate`]). This is *not* the v1 OR-flaw: every wrap is
//! itself a hybrid KEM, and the CEK is uniformly random, so breaking one
//! recipient's classical or post-quantum key alone reveals nothing.
//!
//! ## Binding
//!
//! - Each wrap's AEAD binds `header || recipient_count` as associated data,
//!   so a wrap cannot be lifted into an envelope with a different recipient
//!   count or format.
//! - The payload AEAD binds the **entire prefix** (header, count, the CEK
//!   commitment, *all* wraps, and the payload nonce). Adding, removing,
//!   reordering, or duplicating any wrap changes the payload tag, so tampering
//!   fails as a uniform [`Error::DecryptionFailed`].
//! - A `SHA3-256(CEK)` commitment is carried in the envelope and checked by
//!   every recipient against the CEK they recovered. AES-GCM is not
//!   key-committing, so without this a malicious sender could wrap *different*
//!   CEKs to different recipients and craft one payload that decrypts to
//!   different plaintexts per recipient; the commitment forecloses that.
//!
//! ## Opening
//!
//! [`open_multi`] trial-decrypts every wrap with no recipient identifier on
//! the wire — an envelope reveals nothing about who its recipients are. The
//! cost is one hybrid decapsulation per wrap; [`MAX_RECIPIENTS`] bounds it,
//! enforced at both seal and parse time.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::hybrid_kem::{self, KemCiphertext};
use crate::keys::{KeyPair, PublicKeyBundle};
use crate::wire::{read_header, take, write_header};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use alloc::boxed::Box;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Commit to a CEK: `SHA3-256(label || cek)`. Recipients check that the CEK
/// they recovered matches the single committed value, which stops a malicious
/// sender from wrapping different CEKs to different recipients (AES-GCM is not
/// key-committing).
fn cek_commitment(cek: &[u8; CEK_LEN]) -> [u8; CEK_COMMIT_LEN] {
    let mut hasher = Sha3_256::new();
    hasher.update(MULTI_CEK_COMMIT_LABEL);
    hasher.update(cek);
    hasher.finalize().into()
}

/// A CEK wrapped for one recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Wrap {
    epk_x25519: [u8; X25519_PK_LEN],
    ct_mlkem: Box<[u8; MLKEM1024_CT_LEN]>,
    wrap_nonce: [u8; NONCE_LEN],
    wrapped_cek: [u8; CEK_LEN + TAG_LEN],
}

/// An encrypted message addressed to one or more recipients.
///
/// Wire layout (`QSM2`):
///
/// ```text
/// header[6] | recipient_count: u16_be | wrap[0..n] | payload_nonce[12] | payload_ct[..]
/// wrap = epk_x25519[32] | ct_mlkem[1568] | wrap_nonce[12] | wrapped_cek[48]
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiRecipientEnvelope {
    /// `SHA3-256(label || CEK)` — every recipient checks their recovered CEK
    /// against this, preventing sender equivocation.
    cek_commitment: [u8; CEK_COMMIT_LEN],
    wraps: Vec<Wrap>,
    payload_nonce: [u8; NONCE_LEN],
    payload_ct: Vec<u8>,
}

impl MultiRecipientEnvelope {
    /// Number of recipient wraps in this envelope.
    pub fn recipient_count(&self) -> usize {
        self.wraps.len()
    }

    /// The authenticated prefix (header through payload nonce), used as the
    /// payload AEAD associated data.
    fn write_prefix(&self, out: &mut Vec<u8>) {
        debug_assert!(self.wraps.len() <= MAX_RECIPIENTS);
        write_header(out, MAGIC_MULTI);
        out.extend_from_slice(&(self.wraps.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.cek_commitment);
        for wrap in &self.wraps {
            out.extend_from_slice(&wrap.epk_x25519);
            out.extend_from_slice(wrap.ct_mlkem.as_ref());
            out.extend_from_slice(&wrap.wrap_nonce);
            out.extend_from_slice(&wrap.wrapped_cek);
        }
        out.extend_from_slice(&self.payload_nonce);
    }

    /// Serialize to the `QSM2` wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            HEADER_LEN
                + 2
                + CEK_COMMIT_LEN
                + self.wraps.len() * WRAP_LEN
                + NONCE_LEN
                + self.payload_ct.len(),
        );
        self.write_prefix(&mut out);
        out.extend_from_slice(&self.payload_ct);
        out
    }

    /// Parse a `QSM2` envelope.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEnvelope`] on malformed input,
    /// [`Error::TooManyRecipients`] / [`Error::NoRecipients`] on an
    /// out-of-range count, and version/suite errors for other formats.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut rest = read_header(bytes, MAGIC_MULTI, Error::InvalidEnvelope)?;

        let count_bytes: [u8; 2] = take(&mut rest, Error::InvalidEnvelope)?;
        let count = u16::from_be_bytes(count_bytes) as usize;
        if count == 0 {
            return Err(Error::NoRecipients);
        }
        if count > MAX_RECIPIENTS {
            return Err(Error::TooManyRecipients {
                count,
                max: MAX_RECIPIENTS,
            });
        }

        let cek_commitment = take(&mut rest, Error::InvalidEnvelope)?;

        let mut wraps = Vec::with_capacity(count);
        for _ in 0..count {
            let epk_x25519 = take(&mut rest, Error::InvalidEnvelope)?;
            let ct_mlkem: [u8; MLKEM1024_CT_LEN] = take(&mut rest, Error::InvalidEnvelope)?;
            let wrap_nonce = take(&mut rest, Error::InvalidEnvelope)?;
            let wrapped_cek = take(&mut rest, Error::InvalidEnvelope)?;
            wraps.push(Wrap {
                epk_x25519,
                ct_mlkem: Box::new(ct_mlkem),
                wrap_nonce,
                wrapped_cek,
            });
        }

        let payload_nonce = take(&mut rest, Error::InvalidEnvelope)?;
        if rest.len() < TAG_LEN {
            return Err(Error::InvalidEnvelope);
        }
        Ok(Self {
            cek_commitment,
            wraps,
            payload_nonce,
            payload_ct: rest.to_vec(),
        })
    }
}

/// The wrap-AEAD associated data: `header || recipient_count`.
fn wrap_aad(count: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + 2);
    write_header(&mut aad, MAGIC_MULTI);
    aad.extend_from_slice(&(count as u16).to_be_bytes());
    aad
}

/// Encrypt `plaintext` for every recipient in `recipients`.
///
/// # Errors
///
/// [`Error::NoRecipients`] for an empty list, [`Error::TooManyRecipients`]
/// past [`MAX_RECIPIENTS`], [`Error::MessageTooLarge`] past
/// [`MAX_PLAINTEXT_LEN`], and [`Error::RandomnessUnavailable`] on RNG failure.
pub fn seal_multi(
    plaintext: &[u8],
    recipients: &[&PublicKeyBundle],
) -> Result<MultiRecipientEnvelope> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }
    if recipients.len() > MAX_RECIPIENTS {
        return Err(Error::TooManyRecipients {
            count: recipients.len(),
            max: MAX_RECIPIENTS,
        });
    }
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(Error::MessageTooLarge {
            len: plaintext.len(),
            max: MAX_PLAINTEXT_LEN,
        });
    }

    let mut cek = Zeroizing::new([0u8; CEK_LEN]);
    getrandom::fill(cek.as_mut()).map_err(|_| Error::RandomnessUnavailable)?;

    let aad = wrap_aad(recipients.len());
    let mut wraps = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let (kem_ct, ss) = hybrid_kem::encapsulate(recipient)?;
        let cipher = Aes256Gcm::new((&*ss).into());
        let mut wrap_nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut wrap_nonce).map_err(|_| Error::RandomnessUnavailable)?;
        // Encrypting a fixed 32-byte CEK cannot fail (AES-GCM only errors far
        // past any real length), and its output is exactly CEK_LEN + TAG_LEN.
        let wrapped = cipher
            .encrypt(
                (&wrap_nonce).into(),
                Payload {
                    msg: &*cek,
                    aad: &aad,
                },
            )
            .expect("AES-GCM wrap of a 32-byte CEK is infallible");
        let wrapped_cek: [u8; CEK_LEN + TAG_LEN] = wrapped
            .try_into()
            .expect("AES-256-GCM output is plaintext length + 16-byte tag");
        wraps.push(Wrap {
            epk_x25519: kem_ct.epk_x25519,
            ct_mlkem: kem_ct.ct_mlkem,
            wrap_nonce,
            wrapped_cek,
        });
    }

    let mut payload_nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut payload_nonce).map_err(|_| Error::RandomnessUnavailable)?;

    let mut envelope = MultiRecipientEnvelope {
        cek_commitment: cek_commitment(&cek),
        wraps,
        payload_nonce,
        payload_ct: Vec::new(),
    };
    let mut payload_aad = Vec::new();
    envelope.write_prefix(&mut payload_aad);

    let cipher = Aes256Gcm::new((&*cek).into());
    envelope.payload_ct = cipher
        .encrypt(
            (&payload_nonce).into(),
            Payload {
                msg: plaintext,
                aad: &payload_aad,
            },
        )
        .map_err(|_| Error::MessageTooLarge {
            len: plaintext.len(),
            max: MAX_PLAINTEXT_LEN,
        })?;
    Ok(envelope)
}

/// Decrypt a multi-recipient envelope with `keypair`, if it is a recipient.
///
/// Every wrap is trial-decrypted; there is no per-recipient identifier on the
/// wire. Returns [`Error::DecryptionFailed`] uniformly if `keypair` is not a
/// recipient or the envelope was tampered with.
pub fn open_multi(keypair: &KeyPair, envelope: &MultiRecipientEnvelope) -> Result<Vec<u8>> {
    let aad = wrap_aad(envelope.wraps.len());
    let mut payload_aad = Vec::new();
    envelope.write_prefix(&mut payload_aad);

    for wrap in &envelope.wraps {
        let kem_ct = KemCiphertext {
            epk_x25519: wrap.epk_x25519,
            ct_mlkem: wrap.ct_mlkem.clone(),
        };
        let ss = hybrid_kem::decapsulate(keypair, &kem_ct);
        let cipher = Aes256Gcm::new((&*ss).into());
        let Ok(cek_vec) = cipher.decrypt(
            (&wrap.wrap_nonce).into(),
            Payload {
                msg: &wrap.wrapped_cek,
                aad: &aad,
            },
        ) else {
            continue;
        };

        let cek_vec = Zeroizing::new(cek_vec);
        let cek: Zeroizing<[u8; CEK_LEN]> = Zeroizing::new(
            cek_vec
                .as_slice()
                .try_into()
                .map_err(|_| Error::DecryptionFailed)?,
        );

        // Reject a sender who wrapped a different CEK than it committed to
        // (equivocation). Constant-time compare against the single commitment.
        let commit_ok: bool = cek_commitment(&cek).ct_eq(&envelope.cek_commitment).into();
        if !commit_ok {
            return Err(Error::DecryptionFailed);
        }

        let payload_cipher = Aes256Gcm::new((&*cek).into());
        return payload_cipher
            .decrypt(
                (&envelope.payload_nonce).into(),
                Payload {
                    msg: &envelope.payload_ct,
                    aad: &payload_aad,
                },
            )
            .map_err(|_| Error::DecryptionFailed);
    }
    Err(Error::DecryptionFailed)
}
