//! Streaming authenticated encryption (`QST2`) for payloads too large to hold
//! in memory or to seal in one shot (over [`MAX_PLAINTEXT_LEN`]).
//!
//! One hybrid KEM run (X25519 + ML-KEM-1024) derives a single AES-256-GCM key;
//! the payload is then encrypted in fixed-size chunks using the STREAM
//! construction (Rogaway/Hoang online authenticated encryption):
//!
//! - The 12-byte per-chunk nonce is `prefix (7) || u32 chunk index || last (1)`.
//! - Each chunk's associated data is `stream_header || u32 index || last`,
//!   binding the chunk to its position and to the one-time header, so
//!   reordering, duplicating, dropping, or truncating chunks fails.
//! - The final chunk sets the last-flag to 1. A stream that never presents a
//!   last chunk is [`Error::StreamTruncated`] at [`StreamOpener::finish`].
//!
//! Chunks are [`STREAM_CHUNK_SIZE`] (64 KiB) of plaintext each; the `u32`
//! counter allows up to 2^32 chunks (256 TiB) before rejection.
//!
//! ```
//! use quantum_shield::{HybridCrypto, StreamSealer};
//! # fn run() -> quantum_shield::Result<()> {
//! let bob = HybridCrypto::generate()?;
//! let (mut sealer, header) = StreamSealer::new(bob.public_keys())?;
//! let c1 = sealer.seal_chunk(b"first part ", false)?;
//! let c2 = sealer.seal_chunk(b"second part", true)?;
//!
//! let mut opener = bob.stream_opener(&header)?;
//! let mut out = Vec::new();
//! out.extend(opener.open_chunk(&c1)?.0);
//! out.extend(opener.open_chunk(&c2)?.0);
//! opener.finish()?;
//! assert_eq!(out, b"first part second part");
//! # Ok(()) }
//! ```

use crate::constants::*;
use crate::error::{Error, Result};
use crate::hybrid_kem::{self, KemCiphertext};
use crate::keys::{KeyPair, PublicKeyBundle};
use crate::wire::{read_header, take, write_header};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// Assemble the 12-byte chunk nonce: `prefix || u32 index || last-flag`.
fn chunk_nonce(prefix: &[u8; STREAM_NONCE_PREFIX_LEN], index: u32, last: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..STREAM_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[STREAM_NONCE_PREFIX_LEN..STREAM_NONCE_PREFIX_LEN + 4]
        .copy_from_slice(&index.to_be_bytes());
    nonce[NONCE_LEN - 1] = last as u8;
    nonce
}

/// Per-chunk associated data: `stream_header || u32 index || last-flag`.
fn chunk_aad(header: &[u8], index: u32, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 5);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(last as u8);
    aad
}

/// Encrypts a payload as a sequence of independently authenticated chunks.
pub struct StreamSealer {
    cipher: Aes256Gcm,
    nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    header: Vec<u8>,
    index: u32,
    finished: bool,
}

impl StreamSealer {
    /// Begin a stream to `recipient`. Returns the sealer and the header bytes
    /// (`QST2`) that must be written before the chunks.
    ///
    /// # Errors
    ///
    /// [`Error::RandomnessUnavailable`] if the OS RNG fails.
    pub fn new(recipient: &PublicKeyBundle) -> Result<(Self, Vec<u8>)> {
        let (kem_ct, ss) = hybrid_kem::encapsulate(recipient)?;
        let mut nonce_prefix = [0u8; STREAM_NONCE_PREFIX_LEN];
        getrandom::fill(&mut nonce_prefix).map_err(|_| Error::RandomnessUnavailable)?;

        let mut header = Vec::with_capacity(STREAM_HEADER_LEN);
        write_header(&mut header, MAGIC_STREAM);
        header.extend_from_slice(&kem_ct.epk_x25519);
        header.extend_from_slice(kem_ct.ct_mlkem.as_ref());
        header.extend_from_slice(&nonce_prefix);

        let cipher = Aes256Gcm::new((&*ss).into());
        Ok((
            Self {
                cipher,
                nonce_prefix,
                header: header.clone(),
                index: 0,
                finished: false,
            },
            header,
        ))
    }

    /// Encrypt one chunk. Set `last` on the final chunk. Returns the framed
    /// chunk bytes to write.
    ///
    /// # Errors
    ///
    /// [`Error::StreamFinished`] if called after a `last` chunk or once the
    /// 2^32-chunk limit is reached; [`Error::MessageTooLarge`] if a single
    /// chunk's ciphertext would exceed the 32-bit frame length.
    pub fn seal_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::StreamFinished);
        }
        // Refuse a non-final chunk at the maximum index *before* encrypting, so
        // the next call can never reuse the index/nonce. (A final chunk at the
        // maximum index is fine — the stream ends there.)
        if !last && self.index == u32::MAX {
            self.finished = true;
            return Err(Error::StreamFinished);
        }
        // Bound the per-chunk ciphertext to the 32-bit frame length field.
        if plaintext.len() > (u32::MAX as usize - TAG_LEN) {
            return Err(Error::MessageTooLarge {
                len: plaintext.len(),
                max: u32::MAX as usize - TAG_LEN,
            });
        }

        let nonce = chunk_nonce(&self.nonce_prefix, self.index, last);
        let aad = chunk_aad(&self.header, self.index, last);
        let ct = self
            .cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::MessageTooLarge {
                len: plaintext.len(),
                max: u32::MAX as usize - TAG_LEN,
            })?;

        // Frame: last(1) || u32_be ct_len || ct.
        let mut frame = Vec::with_capacity(5 + ct.len());
        frame.push(last as u8);
        frame.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        frame.extend_from_slice(&ct);

        if last {
            self.finished = true;
        } else {
            // Safe: guarded above that index < u32::MAX for non-final chunks.
            self.index += 1;
        }
        Ok(frame)
    }
}

/// Decrypts a stream produced by [`StreamSealer`], one chunk at a time.
///
/// **You must call [`finish`](StreamOpener::finish) after the last chunk.**
/// Per-chunk authentication catches reordering, duplication, and corruption,
/// but *truncation* — an attacker dropping the trailing chunks, including the
/// final one — is only detected by `finish`, which fails with
/// [`Error::StreamTruncated`] if it never saw a chunk marked `last`. A consumer
/// that just loops `open_chunk` until its input is exhausted and skips `finish`
/// will silently accept a truncated stream.
pub struct StreamOpener {
    cipher: Aes256Gcm,
    nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    header: Vec<u8>,
    index: u32,
    finished: bool,
}

impl StreamOpener {
    /// Begin decrypting from the stream header bytes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEnvelope`] if the header is malformed;
    /// version/suite errors for other formats.
    pub fn new(keypair: &KeyPair, header_bytes: &[u8]) -> Result<Self> {
        let mut rest = read_header(header_bytes, MAGIC_STREAM, Error::InvalidEnvelope)?;
        let epk_x25519: [u8; X25519_PK_LEN] = take(&mut rest, Error::InvalidEnvelope)?;
        let ct_mlkem: [u8; MLKEM1024_CT_LEN] = take(&mut rest, Error::InvalidEnvelope)?;
        let nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN] = take(&mut rest, Error::InvalidEnvelope)?;
        if !rest.is_empty() {
            return Err(Error::InvalidEnvelope);
        }

        let kem_ct = KemCiphertext {
            epk_x25519,
            ct_mlkem: alloc::boxed::Box::new(ct_mlkem),
        };
        let ss: Zeroizing<[u8; 32]> = hybrid_kem::decapsulate(keypair, &kem_ct);
        let cipher = Aes256Gcm::new((&*ss).into());

        Ok(Self {
            cipher,
            nonce_prefix,
            header: header_bytes.to_vec(),
            index: 0,
            finished: false,
        })
    }

    /// Decrypt one chunk frame. Returns `(plaintext, was_last)`.
    ///
    /// # Errors
    ///
    /// [`Error::DecryptionFailed`] on any authentication failure (including a
    /// reordered, duplicated, or spliced chunk); [`Error::StreamFinished`] if
    /// called after the last chunk.
    pub fn open_chunk(&mut self, frame: &[u8]) -> Result<(Vec<u8>, bool)> {
        if self.finished {
            return Err(Error::StreamFinished);
        }
        if frame.len() < 5 {
            return Err(Error::DecryptionFailed);
        }
        let last = match frame[0] {
            0 => false,
            1 => true,
            _ => return Err(Error::DecryptionFailed),
        };
        let ct_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        let ct = &frame[5..];
        if ct.len() != ct_len || ct_len < TAG_LEN {
            return Err(Error::DecryptionFailed);
        }

        let nonce = chunk_nonce(&self.nonce_prefix, self.index, last);
        let aad = chunk_aad(&self.header, self.index, last);
        let plaintext = self
            .cipher
            .decrypt((&nonce).into(), Payload { msg: ct, aad: &aad })
            .map_err(|_| Error::DecryptionFailed)?;

        if last {
            self.finished = true;
        } else {
            self.index = self.index.checked_add(1).ok_or(Error::DecryptionFailed)?;
        }
        Ok((plaintext, last))
    }

    /// Confirm the stream ended with a final chunk.
    ///
    /// # Errors
    ///
    /// [`Error::StreamTruncated`] if no `last` chunk was ever seen.
    pub fn finish(self) -> Result<()> {
        if self.finished {
            Ok(())
        } else {
            Err(Error::StreamTruncated)
        }
    }
}
