//! Key-rotation attestations (`QSR2`).
//!
//! When a keypair is rotated, the **old** keypair signs the **new** public
//! bundle, producing a [`RotationAttestation`] that gives verifiers a
//! cryptographic old → new link. Because it reuses the hybrid
//! [`sign`](crate::sign)/[`verify`](crate::verify), the attestation is itself
//! Ed25519 + ML-DSA — forging it requires breaking both.
//!
//! The signed message is `old_key_id (16) || epoch (u64) || new_public (QSP2)`
//! under the [`ROTATION_CONTEXT`] domain. The old bundle is **not** on the
//! wire: the verifier supplies the key it already trusts, so an attestation
//! can only be checked against an explicit trust anchor.
//!
//! ## Rollback protection is the caller's responsibility
//!
//! A [`RotationAttestation`] carries no clock and does not expire: every
//! attestation `old` ever produced verifies forever under `old`. If a key is
//! rotated more than once (`old→new1`, later `old→new2`), a captured `old→new1`
//! would otherwise let an attacker roll a verifier back to the superseded
//! `new1`. To prevent this, each attestation binds a caller-chosen monotonic
//! `epoch`; a verifier **must** remember the highest epoch it has accepted for
//! a given `old` and reject any attestation with a lower-or-equal epoch. The
//! library cannot enforce this itself (it holds no state), so it exposes the
//! epoch via [`RotationAttestation::epoch`].
//!
//! ```
//! use quantum_shield::{HybridCrypto, verify_rotation};
//! # fn run() -> quantum_shield::Result<()> {
//! let old = HybridCrypto::generate()?;
//! let new = HybridCrypto::generate()?;
//!
//! let attestation = old.attest_rotation(new.public_keys(), 1)?;
//! // A peer who trusts `old` learns the authentic new key:
//! let trusted_new = verify_rotation(old.public_keys(), &attestation)?;
//! assert_eq!(trusted_new, new.public_keys());
//! // ...and rejects it if its epoch does not advance past the last accepted one:
//! assert!(attestation.epoch() > 0);
//! # Ok(()) }
//! ```

use crate::constants::*;
use crate::error::{Error, Result};
use crate::keys::{KeyPair, PublicKeyBundle};
use crate::sign;
use crate::types::HybridSignature;
use crate::wire::{read_header, write_header};
use alloc::vec::Vec;

/// A signed statement that one keypair authorizes a successor public bundle at
/// a given epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationAttestation {
    epoch: u64,
    new_public: PublicKeyBundle,
    signature: HybridSignature,
}

impl RotationAttestation {
    /// The attested successor public bundle. Only trustworthy once the
    /// attestation has passed [`verify_rotation`].
    pub fn new_public(&self) -> &PublicKeyBundle {
        &self.new_public
    }

    /// The caller-chosen monotonic epoch bound into the signature. Verifiers
    /// must reject an attestation whose epoch does not advance past the last
    /// one they accepted for this signer (see the module docs on rollback).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Serialize to the `QSR2` wire format:
    /// `header[6] || epoch (u64_be, 8) || new_public (QSP2, 4230) || signature (QSS2, 4697)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 8 + PUBLIC_BUNDLE_LEN + SIGNATURE_LEN);
        write_header(&mut out, MAGIC_ROTATION);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.new_public.to_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    /// Parse a `QSR2` attestation.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSignature`] on malformed input; version/suite errors for
    /// other formats. The signature is not checked here — call
    /// [`verify_rotation`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let rest = read_header(bytes, MAGIC_ROTATION, Error::InvalidSignature)?;
        if rest.len() != 8 + PUBLIC_BUNDLE_LEN + SIGNATURE_LEN {
            return Err(Error::InvalidSignature);
        }
        let (epoch_bytes, rest) = rest.split_at(8);
        let epoch =
            u64::from_be_bytes(epoch_bytes.try_into().expect("split_at guarantees 8 bytes"));
        let (bundle_bytes, sig_bytes) = rest.split_at(PUBLIC_BUNDLE_LEN);
        let new_public = PublicKeyBundle::from_bytes(bundle_bytes)?;
        let signature = HybridSignature::from_bytes(sig_bytes)?;
        Ok(Self {
            epoch,
            new_public,
            signature,
        })
    }
}

/// The message signed by an attestation: `old_key_id || epoch || new_public`.
fn rotation_message(old: &PublicKeyBundle, epoch: u64, new_public: &PublicKeyBundle) -> Vec<u8> {
    let mut msg = Vec::with_capacity(KEY_ID_LEN + 8 + PUBLIC_BUNDLE_LEN);
    msg.extend_from_slice(old.key_id().as_bytes());
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(&new_public.to_bytes());
    msg
}

/// Produce an attestation that `old` authorizes `new_public` as its successor
/// at `epoch`. Callers should use a strictly increasing `epoch` per signer.
pub(crate) fn attest_rotation(
    old: &KeyPair,
    new_public: &PublicKeyBundle,
    epoch: u64,
) -> Result<RotationAttestation> {
    let message = rotation_message(old.public_keys(), epoch, new_public);
    let signature = sign::sign(old, &message, ROTATION_CONTEXT)?;
    Ok(RotationAttestation {
        epoch,
        new_public: new_public.clone(),
        signature,
    })
}

/// Verify a rotation attestation against the trusted `old` public bundle.
///
/// On success returns the authenticated successor bundle.
///
/// # Errors
///
/// [`Error::VerificationFailed`] if the attestation was not signed by `old`
/// over its embedded successor.
pub fn verify_rotation<'a>(
    old: &PublicKeyBundle,
    attestation: &'a RotationAttestation,
) -> Result<&'a PublicKeyBundle> {
    let message = rotation_message(old, attestation.epoch, &attestation.new_public);
    sign::verify(&message, ROTATION_CONTEXT, &attestation.signature, old)?;
    Ok(&attestation.new_public)
}
