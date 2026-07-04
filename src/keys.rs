//! Key generation, derivation, and serialization.
//!
//! A [`KeyPair`] owns four independent secrets, all stored and exported in
//! seed form (the FIPS-recommended private-key encoding; every derived key is
//! recomputed from its seed on import):
//!
//! - an X25519 static secret (32 bytes),
//! - an ML-KEM-1024 (d,z) seed (64 bytes, FIPS 203),
//! - an Ed25519 seed (32 bytes),
//! - an ML-DSA-87 xi seed (32 bytes, FIPS 204 Algorithm 6).
//!
//! Seeds are zeroized on drop. Public counterparts travel together as a
//! [`PublicKeyBundle`], which validates every component when parsed.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::wire::{read_header, take, write_header};
use alloc::boxed::Box;
use alloc::vec::Vec;
use ml_dsa::signature::Keypair as _;
use ml_dsa::{KeyExport as _, MlDsa87};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024};
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A short, stable identifier for a public-key bundle: the first
/// [`KEY_ID_LEN`] bytes of `SHA3-256(QSP2 bytes)`. Useful for referencing or
/// pinning a key (e.g. in a rotation record) without carrying the full bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId([u8; KEY_ID_LEN]);

impl KeyId {
    /// The raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_ID_LEN] {
        &self.0
    }
}

/// The four private seeds, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Seeds {
    pub(crate) x25519_sk: [u8; X25519_SK_LEN],
    pub(crate) mlkem_seed: [u8; MLKEM_SEED_LEN],
    pub(crate) ed25519_seed: [u8; ED25519_SEED_LEN],
    pub(crate) mldsa_seed: [u8; MLDSA_SEED_LEN],
}

/// A complete hybrid keypair: private seeds plus derived key objects.
///
/// Create one with [`KeyPair::generate`] or restore one from a previous
/// [`KeyPair::to_secret_bytes`] export via [`KeyPair::from_secret_bytes`].
pub struct KeyPair {
    seeds: Seeds,
    pub(crate) x25519_sk: x25519_dalek::StaticSecret,
    pub(crate) mlkem_dk: Box<DecapsulationKey1024>,
    pub(crate) ed25519_sk: ed25519_dalek::SigningKey,
    pub(crate) mldsa_sk: Box<ml_dsa::SigningKey<MlDsa87>>,
    public: PublicKeyBundle,
}

impl KeyPair {
    /// Generate a fresh keypair from operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] if the OS RNG fails.
    pub fn generate() -> Result<Self> {
        let mut seeds = Seeds {
            x25519_sk: [0u8; X25519_SK_LEN],
            mlkem_seed: [0u8; MLKEM_SEED_LEN],
            ed25519_seed: [0u8; ED25519_SEED_LEN],
            mldsa_seed: [0u8; MLDSA_SEED_LEN],
        };
        getrandom::fill(&mut seeds.x25519_sk).map_err(|_| Error::RandomnessUnavailable)?;
        getrandom::fill(&mut seeds.mlkem_seed).map_err(|_| Error::RandomnessUnavailable)?;
        getrandom::fill(&mut seeds.ed25519_seed).map_err(|_| Error::RandomnessUnavailable)?;
        getrandom::fill(&mut seeds.mldsa_seed).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self::from_seeds(seeds))
    }

    /// Derive all key objects from the given seeds.
    pub(crate) fn from_seeds(seeds: Seeds) -> Self {
        let x25519_sk = x25519_dalek::StaticSecret::from(seeds.x25519_sk);
        let mlkem_dk = Box::new(DecapsulationKey1024::from_seed(seeds.mlkem_seed.into()));
        let ed25519_sk = ed25519_dalek::SigningKey::from_bytes(&seeds.ed25519_seed);
        let mldsa_sk = Box::new(ml_dsa::SigningKey::<MlDsa87>::from_seed(
            &seeds.mldsa_seed.into(),
        ));

        let public = PublicKeyBundle {
            x25519: x25519_dalek::PublicKey::from(&x25519_sk),
            mlkem: Box::new(mlkem_dk.encapsulation_key().clone()),
            ed25519: ed25519_sk.verifying_key(),
            mldsa: Box::new(mldsa_sk.verifying_key()),
        };

        Self {
            seeds,
            x25519_sk,
            mlkem_dk,
            ed25519_sk,
            mldsa_sk,
            public,
        }
    }

    /// The public half of this keypair, for sharing with peers.
    pub fn public_keys(&self) -> &PublicKeyBundle {
        &self.public
    }

    /// Export the private seeds as a v2 secret-key bundle (`QSK2`).
    ///
    /// The returned buffer is zeroized on drop, but the caller is responsible
    /// for protecting any copy written to storage.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::with_capacity(SECRET_BUNDLE_LEN);
        write_header(&mut out, MAGIC_SECRET_BUNDLE);
        out.extend_from_slice(&self.seeds.x25519_sk);
        out.extend_from_slice(&self.seeds.mlkem_seed);
        out.extend_from_slice(&self.seeds.ed25519_seed);
        out.extend_from_slice(&self.seeds.mldsa_seed);
        debug_assert_eq!(out.len(), SECRET_BUNDLE_LEN);
        Zeroizing::new(out)
    }

    /// Restore a keypair from a [`KeyPair::to_secret_bytes`] export.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] on malformed input, and version/suite
    /// errors for artifacts from other format versions.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let mut rest = read_header(bytes, MAGIC_SECRET_BUNDLE, Error::InvalidKey)?;
        let seeds = Seeds {
            x25519_sk: take(&mut rest, Error::InvalidKey)?,
            mlkem_seed: take(&mut rest, Error::InvalidKey)?,
            ed25519_seed: take(&mut rest, Error::InvalidKey)?,
            mldsa_seed: take(&mut rest, Error::InvalidKey)?,
        };
        if !rest.is_empty() {
            return Err(Error::InvalidKey);
        }
        Ok(Self::from_seeds(seeds))
    }
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair").finish_non_exhaustive()
    }
}

/// The public keys of a hybrid keypair.
///
/// Serialize with [`PublicKeyBundle::to_bytes`]; parsing via
/// [`PublicKeyBundle::from_bytes`] validates every component.
#[derive(Clone)]
pub struct PublicKeyBundle {
    pub(crate) x25519: x25519_dalek::PublicKey,
    pub(crate) mlkem: Box<EncapsulationKey1024>,
    pub(crate) ed25519: ed25519_dalek::VerifyingKey,
    pub(crate) mldsa: Box<ml_dsa::VerifyingKey<MlDsa87>>,
}

impl PublicKeyBundle {
    /// Serialize to the v2 public-key bundle format (`QSP2`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_BUNDLE_LEN);
        write_header(&mut out, MAGIC_PUBLIC_BUNDLE);
        out.extend_from_slice(self.x25519.as_bytes());
        out.extend_from_slice(&self.mlkem.to_bytes());
        out.extend_from_slice(self.ed25519.as_bytes());
        out.extend_from_slice(&self.mldsa.encode());
        debug_assert_eq!(out.len(), PUBLIC_BUNDLE_LEN);
        out
    }

    /// This bundle's [`KeyId`] — `SHA3-256(self.to_bytes())[..16]`.
    pub fn key_id(&self) -> KeyId {
        let digest = Sha3_256::digest(self.to_bytes());
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&digest[..KEY_ID_LEN]);
        KeyId(id)
    }

    /// Parse and validate a v2 public-key bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the encoding is malformed or any
    /// component fails validation (e.g. a non-canonical Ed25519 point or an
    /// out-of-range ML-KEM key).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut rest = read_header(bytes, MAGIC_PUBLIC_BUNDLE, Error::InvalidKey)?;

        let x25519_bytes: [u8; X25519_PK_LEN] = take(&mut rest, Error::InvalidKey)?;
        let mlkem_bytes: [u8; MLKEM1024_EK_LEN] = take(&mut rest, Error::InvalidKey)?;
        let ed25519_bytes: [u8; ED25519_PK_LEN] = take(&mut rest, Error::InvalidKey)?;
        let mldsa_bytes: [u8; MLDSA87_VK_LEN] = take(&mut rest, Error::InvalidKey)?;
        if !rest.is_empty() {
            return Err(Error::InvalidKey);
        }

        let x25519 = x25519_dalek::PublicKey::from(x25519_bytes);
        let mlkem =
            EncapsulationKey1024::new(&mlkem_bytes.into()).map_err(|_| Error::InvalidKey)?;
        let ed25519 = ed25519_dalek::VerifyingKey::from_bytes(&ed25519_bytes)
            .map_err(|_| Error::InvalidKey)?;
        let mldsa = ml_dsa::VerifyingKey::<MlDsa87>::decode(&mldsa_bytes.into());

        Ok(Self {
            x25519,
            mlkem: Box::new(mlkem),
            ed25519,
            mldsa: Box::new(mldsa),
        })
    }
}

impl core::fmt::Debug for PublicKeyBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKeyBundle")
            .field("x25519", &self.x25519)
            .finish_non_exhaustive()
    }
}

impl PartialEq for PublicKeyBundle {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PublicKeyBundle {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_crate_types() {
        use ml_dsa::signature::SignatureEncoding as _;
        let kp = KeyPair::generate().unwrap();
        assert_eq!(kp.public.mlkem.to_bytes().len(), MLKEM1024_EK_LEN);
        assert_eq!(kp.public.mldsa.encode().len(), MLDSA87_VK_LEN);
        use ed25519_dalek::Signer as _;
        use ml_dsa::signature::Signer as _;
        let ed_sig = kp.ed25519_sk.sign(b"x");
        assert_eq!(ed_sig.to_bytes().len(), ED25519_SIG_LEN);
        let pq_sig: ml_dsa::Signature<MlDsa87> = kp.mldsa_sk.sign(b"x");
        assert_eq!(pq_sig.to_bytes().len(), MLDSA87_SIG_LEN);
    }

    #[test]
    fn public_bundle_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let bytes = kp.public_keys().to_bytes();
        assert_eq!(bytes.len(), PUBLIC_BUNDLE_LEN);
        let parsed = PublicKeyBundle::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, *kp.public_keys());
    }

    #[test]
    fn secret_bundle_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let secret = kp.to_secret_bytes();
        assert_eq!(secret.len(), SECRET_BUNDLE_LEN);
        let restored = KeyPair::from_secret_bytes(&secret).unwrap();
        assert_eq!(restored.public_keys(), kp.public_keys());
    }

    #[test]
    fn secret_bundle_rejects_bad_input() {
        let kp = KeyPair::generate().unwrap();
        let secret = kp.to_secret_bytes();
        // Truncated
        assert_eq!(
            KeyPair::from_secret_bytes(&secret[..secret.len() - 1]).unwrap_err(),
            Error::InvalidKey
        );
        // Extended
        let mut long = secret.to_vec();
        long.push(0);
        assert_eq!(
            KeyPair::from_secret_bytes(&long).unwrap_err(),
            Error::InvalidKey
        );
        // Public bundle passed as secret bundle
        assert_eq!(
            KeyPair::from_secret_bytes(&kp.public_keys().to_bytes()).unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn public_bundle_rejects_invalid_ed25519_point() {
        // Find an encoding that fails Ed25519 point decompression (about half
        // of all y-coordinates do), then check our parser propagates the
        // rejection instead of storing the raw bytes unvalidated.
        let invalid = (0u8..=255)
            .map(|b| {
                let mut k = [b; ED25519_PK_LEN];
                k[0] = b.wrapping_add(1);
                k
            })
            .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
            .expect("some encoding must fail decompression");

        let kp = KeyPair::generate().unwrap();
        let mut bytes = kp.public_keys().to_bytes();
        let off = HEADER_LEN + X25519_PK_LEN + MLKEM1024_EK_LEN;
        bytes[off..off + ED25519_PK_LEN].copy_from_slice(&invalid);
        assert_eq!(
            PublicKeyBundle::from_bytes(&bytes).unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn public_bundle_rejects_invalid_mlkem_key() {
        let kp = KeyPair::generate().unwrap();
        let mut bytes = kp.public_keys().to_bytes();
        // Saturate the ML-KEM key bytes; coefficients out of range must fail
        // the modulus check in EncapsulationKey::new.
        let off = HEADER_LEN + X25519_PK_LEN;
        bytes[off..off + MLKEM1024_EK_LEN].fill(0xFF);
        assert_eq!(
            PublicKeyBundle::from_bytes(&bytes).unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let kp = KeyPair::generate().unwrap();
        let dbg = format!("{kp:?}");
        assert_eq!(dbg, "KeyPair { .. }");
    }
}
