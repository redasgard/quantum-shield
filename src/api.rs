//! The [`HybridCrypto`] convenience facade.

use crate::error::Result;
use crate::keys::{KeyPair, PublicKeyBundle};
use crate::multi::MultiRecipientEnvelope;
use crate::types::{Envelope, HybridSignature};
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// A hybrid keypair with convenience methods for the common workflows.
///
/// This is a thin wrapper around [`KeyPair`] plus the free functions
/// [`seal`](crate::seal) and [`verify`](crate::verify).
///
/// # Example
///
/// ```no_run
/// use quantum_shield::HybridCrypto;
///
/// # fn main() -> quantum_shield::Result<()> {
/// let alice = HybridCrypto::generate()?;
/// let bob = HybridCrypto::generate()?;
///
/// // Alice encrypts for Bob.
/// let envelope = alice.seal_for(b"hello", bob.public_keys())?;
/// let plaintext = bob.open(&envelope)?;
/// assert_eq!(plaintext, b"hello");
///
/// // Alice signs; anyone verifies.
/// let sig = alice.sign(b"release-v2.tar.gz", b"code-signing")?;
/// quantum_shield::verify(b"release-v2.tar.gz", b"code-signing", &sig, alice.public_keys())?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct HybridCrypto {
    keypair: KeyPair,
}

impl HybridCrypto {
    /// Generate a fresh hybrid keypair from OS randomness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`](crate::Error::RandomnessUnavailable)
    /// if the OS RNG fails.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            keypair: KeyPair::generate()?,
        })
    }

    /// Restore a keypair from a [`HybridCrypto::to_secret_bytes`] export.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`](crate::Error::InvalidKey) on malformed input.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            keypair: KeyPair::from_secret_bytes(bytes)?,
        })
    }

    /// Export the private seeds. Handle with care; the buffer zeroizes on drop.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        self.keypair.to_secret_bytes()
    }

    /// The public half of this keypair, for sharing.
    pub fn public_keys(&self) -> &PublicKeyBundle {
        self.keypair.public_keys()
    }

    /// Encrypt `plaintext` for `recipient`. Equivalent to [`crate::seal`].
    ///
    /// # Errors
    ///
    /// See [`crate::seal`].
    pub fn seal_for(&self, plaintext: &[u8], recipient: &PublicKeyBundle) -> Result<Envelope> {
        crate::seal(plaintext, recipient)
    }

    /// Decrypt an [`Envelope`] addressed to this keypair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptionFailed`](crate::Error::DecryptionFailed) for
    /// any cryptographic failure, with no further detail by design.
    pub fn open(&self, envelope: &Envelope) -> Result<Vec<u8>> {
        crate::seal::open(&self.keypair, envelope)
    }

    /// Decrypt a [`MultiRecipientEnvelope`] if this keypair is a recipient.
    ///
    /// Equivalent to [`crate::open_multi`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptionFailed`](crate::Error::DecryptionFailed) if
    /// this keypair is not a recipient or the envelope was tampered with.
    pub fn open_multi(&self, envelope: &MultiRecipientEnvelope) -> Result<Vec<u8>> {
        crate::multi::open_multi(&self.keypair, envelope)
    }

    /// Sign `message` under an application `context` (0–255 bytes) with both
    /// Ed25519 and ML-DSA-87.
    ///
    /// The context separates uses of the same key (e.g. `b"code-signing"` vs
    /// `b"api-auth"`); pass `b""` if you don't need one, and pass the same
    /// value to [`crate::verify`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ContextTooLong`](crate::Error::ContextTooLong) if
    /// `context` exceeds 255 bytes.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<HybridSignature> {
        crate::sign::sign(&self.keypair, message, context)
    }
}

impl From<KeyPair> for HybridCrypto {
    fn from(keypair: KeyPair) -> Self {
        Self { keypair }
    }
}
