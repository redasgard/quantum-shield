//! # Quantum Shield
//!
//! Hybrid post-quantum cryptography for Rust:
//!
//! - **Encryption**: X25519 + ML-KEM-1024 (FIPS 203) hybrid KEM feeding a
//!   SHA3-256 combiner, with AES-256-GCM payload encryption. Both key
//!   agreements enter one KDF, so an attacker must break *both* the
//!   classical and the post-quantum layer to recover a message.
//! - **Signatures**: Ed25519 + ML-DSA-87 (FIPS 204), both always present
//!   and both required to verify — the post-quantum signature cannot be
//!   stripped.
//!
//! All algorithm implementations are pure Rust (RustCrypto and dalek
//! crates); the crate builds and runs natively on Apple Silicon, x86-64,
//! and other targets without a C toolchain.
//!
//! ## Security status
//!
//! **This library and the underlying `ml-kem`/`ml-dsa` crates have not been
//! independently audited.** The library implements the FIPS 203/204
//! algorithms via RustCrypto; the library itself is not FIPS-validated.
//! Evaluate accordingly before using it to protect production data.
//!
//! Artifacts produced by quantum-shield 0.1.x use a cryptographically broken
//! format and are rejected with [`Error::LegacyV1Artifact`].
//!
//! ## Example
//!
//! ```no_run
//! use quantum_shield::{HybridCrypto, verify};
//!
//! # fn main() -> quantum_shield::Result<()> {
//! let alice = HybridCrypto::generate()?;
//! let bob = HybridCrypto::generate()?;
//!
//! // Alice encrypts a message for Bob.
//! let envelope = alice.seal_for(b"Hybrid PQ message", bob.public_keys())?;
//! let plaintext = bob.open(&envelope)?;
//! assert_eq!(plaintext, b"Hybrid PQ message");
//!
//! // Alice signs a message; Bob verifies it.
//! let signature = alice.sign(b"I agree to these terms", b"contract")?;
//! verify(b"I agree to these terms", b"contract", &signature, alice.public_keys())?;
//! # Ok(())
//! # }
//! ```
//!
//! Wire objects ([`Envelope`], [`HybridSignature`], [`PublicKeyBundle`])
//! serialize to versioned binary formats via `to_bytes`/`from_bytes`; the
//! format is specified in `docs/design.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod api;
mod constants;
mod error;
mod hybrid_kem;
mod keys;
mod multi;
#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
mod pem;
mod rotate;
mod seal;
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
mod serde_impls;
mod sign;
mod stream;
mod types;
mod wire;

pub use api::HybridCrypto;
pub use constants::*;
pub use error::{Error, Result};
pub use keys::{KeyId, KeyPair, PublicKeyBundle};
pub use multi::{open_multi, seal_multi, MultiRecipientEnvelope};
pub use rotate::{verify_rotation, RotationAttestation};
pub use seal::{open, seal};
pub use stream::{StreamOpener, StreamSealer};
pub use types::{Envelope, HybridSignature};
pub use zeroize::Zeroizing;

/// Verify a [`HybridSignature`] over `message` and `context` against the
/// signer's [`PublicKeyBundle`].
///
/// Both the Ed25519 and the ML-DSA-87 component must be valid.
///
/// # Errors
///
/// Returns [`Error::VerificationFailed`] if either component is invalid, and
/// [`Error::ContextTooLong`] if `context` exceeds 255 bytes.
pub fn verify(
    message: &[u8],
    context: &[u8],
    signature: &HybridSignature,
    signer: &PublicKeyBundle,
) -> Result<()> {
    sign::verify(message, context, signature, signer)
}

/// Commonly used items.
pub mod prelude {
    pub use crate::{
        seal, verify, Envelope, HybridCrypto, HybridSignature, KeyPair, PublicKeyBundle, Result,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_encryption() {
        let alice = HybridCrypto::generate().unwrap();
        let bob = HybridCrypto::generate().unwrap();

        let envelope = alice.seal_for(b"Test message", bob.public_keys()).unwrap();
        let decrypted = bob.open(&envelope).unwrap();
        assert_eq!(decrypted, b"Test message");
    }

    #[test]
    fn end_to_end_signature() {
        let alice = HybridCrypto::generate().unwrap();
        let sig = alice.sign(b"Message to sign", b"").unwrap();
        verify(b"Message to sign", b"", &sig, alice.public_keys()).unwrap();
    }

    #[test]
    fn free_function_seal_matches_method() {
        let bob = HybridCrypto::generate().unwrap();
        let envelope = seal(b"via free function", bob.public_keys()).unwrap();
        assert_eq!(bob.open(&envelope).unwrap(), b"via free function");
    }
}
