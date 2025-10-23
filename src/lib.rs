//! # Quantum Shield
//!
//! Hybrid quantum-resistant cryptography library using NIST-standardized post-quantum algorithms.
//!
//! ## Features
//!
//! - Hybrid Encryption: RSA-4096 + Kyber-1024 (NIST Level 5)
//! - Hybrid Signatures: RSA-4096-PSS + Dilithium5 (NIST Level 5)
//! - Defense in Depth: Multiple independent security layers
//! - Automatic Failover: Falls back to Kyber if RSA decryption fails
//!
//! ## Quick Example
//!
//! ```no_run
//! use quantum_shield::{HybridCrypto, Result};
//!
//! # fn main() -> Result<()> {
//! // Generate keypairs for Alice and Bob
//! let alice = HybridCrypto::generate_keypair()?;
//! let bob = HybridCrypto::generate_keypair()?;
//!
//! // Alice encrypts a message for Bob
//! let message = b"Secret quantum-resistant message";
//! let encrypted = alice.encrypt(message, &bob.public_keys())?;
//!
//! // Bob decrypts the message
//! let decrypted = bob.decrypt(&encrypted)?;
//! assert_eq!(message, &decrypted[..]);
//! # Ok(())
//! # }
//! ```

#![doc(html_root_url = "https://docs.rs/quantum-shield/0.1.0")]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod constants;
mod crypto;
mod error;
mod keys;
mod types;
mod security;

pub use constants::*;
pub use crypto::HybridCrypto;
pub use error::{Error, Result};
pub use keys::{PublicKeys, PrivateKeys, KeyPair};
pub use types::{HybridCiphertext, HybridSignature, CryptoVersion};
pub use security::{
    SecurityManager, EntropyMonitor, TimingProtection, SecureMemory,
    AlgorithmAgility, SecurityAuditResult, constant_time_compare,
    constant_time_select
};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::{HybridCrypto, PublicKeys, PrivateKeys, KeyPair, Result};
    pub use crate::{HybridCiphertext, HybridSignature};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encryption() {
        let alice = HybridCrypto::generate_keypair().unwrap();
        let bob = HybridCrypto::generate_keypair().unwrap();

        let message = b"Test message";
        let encrypted = alice.encrypt(message, &bob.public_keys()).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();

        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_basic_signature() {
        let alice = HybridCrypto::generate_keypair().unwrap();

        let message = b"Message to sign";
        let signature = alice.sign(message).unwrap();
        let valid = HybridCrypto::verify(message, &signature, &alice.public_keys()).unwrap();

        assert!(valid);
    }
}

