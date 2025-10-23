//! Key management for hybrid cryptography

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Public keys bundle for hybrid cryptography
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeys {
    /// RSA-4096 public key (PEM format)
    pub rsa_pem: String,
    
    /// Kyber-1024 public key (base64)
    pub kyber_base64: String,
    
    /// Dilithium5 public key (base64)
    pub dilithium_base64: String,
    
    /// Version for compatibility
    pub version: u32,
}

impl PublicKeys {
    /// Create a new public keys bundle
    pub fn new(rsa_pem: String, kyber_base64: String, dilithium_base64: String) -> Self {
        Self {
            rsa_pem,
            kyber_base64,
            dilithium_base64,
            version: 1,
        }
    }
    
    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| Error::SerializationError(e.to_string()))
    }
    
    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::SerializationError(e.to_string()))
    }
}

/// Private keys (zeroized on drop for security)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct PrivateKeys {
    /// RSA-4096 private key (PEM format)
    pub(crate) rsa_pem: String,
    
    /// Kyber-1024 private key (binary)
    pub(crate) kyber_bytes: Vec<u8>,
    
    /// Dilithium5 private key (binary)
    pub(crate) dilithium_bytes: Vec<u8>,
}

impl PrivateKeys {
    /// Create a new private keys bundle
    pub(crate) fn new(rsa_pem: String, kyber_bytes: Vec<u8>, dilithium_bytes: Vec<u8>) -> Self {
        Self {
            rsa_pem,
            kyber_bytes,
            dilithium_bytes,
        }
    }
}

/// Complete keypair (public + private)
pub struct KeyPair {
    /// Public keys
    pub(crate) public: PublicKeys,
    
    /// Private keys
    pub(crate) private: PrivateKeys,
}

impl KeyPair {
    /// Get public keys
    pub fn public_keys(&self) -> &PublicKeys {
        &self.public
    }
    
    /// Get private keys (internal use only)
    pub(crate) fn private_keys(&self) -> &PrivateKeys {
        &self.private
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_keys_serialization() {
        let keys = PublicKeys::new(
            "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
            "kyber_key".to_string(),
            "dilithium_key".to_string(),
        );
        
        let json = keys.to_json().unwrap();
        let keys2 = PublicKeys::from_json(&json).unwrap();
        
        assert_eq!(keys.rsa_pem, keys2.rsa_pem);
        assert_eq!(keys.kyber_base64, keys2.kyber_base64);
    }

    #[test]
    fn test_private_keys_zeroize() {
        let mut private = PrivateKeys::new(
            "private_key".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
        );
        
        // Keys should be zeroized on drop
        drop(private);
    }
}

