//! Core types for hybrid cryptography

use serde::{Deserialize, Serialize};

/// Cryptography version for algorithm agility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoVersion(pub u32);

impl CryptoVersion {
    /// Current version
    pub const CURRENT: CryptoVersion = CryptoVersion(1);
    
    /// Check if this version is supported
    pub fn is_supported(&self) -> bool {
        self.0 <= Self::CURRENT.0
    }
}

impl Default for CryptoVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Hybrid encrypted data (RSA + Kyber + AES)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// Crypto version for forward compatibility
    pub version: CryptoVersion,
    
    /// AES-256-GCM encrypted data (base64)
    pub ciphertext: String,
    
    /// Symmetric key encrypted with RSA-4096 (base64)
    pub encrypted_key_rsa: String,
    
    /// Symmetric key encrypted with Kyber-1024 (base64)
    pub encrypted_key_kyber: String,
    
    /// Algorithm description for informational purposes
    pub algorithm: String,
}

impl HybridCiphertext {
    /// Create a new hybrid ciphertext
    pub fn new(
        ciphertext: String,
        encrypted_key_rsa: String,
        encrypted_key_kyber: String,
    ) -> Self {
        Self {
            version: CryptoVersion::CURRENT,
            ciphertext,
            encrypted_key_rsa,
            encrypted_key_kyber,
            algorithm: "AES-256-GCM + RSA-4096-OAEP + Kyber-1024".to_string(),
        }
    }
    
    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
    
    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Hybrid digital signature (RSA + Dilithium)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Crypto version
    pub version: CryptoVersion,
    
    /// RSA-4096-PSS signature (base64)
    pub rsa_signature: String,
    
    /// Dilithium5 signature (base64, optional for backward compatibility)
    pub dilithium_signature: Option<String>,
}

impl HybridSignature {
    /// Create a new hybrid signature
    pub fn new(rsa_signature: String, dilithium_signature: Option<String>) -> Self {
        Self {
            version: CryptoVersion::CURRENT,
            rsa_signature,
            dilithium_signature,
        }
    }
    
    /// Check if this signature includes post-quantum component
    pub fn is_quantum_resistant(&self) -> bool {
        self.dilithium_signature.is_some()
    }
    
    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
    
    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let v = CryptoVersion::CURRENT;
        assert!(v.is_supported());
        
        let future = CryptoVersion(999);
        assert!(!future.is_supported());
    }

    #[test]
    fn test_ciphertext_serialization() {
        let ct = HybridCiphertext::new(
            "ciphertext".to_string(),
            "rsa_key".to_string(),
            "kyber_key".to_string(),
        );
        
        let json = ct.to_json().unwrap();
        let ct2 = HybridCiphertext::from_json(&json).unwrap();
        
        assert_eq!(ct.ciphertext, ct2.ciphertext);
    }

    #[test]
    fn test_signature_quantum_resistant() {
        let sig1 = HybridSignature::new("rsa".to_string(), None);
        assert!(!sig1.is_quantum_resistant());
        
        let sig2 = HybridSignature::new("rsa".to_string(), Some("dilithium".to_string()));
        assert!(sig2.is_quantum_resistant());
    }
}

