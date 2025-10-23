//! Error types for Quantum Shield

use std::fmt;

/// Result type alias for Quantum Shield operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during cryptographic operations
#[derive(Debug)]
pub enum Error {
    /// Invalid key format or size
    InvalidKey(String),
    
    /// Encryption operation failed
    EncryptionFailed(String),
    
    /// Decryption operation failed  
    DecryptionFailed(String),
    
    /// Signature generation failed
    SigningFailed(String),
    
    /// Signature verification failed
    VerificationFailed(String),
    
    /// Key generation failed
    KeyGenerationFailed(String),
    
    /// Serialization/deserialization error
    SerializationError(String),
    
    /// Invalid ciphertext format
    InvalidCiphertext(String),
    
    /// Invalid signature format
    InvalidSignature(String),
    
    /// IO error
    IoError(String),
    
    /// Unsupported version
    UnsupportedVersion(u32),
    
    /// Generic error
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            Error::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            Error::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            Error::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            Error::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            Error::KeyGenerationFailed(msg) => write!(f, "Key generation failed: {}", msg),
            Error::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Error::InvalidCiphertext(msg) => write!(f, "Invalid ciphertext: {}", msg),
            Error::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            Error::IoError(msg) => write!(f, "IO error: {}", msg),
            Error::UnsupportedVersion(v) => write!(f, "Unsupported version: {}", v),
            Error::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::SerializationError(err.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::SerializationError(format!("Base64 decode error: {}", err))
    }
}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Self {
        Error::Other(format!("RSA error: {}", err))
    }
}

impl From<rsa::pkcs8::Error> for Error {
    fn from(err: rsa::pkcs8::Error) -> Self {
        Error::InvalidKey(format!("PKCS8 error: {}", err))
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(err: aes_gcm::Error) -> Self {
        Error::EncryptionFailed(format!("AES-GCM error: {:?}", err))
    }
}

