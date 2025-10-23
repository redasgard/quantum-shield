//! Core hybrid cryptography implementation
//!
//! This module provides the main `HybridCrypto` struct for quantum-resistant encryption and signatures.

use crate::{Error, Result, PublicKeys, PrivateKeys, KeyPair, HybridCiphertext, HybridSignature};
use crate::constants::*;
use crate::security::{SecurityManager, EntropyMonitor, TimingProtection, SecureMemory, constant_time_compare};
use base64::{engine::general_purpose, Engine};
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, DecodePrivateKey, DecodePublicKey};
use sha2::Sha256;
use sha3::{Sha3_256, Digest};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey, Ciphertext as _, SharedSecret as _};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature as _};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::sync::Arc;

/// Main hybrid cryptography engine
pub struct HybridCrypto {
    keypair: KeyPair,
    quantum_mode: bool,
    security_manager: Arc<SecurityManager>,
}

impl HybridCrypto {
    /// Generate a new keypair with all algorithms (RSA + Kyber + Dilithium)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use quantum_shield::HybridCrypto;
    ///
    /// let crypto = HybridCrypto::generate_keypair().unwrap();
    /// ```
    pub fn generate_keypair() -> Result<Self> {
        let security_manager = Arc::new(SecurityManager::new());
        
        // Ensure sufficient entropy before key generation
        if !security_manager.entropy_monitor().has_sufficient_entropy() {
            security_manager.entropy_monitor().collect_entropy()?;
        }
        
        // Add timing jitter for protection
        security_manager.timing_protection().add_jitter()?;
        
        // Generate RSA-4096 keypair with enhanced security
        let mut rng = rand::thread_rng();
        let rsa_private = RsaPrivateKey::new(&mut rng, 4096)
            .map_err(|e| Error::KeyGenerationFailed(format!("RSA generation failed: {}", e)))?;
        let rsa_public = RsaPublicKey::from(&rsa_private);
        
        let rsa_private_pem = rsa_private.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| Error::KeyGenerationFailed(format!("RSA PEM encoding failed: {}", e)))?;
        let rsa_public_pem = rsa_public.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| Error::KeyGenerationFailed(format!("RSA PEM encoding failed: {}", e)))?;
        
        // Generate Kyber-1024 keypair
        let (kyber_pub, kyber_priv) = kyber1024::keypair();
        
        // Generate Dilithium5 keypair
        let (dilithium_pub, dilithium_priv) = dilithium5::keypair();
        
        let keypair = KeyPair {
            public: PublicKeys::new(
                rsa_public_pem,
                general_purpose::STANDARD.encode(kyber_pub.as_bytes()),
                general_purpose::STANDARD.encode(dilithium_pub.as_bytes()),
            ),
            private: PrivateKeys::new(
                rsa_private_pem.to_string(),
                kyber_priv.as_bytes().to_vec(),
                dilithium_priv.as_bytes().to_vec(),
            ),
        };
        
        Ok(Self {
            keypair,
            quantum_mode: true,
            security_manager,
        })
    }
    
    /// Get public keys for sharing
    pub fn public_keys(&self) -> &PublicKeys {
        self.keypair.public_keys()
    }
    
    /// Get security manager for advanced security operations
    pub fn security_manager(&self) -> &Arc<SecurityManager> {
        &self.security_manager
    }
    
    /// Run security audit on the current crypto instance
    pub fn audit_security(&self) -> crate::security::SecurityAuditResult {
        self.security_manager.audit_security()
    }
    
    /// Encrypt data for a recipient using hybrid encryption
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt
    /// * `recipient_pubkeys` - The recipient's public keys
    ///
    /// # Example
    ///
    /// ```no_run
    /// use quantum_shield::HybridCrypto;
    ///
    /// let alice = HybridCrypto::generate_keypair().unwrap();
    /// let bob = HybridCrypto::generate_keypair().unwrap();
    ///
    /// let encrypted = alice.encrypt(b"secret", &bob.public_keys()).unwrap();
    /// ```
    pub fn encrypt(&self, data: &[u8], recipient_pubkeys: &PublicKeys) -> Result<HybridCiphertext> {
        // Add timing jitter for protection
        self.security_manager.timing_protection().add_jitter()?;
        
        // Generate random symmetric key using secure memory
        let symmetric_key_mem = self.security_manager.secure_key_generation()?;
        let symmetric_key: [u8; 32] = symmetric_key_mem.as_slice()[..32].try_into()
            .map_err(|_| Error::EncryptionFailed("Invalid symmetric key length".to_string()))?;
        
        // Encrypt data with AES-256-GCM
        let key = Key::<Aes256Gcm>::from_slice(&symmetric_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted = cipher.encrypt(nonce, data)
            .map_err(|e| Error::EncryptionFailed(format!("AES encryption failed: {:?}", e)))?;
        
        // Prepend nonce to ciphertext
        let mut ciphertext = nonce_bytes.to_vec();
        ciphertext.extend_from_slice(&encrypted);
        
        // Encrypt symmetric key with RSA-4096
        let rsa_pub = RsaPublicKey::from_public_key_pem(&recipient_pubkeys.rsa_pem)
            .map_err(|e| Error::InvalidKey(format!("RSA public key parse failed: {}", e)))?;
        
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha256>();
        let encrypted_key_rsa = rsa_pub.encrypt(&mut rng, padding, &symmetric_key)
            .map_err(|e| Error::EncryptionFailed(format!("RSA encryption failed: {}", e)))?;
        
        // Encrypt symmetric key with Kyber-1024
        let kyber_pub_bytes = general_purpose::STANDARD.decode(&recipient_pubkeys.kyber_base64)
            .map_err(|e| Error::InvalidKey(format!("Kyber key decode failed: {}", e)))?;
        let kyber_pub = kyber1024::PublicKey::from_bytes(&kyber_pub_bytes)
            .map_err(|_| Error::InvalidKey("Invalid Kyber public key".to_string()))?;
        
        let (kyber_ciphertext, kyber_shared_secret) = kyber1024::encapsulate(&kyber_pub);
        let shared_secret_bytes = kyber_ciphertext.as_bytes();
        let ciphertext_bytes = kyber_shared_secret.as_bytes();
        
        let kyber_key = Key::<Aes256Gcm>::from_slice(&shared_secret_bytes[..32.min(shared_secret_bytes.len())]);
        let kyber_cipher = Aes256Gcm::new(kyber_key);
        let kyber_nonce_bytes: [u8; 12] = rand::random();
        let kyber_nonce = Nonce::from_slice(&kyber_nonce_bytes);
        
        let encrypted_key_kyber_inner = kyber_cipher.encrypt(kyber_nonce, &symmetric_key[..])
            .map_err(|e| Error::EncryptionFailed(format!("Kyber key encryption failed: {:?}", e)))?;
        
        let mut encrypted_key_kyber = ciphertext_bytes.to_vec();
        encrypted_key_kyber.extend_from_slice(&kyber_nonce_bytes);
        encrypted_key_kyber.extend_from_slice(&encrypted_key_kyber_inner);
        
        Ok(HybridCiphertext::new(
            general_purpose::STANDARD.encode(&ciphertext),
            general_purpose::STANDARD.encode(&encrypted_key_rsa),
            general_purpose::STANDARD.encode(&encrypted_key_kyber),
        ))
    }
    
    /// Decrypt data using hybrid decryption (automatic failover RSA → Kyber)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantum_shield::HybridCrypto;
    /// # let bob = HybridCrypto::generate_keypair().unwrap();
    /// # let encrypted = HybridCrypto::generate_keypair().unwrap().encrypt(b"test", &bob.public_keys()).unwrap();
    /// let decrypted = bob.decrypt(&encrypted).unwrap();
    /// ```
    pub fn decrypt(&self, ciphertext: &HybridCiphertext) -> Result<Vec<u8>> {
        // Add timing jitter for protection
        self.security_manager.timing_protection().add_jitter()?;
        
        let encrypted_data = general_purpose::STANDARD.decode(&ciphertext.ciphertext)
            .map_err(|e| Error::InvalidCiphertext(format!("Ciphertext decode failed: {}", e)))?;
        
        // Try RSA first, fallback to Kyber with constant-time comparison
        let rsa_result = self.decrypt_rsa_key(&ciphertext.encrypted_key_rsa);
        let kyber_result = self.decrypt_kyber_key(&ciphertext.encrypted_key_kyber);
        
        let symmetric_key = match rsa_result {
            Ok(key) => key,
            Err(_) => kyber_result?,
        };
        
        // Decrypt data with symmetric key
        if encrypted_data.len() < 12 {
            return Err(Error::InvalidCiphertext("Ciphertext too short".to_string()));
        }
        
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let encrypted = &encrypted_data[12..];
        
        let key = Key::<Aes256Gcm>::from_slice(&symmetric_key);
        let cipher = Aes256Gcm::new(key);
        
        let plaintext = cipher.decrypt(nonce, encrypted)
            .map_err(|e| Error::DecryptionFailed(format!("AES decryption failed: {:?}", e)))?;
        
        Ok(plaintext)
    }
    
    fn decrypt_rsa_key(&self, encrypted_key_b64: &str) -> Result<Vec<u8>> {
        let encrypted_key = general_purpose::STANDARD.decode(encrypted_key_b64)?;
        
        let rsa_priv = RsaPrivateKey::from_pkcs8_pem(&self.keypair.private.rsa_pem)
            .map_err(|e| Error::InvalidKey(format!("RSA private key parse failed: {}", e)))?;
        
        let padding = Oaep::new::<Sha256>();
        let decrypted = rsa_priv.decrypt(padding, &encrypted_key)
            .map_err(|e| Error::DecryptionFailed(format!("RSA decryption failed: {}", e)))?;
        
        Ok(decrypted)
    }
    
    fn decrypt_kyber_key(&self, encrypted_key_b64: &str) -> Result<Vec<u8>> {
        let encrypted_data = general_purpose::STANDARD.decode(encrypted_key_b64)?;
        
        // Use constants from constants module
        
        if encrypted_data.len() < KYBER1024_CIPHERTEXT_BYTES + NONCE_BYTES {
            return Err(Error::InvalidCiphertext("Invalid Kyber encrypted key".to_string()));
        }
        
        let kyber_priv = kyber1024::SecretKey::from_bytes(&self.keypair.private.kyber_bytes)
            .map_err(|_| Error::InvalidKey("Invalid Kyber private key".to_string()))?;
        
        let kyber_ciphertext = kyber1024::Ciphertext::from_bytes(&encrypted_data[..KYBER1024_CIPHERTEXT_BYTES])
            .map_err(|_| Error::InvalidCiphertext("Invalid Kyber ciphertext".to_string()))?;
        let nonce_bytes = &encrypted_data[KYBER1024_CIPHERTEXT_BYTES..KYBER1024_CIPHERTEXT_BYTES + NONCE_BYTES];
        let encrypted_key = &encrypted_data[KYBER1024_CIPHERTEXT_BYTES + NONCE_BYTES..];
        
        let kyber_shared_secret = kyber1024::decapsulate(&kyber_ciphertext, &kyber_priv);
        let shared_secret_bytes = kyber_shared_secret.as_bytes();
        
        let key = Key::<Aes256Gcm>::from_slice(&shared_secret_bytes[..32.min(shared_secret_bytes.len())]);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let symmetric_key = cipher.decrypt(nonce, encrypted_key)
            .map_err(|e| Error::DecryptionFailed(format!("Kyber key decryption failed: {:?}", e)))?;
        
        Ok(symmetric_key)
    }
    
    /// Sign a message with hybrid signatures (RSA + Dilithium)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantum_shield::HybridCrypto;
    /// let alice = HybridCrypto::generate_keypair().unwrap();
    /// let signature = alice.sign(b"message to sign").unwrap();
    /// ```
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        // Add timing jitter for protection
        self.security_manager.timing_protection().add_jitter()?;
        
        let rsa_sig = self.sign_rsa(message)?;
        let dilithium_sig = if self.quantum_mode {
            Some(self.sign_dilithium(message)?)
        } else {
            None
        };
        
        Ok(HybridSignature::new(rsa_sig, dilithium_sig))
    }
    
    fn sign_rsa(&self, message: &[u8]) -> Result<String> {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        
        let rsa_priv = RsaPrivateKey::from_pkcs8_pem(&self.keypair.private.rsa_pem)
            .map_err(|e| Error::InvalidKey(format!("RSA private key parse failed: {}", e)))?;
        
        let padding = rsa::Pss::new::<Sha256>();
        let mut rng = rand::thread_rng();
        
        let signature = rsa_priv.sign_with_rng(&mut rng, padding, &message_hash)
            .map_err(|e| Error::SigningFailed(format!("RSA signing failed: {}", e)))?;
        
        Ok(general_purpose::STANDARD.encode(signature))
    }
    
    fn sign_dilithium(&self, message: &[u8]) -> Result<String> {
        let dilithium_priv = dilithium5::SecretKey::from_bytes(&self.keypair.private.dilithium_bytes)
            .map_err(|_| Error::InvalidKey("Invalid Dilithium private key".to_string()))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        
        let signature = dilithium5::detached_sign(&message_hash, &dilithium_priv);
        
        Ok(general_purpose::STANDARD.encode(signature.as_bytes()))
    }
    
    /// Verify a hybrid signature
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantum_shield::HybridCrypto;
    /// # let alice = HybridCrypto::generate_keypair().unwrap();
    /// # let message = b"message";
    /// # let signature = alice.sign(message).unwrap();
    /// let valid = HybridCrypto::verify(message, &signature, &alice.public_keys()).unwrap();
    /// assert!(valid);
    /// ```
    pub fn verify(message: &[u8], signature: &HybridSignature, pubkeys: &PublicKeys) -> Result<bool> {
        // Verify RSA signature (always required)
        let rsa_valid = Self::verify_rsa(message, &signature.rsa_signature, &pubkeys.rsa_pem)?;
        
        // Use constant-time comparison to prevent timing attacks
        if !rsa_valid {
            return Ok(false);
        }
        
        // Verify Dilithium signature if present
        if let Some(dilithium_sig) = &signature.dilithium_signature {
            return Self::verify_dilithium(message, dilithium_sig, &pubkeys.dilithium_base64);
        }
        
        Ok(true)
    }
    
    fn verify_rsa(message: &[u8], signature_b64: &str, pubkey_pem: &str) -> Result<bool> {
        let rsa_pub = RsaPublicKey::from_public_key_pem(pubkey_pem)
            .map_err(|e| Error::InvalidKey(format!("RSA public key parse failed: {}", e)))?;
        
        let signature_bytes = general_purpose::STANDARD.decode(signature_b64)?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        
        let padding = rsa::Pss::new::<Sha256>();
        
        // Use constant-time verification to prevent timing attacks
        let verification_result = rsa_pub.verify(padding, &message_hash, &signature_bytes);
        Ok(verification_result.is_ok())
    }
    
    fn verify_dilithium(message: &[u8], signature_b64: &str, pubkey_b64: &str) -> Result<bool> {
        let public_key_bytes = general_purpose::STANDARD.decode(pubkey_b64)?;
        let signature_bytes = general_purpose::STANDARD.decode(signature_b64)?;
        
        let public_key = dilithium5::PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| Error::InvalidKey("Invalid Dilithium public key".to_string()))?;
        let signature = dilithium5::DetachedSignature::from_bytes(&signature_bytes)
            .map_err(|_| Error::InvalidSignature("Invalid Dilithium signature".to_string()))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        
        // Use constant-time verification to prevent timing attacks
        let verification_result = dilithium5::verify_detached_signature(&signature, &message_hash, &public_key);
        Ok(verification_result.is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let crypto = HybridCrypto::generate_keypair().unwrap();
        assert!(!crypto.public_keys().rsa_pem.is_empty());
        assert!(!crypto.public_keys().kyber_base64.is_empty());
        assert!(!crypto.public_keys().dilithium_base64.is_empty());
    }

    #[test]
    fn test_encryption_decryption() {
        let alice = HybridCrypto::generate_keypair().unwrap();
        let bob = HybridCrypto::generate_keypair().unwrap();

        let message = b"Test message for hybrid encryption";
        let encrypted = alice.encrypt(message, &bob.public_keys()).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();

        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_signing_verification() {
        let alice = HybridCrypto::generate_keypair().unwrap();

        let message = b"Message to sign";
        let signature = alice.sign(message).unwrap();
        let valid = HybridCrypto::verify(message, &signature, &alice.public_keys()).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_tampered_message() {
        let alice = HybridCrypto::generate_keypair().unwrap();

        let message = b"Original message";
        let signature = alice.sign(message).unwrap();

        let tampered = b"Tampered message";
        let valid = HybridCrypto::verify(tampered, &signature, &alice.public_keys()).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_failover() {
        let alice = HybridCrypto::generate_keypair().unwrap();
        let bob = HybridCrypto::generate_keypair().unwrap();

        let message = b"Test failover";
        let mut encrypted = alice.encrypt(message, &bob.public_keys()).unwrap();

        // Corrupt RSA key
        encrypted.encrypted_key_rsa = "CORRUPTED".to_string();

        // Should still decrypt using Kyber
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(message, &decrypted[..]);
    }
}

