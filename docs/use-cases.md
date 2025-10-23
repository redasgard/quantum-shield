# Use Cases

## Overview

Quantum Shield provides quantum-resistant cryptography for scenarios requiring long-term data protection. This document outlines real-world use cases and implementation patterns.

## 1. Secure Communication Systems

### Scenario: Encrypted Messaging Platform

**Requirements:**
- End-to-end encryption between users
- Future-proof against quantum computers
- Message signatures for authentication

**Implementation:**

```rust
use quantum_shield::{HybridCrypto, PublicKeys};
use std::collections::HashMap;

struct SecureMessaging {
    users: HashMap<String, HybridCrypto>,
    public_keys: HashMap<String, PublicKeys>,
}

impl SecureMessaging {
    fn new() -> Self {
        Self {
            users: HashMap::new(),
            public_keys: HashMap::new(),
        }
    }
    
    fn register_user(&mut self, username: &str) -> quantum_shield::Result<()> {
        let keypair = HybridCrypto::generate_keypair()?;
        self.public_keys.insert(username.to_string(), keypair.public_keys());
        self.users.insert(username.to_string(), keypair);
        Ok(())
    }
    
    fn send_message(
        &self,
        from: &str,
        to: &str,
        message: &str,
    ) -> quantum_shield::Result<(Vec<u8>, Vec<u8>)> {
        let sender = self.users.get(from)
            .ok_or_else(|| quantum_shield::Error::InvalidInput("Sender not found".into()))?;
        let recipient_keys = self.public_keys.get(to)
            .ok_or_else(|| quantum_shield::Error::InvalidInput("Recipient not found".into()))?;
        
        // Encrypt message
        let encrypted = sender.encrypt(message.as_bytes(), recipient_keys)?;
        
        // Sign message
        let signature = sender.sign(message.as_bytes())?;
        
        Ok((
            serde_json::to_vec(&encrypted)?,
            serde_json::to_vec(&signature)?,
        ))
    }
    
    fn receive_message(
        &self,
        recipient: &str,
        sender: &str,
        encrypted_data: &[u8],
        signature_data: &[u8],
    ) -> quantum_shield::Result<String> {
        let receiver = self.users.get(recipient)
            .ok_or_else(|| quantum_shield::Error::InvalidInput("Recipient not found".into()))?;
        let sender_keys = self.public_keys.get(sender)
            .ok_or_else(|| quantum_shield::Error::InvalidInput("Sender not found".into()))?;
        
        // Deserialize
        let encrypted: quantum_shield::HybridCiphertext = serde_json::from_slice(encrypted_data)?;
        let signature: quantum_shield::HybridSignature = serde_json::from_slice(signature_data)?;
        
        // Decrypt
        let decrypted = receiver.decrypt(&encrypted)?;
        
        // Verify signature
        let valid = HybridCrypto::verify(&decrypted, &signature, sender_keys)?;
        if !valid {
            return Err(quantum_shield::Error::VerificationFailed);
        }
        
        Ok(String::from_utf8(decrypted)?)
    }
}
```

**Benefits:**
- Messages secure even if intercepted and stored for future decryption
- Authentication prevents impersonation attacks
- Hybrid approach provides maximum security

## 2. Blockchain and Web3 Applications

### Scenario: Quantum-Resistant Cryptocurrency Wallet

**Requirements:**
- Secure transaction signing
- Long-term key storage (years)
- Protection against "harvest now, decrypt later"

**Implementation:**

```rust
use quantum_shield::{HybridCrypto, HybridSignature};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
    nonce: u64,
}

struct QuantumWallet {
    address: String,
    keypair: HybridCrypto,
}

impl QuantumWallet {
    fn create(address: String) -> quantum_shield::Result<Self> {
        let keypair = HybridCrypto::generate_keypair()?;
        Ok(Self { address, keypair })
    }
    
    fn sign_transaction(&self, tx: &Transaction) -> quantum_shield::Result<HybridSignature> {
        let tx_bytes = serde_json::to_vec(tx)?;
        self.keypair.sign(&tx_bytes)
    }
    
    fn verify_transaction(
        tx: &Transaction,
        signature: &HybridSignature,
        public_keys: &quantum_shield::PublicKeys,
    ) -> quantum_shield::Result<bool> {
        let tx_bytes = serde_json::to_vec(tx)?;
        HybridCrypto::verify(&tx_bytes, signature, public_keys)
    }
}

// Blockchain integration
fn submit_transaction(
    wallet: &QuantumWallet,
    to: &str,
    amount: u64,
    nonce: u64,
) -> quantum_shield::Result<()> {
    let tx = Transaction {
        from: wallet.address.clone(),
        to: to.to_string(),
        amount,
        nonce,
    };
    
    let signature = wallet.sign_transaction(&tx)?;
    
    // Submit to blockchain network
    // blockchain_client.submit(tx, signature)?;
    
    println!("Transaction signed and ready for submission");
    Ok(())
}
```

**Benefits:**
- Private keys remain secure even after quantum computers exist
- Transactions cannot be forged
- Future-proof value storage

## 3. Medical Records System

### Scenario: Long-Term Health Data Protection

**Requirements:**
- 30+ year data retention requirements
- HIPAA compliance
- Patient privacy protection

**Implementation:**

```rust
use quantum_shield::HybridCrypto;
use chrono::{DateTime, Utc};

struct MedicalRecord {
    patient_id: String,
    data: Vec<u8>,
    encrypted_at: DateTime<Utc>,
}

struct HealthcareSystem {
    hospital_key: HybridCrypto,
}

impl HealthcareSystem {
    fn new() -> quantum_shield::Result<Self> {
        Ok(Self {
            hospital_key: HybridCrypto::generate_keypair()?,
        })
    }
    
    fn encrypt_patient_record(
        &self,
        patient_id: String,
        medical_data: &[u8],
    ) -> quantum_shield::Result<MedicalRecord> {
        let encrypted = self.hospital_key.encrypt(
            medical_data,
            &self.hospital_key.public_keys(),
        )?;
        
        Ok(MedicalRecord {
            patient_id,
            data: serde_json::to_vec(&encrypted)?,
            encrypted_at: Utc::now(),
        })
    }
    
    fn decrypt_patient_record(
        &self,
        record: &MedicalRecord,
    ) -> quantum_shield::Result<Vec<u8>> {
        let encrypted: quantum_shield::HybridCiphertext = 
            serde_json::from_slice(&record.data)?;
        self.hospital_key.decrypt(&encrypted)
    }
    
    fn share_with_specialist(
        &self,
        record: &MedicalRecord,
        specialist_keys: &quantum_shield::PublicKeys,
    ) -> quantum_shield::Result<Vec<u8>> {
        // Decrypt with hospital key
        let plaintext = self.decrypt_patient_record(record)?;
        
        // Re-encrypt for specialist
        let encrypted = self.hospital_key.encrypt(&plaintext, specialist_keys)?;
        
        Ok(serde_json::to_vec(&encrypted)?)
    }
}
```

**Benefits:**
- Medical records remain confidential for decades
- Secure sharing between healthcare providers
- Compliance with long-term retention laws

## 4. Government and Defense

### Scenario: Classified Document Protection

**Requirements:**
- Top Secret clearance level
- 50+ year classification periods
- Defense against future quantum attacks

**Implementation:**

```rust
use quantum_shield::{HybridCrypto, PublicKeys};

#[derive(Debug, Clone, Copy)]
enum ClassificationLevel {
    Unclassified,
    Confidential,
    Secret,
    TopSecret,
}

struct ClassifiedDocument {
    id: String,
    classification: ClassificationLevel,
    encrypted_content: Vec<u8>,
    signature: Vec<u8>,
}

struct SecureGovernmentSystem {
    signing_authority: HybridCrypto,
    classification_keys: std::collections::HashMap<String, HybridCrypto>,
}

impl SecureGovernmentSystem {
    fn classify_document(
        &self,
        content: &[u8],
        classification: ClassificationLevel,
        clearance_holder_keys: &PublicKeys,
    ) -> quantum_shield::Result<ClassifiedDocument> {
        // Encrypt for clearance holder
        let encrypted = self.signing_authority.encrypt(content, clearance_holder_keys)?;
        
        // Sign by authority
        let signature = self.signing_authority.sign(content)?;
        
        Ok(ClassifiedDocument {
            id: uuid::Uuid::new_v4().to_string(),
            classification,
            encrypted_content: serde_json::to_vec(&encrypted)?,
            signature: serde_json::to_vec(&signature)?,
        })
    }
    
    fn verify_and_decrypt(
        &self,
        doc: &ClassifiedDocument,
        clearance_holder: &HybridCrypto,
    ) -> quantum_shield::Result<Vec<u8>> {
        // Deserialize
        let encrypted: quantum_shield::HybridCiphertext = 
            serde_json::from_slice(&doc.encrypted_content)?;
        let signature: quantum_shield::HybridSignature = 
            serde_json::from_slice(&doc.signature)?;
        
        // Decrypt
        let content = clearance_holder.decrypt(&encrypted)?;
        
        // Verify authenticity
        let valid = HybridCrypto::verify(
            &content,
            &signature,
            &self.signing_authority.public_keys(),
        )?;
        
        if !valid {
            return Err(quantum_shield::Error::VerificationFailed);
        }
        
        Ok(content)
    }
}
```

**Benefits:**
- Documents remain classified for entire classification period
- Authentication prevents document tampering
- Meets national security requirements

## 5. Financial Services

### Scenario: Long-Term Financial Data Protection

**Requirements:**
- 7+ year data retention (regulatory)
- Transaction integrity
- Audit trail protection

**Implementation:**

```rust
use quantum_shield::HybridCrypto;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct FinancialTransaction {
    transaction_id: String,
    amount: f64,
    timestamp: i64,
    from_account: String,
    to_account: String,
}

struct BankingSystem {
    bank_key: HybridCrypto,
}

impl BankingSystem {
    fn process_transaction(
        &self,
        tx: &FinancialTransaction,
    ) -> quantum_shield::Result<(Vec<u8>, Vec<u8>)> {
        let tx_data = serde_json::to_vec(tx)?;
        
        // Encrypt transaction data
        let encrypted = self.bank_key.encrypt(
            &tx_data,
            &self.bank_key.public_keys(),
        )?;
        
        // Sign for audit trail
        let signature = self.bank_key.sign(&tx_data)?;
        
        Ok((
            serde_json::to_vec(&encrypted)?,
            serde_json::to_vec(&signature)?,
        ))
    }
    
    fn audit_transaction(
        &self,
        encrypted_data: &[u8],
        signature_data: &[u8],
    ) -> quantum_shield::Result<FinancialTransaction> {
        // Deserialize
        let encrypted: quantum_shield::HybridCiphertext = 
            serde_json::from_slice(encrypted_data)?;
        let signature: quantum_shield::HybridSignature = 
            serde_json::from_slice(signature_data)?;
        
        // Decrypt
        let tx_data = self.bank_key.decrypt(&encrypted)?;
        
        // Verify integrity
        let valid = HybridCrypto::verify(
            &tx_data,
            &signature,
            &self.bank_key.public_keys(),
        )?;
        
        if !valid {
            return Err(quantum_shield::Error::VerificationFailed);
        }
        
        // Parse transaction
        Ok(serde_json::from_slice(&tx_data)?)
    }
}
```

**Benefits:**
- Regulatory compliance for data retention
- Tamper-proof audit trails
- Protection against future quantum attacks

## 6. IoT and Embedded Systems

### Scenario: Secure Firmware Updates

**Requirements:**
- Firmware integrity verification
- Long-lived devices (10+ years)
- Over-the-air (OTA) updates

**Implementation:**

```rust
use quantum_shield::{HybridCrypto, HybridSignature};

struct FirmwareUpdate {
    version: String,
    binary: Vec<u8>,
    signature: HybridSignature,
}

struct IoTDevice {
    device_id: String,
    manufacturer_public_keys: quantum_shield::PublicKeys,
}

impl IoTDevice {
    fn verify_firmware_update(
        &self,
        update: &FirmwareUpdate,
    ) -> quantum_shield::Result<bool> {
        HybridCrypto::verify(
            &update.binary,
            &update.signature,
            &self.manufacturer_public_keys,
        )
    }
    
    fn apply_update(&mut self, update: FirmwareUpdate) -> quantum_shield::Result<()> {
        if !self.verify_firmware_update(&update)? {
            return Err(quantum_shield::Error::VerificationFailed);
        }
        
        // Apply firmware update
        println!("Firmware {} verified and applied", update.version);
        Ok(())
    }
}

struct Manufacturer {
    signing_key: HybridCrypto,
}

impl Manufacturer {
    fn sign_firmware(&self, version: String, binary: Vec<u8>) 
        -> quantum_shield::Result<FirmwareUpdate> 
    {
        let signature = self.signing_key.sign(&binary)?;
        
        Ok(FirmwareUpdate {
            version,
            binary,
            signature,
        })
    }
}
```

**Benefits:**
- Secure updates throughout device lifetime
- Prevents malicious firmware injection
- Future-proof device security

## 7. Cloud Storage Services

### Scenario: Zero-Knowledge Cloud Backup

**Requirements:**
- Client-side encryption
- Cloud provider cannot decrypt
- Long-term data storage

**Implementation:**

```rust
use quantum_shield::HybridCrypto;

struct CloudBackupClient {
    user_key: HybridCrypto,
}

impl CloudBackupClient {
    fn backup_file(&self, file_data: &[u8]) -> quantum_shield::Result<Vec<u8>> {
        // Encrypt with user's key
        let encrypted = self.user_key.encrypt(
            file_data,
            &self.user_key.public_keys(),
        )?;
        
        // Serialize for upload
        Ok(serde_json::to_vec(&encrypted)?)
    }
    
    fn restore_file(&self, encrypted_data: &[u8]) -> quantum_shield::Result<Vec<u8>> {
        let encrypted: quantum_shield::HybridCiphertext = 
            serde_json::from_slice(encrypted_data)?;
        
        self.user_key.decrypt(&encrypted)
    }
}
```

**Benefits:**
- True zero-knowledge architecture
- Cloud provider cannot access data
- Protection against data breaches

## Summary

Quantum Shield is ideal for:

✅ **Long-term data protection** (5+ years)
✅ **High-value targets** (medical, financial, government)
✅ **Blockchain applications** (cryptocurrency, smart contracts)
✅ **Compliance requirements** (HIPAA, financial regulations)
✅ **IoT security** (long-lived devices)
✅ **Zero-knowledge systems** (client-side encryption)

Choose Quantum Shield when:
- Data must remain secure for years/decades
- Regulatory compliance requires long-term protection
- Future quantum computers are a concern
- You need defense-in-depth security

## Next Steps

- Review [Security Model](./security-model.md) for guarantees
- Check [Performance](./performance.md) for benchmarks
- See [Migration Guide](./migration-guide.md) for adoption

