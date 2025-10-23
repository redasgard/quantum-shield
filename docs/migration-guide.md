# Migration Guide

Guide for migrating from classical cryptography to Quantum Shield.

## Overview

This guide helps you transition from:
- Pure RSA encryption/signatures
- OpenSSL-based crypto
- Other classical cryptography libraries

to quantum-resistant Quantum Shield.

## Migration Paths

### Path 1: From RSA Encryption

**Before (RSA-4096 with OpenSSL):**
```rust
use openssl::rsa::{Rsa, Padding};
use openssl::symm::{encrypt, Cipher};

// Generate RSA keypair
let rsa = Rsa::generate(4096)?;
let public_key = rsa.public_key_to_pem()?;

// Encrypt data
let encrypted = rsa.public_encrypt(&data, Padding::PKCS1_OAEP)?;
```

**After (Quantum Shield):**
```rust
use quantum_shield::HybridCrypto;

// Generate hybrid keypair
let crypto = HybridCrypto::generate_keypair()?;
let public_keys = crypto.public_keys();

// Encrypt data
let encrypted = crypto.encrypt(&data, &public_keys)?;
```

**Changes:**
- Single `generate_keypair()` call instead of manual RSA generation
- `encrypt()` handles AES + RSA + Kyber automatically
- Returns structured `HybridCiphertext` instead of raw bytes

### Path 2: From RSA Signatures

**Before (RSA-PSS):**
```rust
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;

let keypair = Rsa::generate(4096)?;
let pkey = PKey::from_rsa(keypair)?;

let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
signer.update(&message)?;
let signature = signer.sign_to_vec()?;

let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
verifier.update(&message)?;
let valid = verifier.verify(&signature)?;
```

**After (Quantum Shield):**
```rust
use quantum_shield::HybridCrypto;

let crypto = HybridCrypto::generate_keypair()?;

let signature = crypto.sign(&message)?;

let valid = HybridCrypto::verify(&message, &signature, &crypto.public_keys())?;
```

**Changes:**
- Simpler API, no manual hasher setup
- Automatic dual signatures (RSA + Dilithium)
- Type-safe `HybridSignature` structure

### Path 3: From Ring/AWS-LC

**Before (Ring):**
```rust
use ring::signature::{self, KeyPair};
use ring::rand::SystemRandom;

let rng = SystemRandom::new();
let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;

let signature = key_pair.sign(message);
```

**After (Quantum Shield):**
```rust
use quantum_shield::HybridCrypto;

let crypto = HybridCrypto::generate_keypair()?;
let signature = crypto.sign(message)?;
```

**Changes:**
- Switch from Ed25519 to hybrid RSA+Dilithium
- Automatic key generation without explicit RNG
- Quantum-resistant signatures

## Step-by-Step Migration

### Step 1: Add Dependency

```toml
# Remove old dependencies
# openssl = "0.10"
# ring = "0.17"

# Add Quantum Shield
[dependencies]
quantum-shield = "0.1"
```

### Step 2: Update Key Generation

```rust
// Old
let rsa = Rsa::generate(4096)?;

// New
let crypto = HybridCrypto::generate_keypair()?;
```

### Step 3: Update Encryption

```rust
// Old
let encrypted = rsa.public_encrypt(&data, Padding::PKCS1_OAEP)?;

// New
let encrypted = crypto.encrypt(&data, &recipient_public_keys)?;
```

### Step 4: Update Decryption

```rust
// Old
let decrypted = rsa.private_decrypt(&encrypted, Padding::PKCS1_OAEP)?;

// New
let decrypted = crypto.decrypt(&encrypted)?;
```

### Step 5: Update Signing

```rust
// Old
let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
signer.update(&message)?;
let signature = signer.sign_to_vec()?;

// New
let signature = crypto.sign(&message)?;
```

### Step 6: Update Verification

```rust
// Old
let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
verifier.update(&message)?;
let valid = verifier.verify(&signature)?;

// New
let valid = HybridCrypto::verify(&message, &signature, &public_keys)?;
```

### Step 7: Update Key Storage

```rust
// Old (OpenSSL PEM)
let pem = rsa.public_key_to_pem()?;
std::fs::write("key.pem", pem)?;

// New (JSON)
let json = public_keys.to_json()?;
std::fs::write("key.json", json)?;
```

### Step 8: Update Key Loading

```rust
// Old (OpenSSL PEM)
let pem = std::fs::read("key.pem")?;
let rsa = Rsa::public_key_from_pem(&pem)?;

// New (JSON)
let json = std::fs::read_to_string("key.json")?;
let public_keys = PublicKeys::from_json(&json)?;
```

## Data Migration

### Encrypted Data

**Problem:** Existing RSA-encrypted data cannot be decrypted by Quantum Shield directly.

**Solution:**

```rust
// 1. Decrypt with old RSA keys
let old_decrypted = old_rsa.private_decrypt(&old_encrypted, Padding::PKCS1_OAEP)?;

// 2. Re-encrypt with Quantum Shield
let new_encrypted = crypto.encrypt(&old_decrypted, &new_public_keys)?;

// 3. Store new encrypted data
save_encrypted(&new_encrypted)?;
```

### Signed Data

**Problem:** Old RSA signatures won't verify with Quantum Shield.

**Solution:** Re-sign all important documents

```rust
// 1. Verify with old keys (optional)
let old_valid = old_verify(&message, &old_signature)?;

// 2. Generate new signature
let new_signature = crypto.sign(&message)?;

// 3. Store new signature
save_signature(&new_signature)?;
```

## Compatibility Strategies

### Strategy 1: Parallel Operation (Recommended)

Run both systems in parallel during transition:

```rust
struct DualCrypto {
    old_rsa: Rsa,
    new_crypto: HybridCrypto,
}

impl DualCrypto {
    fn encrypt(&self, data: &[u8]) -> (Vec<u8>, HybridCiphertext) {
        let old = self.old_rsa.public_encrypt(data, Padding::PKCS1_OAEP).unwrap();
        let new = self.new_crypto.encrypt(data, &self.new_crypto.public_keys()).unwrap();
        (old, new)
    }
    
    fn decrypt(&self, old: Option<&[u8]>, new: Option<&HybridCiphertext>) -> Vec<u8> {
        if let Some(n) = new {
            self.new_crypto.decrypt(n).unwrap()
        } else if let Some(o) = old {
            self.old_rsa.private_decrypt(o, Padding::PKCS1_OAEP).unwrap()
        } else {
            panic!("No ciphertext provided");
        }
    }
}
```

**Benefit:** Zero downtime, gradual migration

### Strategy 2: Version Field

Add version field to indicate encryption type:

```rust
#[derive(Serialize, Deserialize)]
enum EncryptedData {
    V1Rsa(Vec<u8>),
    V2Hybrid(HybridCiphertext),
}

fn decrypt(data: EncryptedData) -> Result<Vec<u8>> {
    match data {
        EncryptedData::V1Rsa(old) => decrypt_with_rsa(old),
        EncryptedData::V2Hybrid(new) => crypto.decrypt(&new),
    }
}
```

**Benefit:** Clear versioning, easy rollback

### Strategy 3: Big Bang (Not Recommended)

Switch all systems simultaneously.

**Risks:**
- Requires coordination
- No fallback
- High risk of data loss

## Performance Considerations

### Before Migration

| Operation | RSA-4096 Time |
|-----------|---------------|
| Key Gen | 90ms |
| Encrypt | 0.85ms |
| Decrypt | 0.75ms |
| Sign | 0.30ms |
| Verify | 0.12ms |

### After Migration

| Operation | Quantum Shield Time | Overhead |
|-----------|---------------------|----------|
| Key Gen | 100ms | +11% |
| Encrypt | 1.2ms | +41% |
| Decrypt | 1.0ms | +33% |
| Sign | 0.5ms | +67% |
| Verify | 0.3ms | +150% |

**Mitigation:**
- Cache generated keys (one-time cost)
- Parallel operations for batch processing
- Use streaming for large data

## Testing Strategy

### Phase 1: Unit Tests

```rust
#[cfg(test)]
mod migration_tests {
    #[test]
    fn test_encrypt_decrypt_equivalence() {
        // Ensure old and new systems produce same plaintext
        let data = b"test data";
        
        // Old system
        let old_encrypted = old_encrypt(data);
        let old_decrypted = old_decrypt(&old_encrypted);
        
        // New system
        let new_encrypted = new_encrypt(data);
        let new_decrypted = new_decrypt(&new_encrypted);
        
        assert_eq!(old_decrypted, new_decrypted);
        assert_eq!(old_decrypted, data);
    }
}
```

### Phase 2: Integration Tests

```rust
#[test]
fn test_cross_version_communication() {
    // Client with old crypto, server with new
    let old_client = OldCrypto::new();
    let new_server = NewCrypto::new();
    
    // Client encrypts with old
    let encrypted = old_client.encrypt(data);
    
    // Server decrypts (should handle both)
    let decrypted = new_server.decrypt_any(encrypted);
    
    assert_eq!(decrypted, data);
}
```

### Phase 3: Load Tests

```rust
#[test]
fn test_performance_regression() {
    let start = Instant::now();
    for _ in 0..1000 {
        crypto.encrypt(data, &keys)?;
    }
    let duration = start.elapsed();
    
    // Ensure acceptable performance
    assert!(duration < Duration::from_secs(2));
}
```

## Rollback Plan

If migration fails:

### Immediate Rollback

```rust
// Feature flag to switch back
#[cfg(feature = "use-quantum-shield")]
use quantum_shield::HybridCrypto as Crypto;

#[cfg(not(feature = "use-quantum-shield"))]
use openssl::rsa::Rsa as Crypto;
```

### Data Recovery

```rust
// Decrypt with new, re-encrypt with old
fn rollback_data(new_encrypted: &HybridCiphertext) -> Result<Vec<u8>> {
    let plaintext = new_crypto.decrypt(new_encrypted)?;
    let old_encrypted = old_rsa.public_encrypt(&plaintext, Padding::PKCS1_OAEP)?;
    Ok(old_encrypted)
}
```

## Common Pitfalls

### ❌ Pitfall 1: Forgetting Error Handling

```rust
// Bad
let encrypted = crypto.encrypt(data, &keys).unwrap();

// Good
let encrypted = crypto.encrypt(data, &keys)
    .context("Failed to encrypt data")?;
```

### ❌ Pitfall 2: Key Format Mismatch

```rust
// Bad: Trying to load RSA PEM as Quantum Shield
let pem = std::fs::read("old_key.pem")?;
let keys = PublicKeys::from_json(&pem)?; // ERROR!

// Good: Migrate keys first
let pem = std::fs::read("old_key.pem")?;
let old_rsa = Rsa::public_key_from_pem(&pem)?;
// Generate new Quantum Shield keys
let new_crypto = HybridCrypto::generate_keypair()?;
```

### ❌ Pitfall 3: Not Testing Backward Compatibility

Ensure old clients can still communicate during migration period.

### ❌ Pitfall 4: Insufficient Rollback Plan

Always have a way to roll back to old system.

## Timeline Example

### Week 1-2: Planning
- Audit current crypto usage
- Identify all encryption points
- Plan migration strategy

### Week 3-4: Development
- Add Quantum Shield dependency
- Implement parallel operation
- Add feature flags

### Week 5-6: Testing
- Unit tests
- Integration tests
- Performance tests
- Security review

### Week 7: Staging Deployment
- Deploy to staging
- Monitor for issues
- Validate functionality

### Week 8: Production Deployment
- Gradual rollout (10% → 50% → 100%)
- Monitor metrics
- Be ready to rollback

### Week 9+: Data Migration
- Gradually re-encrypt old data
- Retire old crypto system
- Remove old dependencies

## Support

- **Migration Issues**: hello@redasgard.com
- **GitHub**: https://github.com/redasgard/quantum-shield/issues
- **Documentation**: https://docs.rs/quantum-shield

## Checklist

- [ ] Audit current crypto usage
- [ ] Add Quantum Shield dependency
- [ ] Update key generation
- [ ] Update encryption/decryption
- [ ] Update signing/verification
- [ ] Migrate key storage format
- [ ] Implement parallel operation
- [ ] Add version detection
- [ ] Write unit tests
- [ ] Write integration tests
- [ ] Performance test
- [ ] Security review
- [ ] Document rollback plan
- [ ] Deploy to staging
- [ ] Deploy to production
- [ ] Migrate existing data
- [ ] Monitor and optimize
- [ ] Remove old dependencies

