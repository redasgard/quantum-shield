# API Reference

Complete API documentation for Quantum Shield.

## Core Types

### HybridCrypto

Main interface for all cryptographic operations.

```rust
pub struct HybridCrypto { /* private fields */ }
```

#### Methods

##### `generate_keypair()`

```rust
pub fn generate_keypair() -> Result<Self>
```

Generate a new hybrid keypair containing both classical (RSA-4096) and post-quantum (Kyber-1024, Dilithium5) keys.

**Returns:** `Result<HybridCrypto>` - New instance with generated keys

**Time Complexity:** O(n) where n = key size, ~100ms

**Example:**
```rust
let alice = HybridCrypto::generate_keypair()?;
```

##### `encrypt()`

```rust
pub fn encrypt(&self, data: &[u8], recipient_public_keys: &PublicKeys) -> Result<HybridCiphertext>
```

Encrypt data using hybrid encryption (AES-256 + RSA-4096 + Kyber-1024).

**Parameters:**
- `data` - Data to encrypt
- `recipient_public_keys` - Recipient's public keys

**Returns:** `Result<HybridCiphertext>` - Encrypted data with both classical and PQ layers

**Example:**
```rust
let encrypted = alice.encrypt(b"secret", &bob.public_keys())?;
```

##### `decrypt()`

```rust
pub fn decrypt(&self, ciphertext: &HybridCiphertext) -> Result<Vec<u8>>
```

Decrypt data using hybrid decryption with automatic failover.

**Parameters:**
- `ciphertext` - Encrypted data

**Returns:** `Result<Vec<u8>>` - Decrypted plaintext

**Behavior:** Tries RSA first, falls back to Kyber on failure

**Example:**
```rust
let decrypted = bob.decrypt(&encrypted)?;
```

##### `sign()`

```rust
pub fn sign(&self, message: &[u8]) -> Result<HybridSignature>
```

Sign a message using hybrid signatures (RSA-PSS + Dilithium5).

**Parameters:**
- `message` - Message to sign

**Returns:** `Result<HybridSignature>` - Dual signature

**Example:**
```rust
let signature = alice.sign(b"document")?;
```

##### `verify()`

```rust
pub fn verify(message: &[u8], signature: &HybridSignature, public_keys: &PublicKeys) -> Result<bool>
```

Verify a hybrid signature. Both RSA and Dilithium signatures must be valid.

**Parameters:**
- `message` - Original message
- `signature` - Signature to verify
- `public_keys` - Signer's public keys

**Returns:** `Result<bool>` - true if valid, false otherwise

**Example:**
```rust
let valid = HybridCrypto::verify(b"document", &signature, &alice.public_keys())?;
```

##### `public_keys()`

```rust
pub fn public_keys(&self) -> PublicKeys
```

Get public keys for sharing.

**Returns:** `PublicKeys` - Public RSA and Kyber keys

**Example:**
```rust
let pub_keys = alice.public_keys();
```

---

### PublicKeys

Container for public keys.

```rust
pub struct PublicKeys {
    pub rsa: RsaPublicKey,
    pub kyber: Vec<u8>,
}
```

#### Methods

##### `to_json()`

```rust
pub fn to_json(&self) -> Result<String>
```

Serialize public keys to JSON.

**Returns:** `Result<String>` - JSON string

**Example:**
```rust
let json = public_keys.to_json()?;
std::fs::write("alice_public.json", json)?;
```

##### `from_json()`

```rust
pub fn from_json(json: &str) -> Result<Self>
```

Deserialize public keys from JSON.

**Parameters:**
- `json` - JSON string

**Returns:** `Result<PublicKeys>` - Deserialized keys

**Example:**
```rust
let json = std::fs::read_to_string("alice_public.json")?;
let keys = PublicKeys::from_json(&json)?;
```

---

### HybridCiphertext

Encrypted data structure.

```rust
pub struct HybridCiphertext {
    pub version: CryptoVersion,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub encrypted_key_rsa: Vec<u8>,
    pub encrypted_key_kyber: Vec<u8>,
}
```

**Fields:**
- `version` - Algorithm version (for future upgrades)
- `ciphertext` - AES-256-GCM encrypted data
- `nonce` - AES-GCM nonce (96 bits)
- `encrypted_key_rsa` - RSA-encrypted AES key
- `encrypted_key_kyber` - Kyber-encrypted AES key

**Serialization:** Implements `Serialize` and `Deserialize`

---

### HybridSignature

Dual signature structure.

```rust
pub struct HybridSignature {
    pub rsa_signature: Vec<u8>,
    pub dilithium_signature: Vec<u8>,
}
```

**Fields:**
- `rsa_signature` - RSA-4096-PSS signature (~512 bytes)
- `dilithium_signature` - Dilithium5 signature (~4KB)

**Serialization:** Implements `Serialize` and `Deserialize`

---

### KeyPair

Combined public and private keys.

```rust
pub struct KeyPair {
    // Private fields
}
```

#### Methods

##### `public_keys()`

```rust
pub fn public_keys(&self) -> PublicKeys
```

Extract public keys from keypair.

##### `private_keys()`

```rust
pub fn private_keys(&self) -> &PrivateKeys
```

Get reference to private keys (use carefully).

---

## Error Types

### Error

Main error enum.

```rust
pub enum Error {
    KeyGenerationFailed,
    EncryptionFailed,
    DecryptionFailed,
    SigningFailed,
    VerificationFailed,
    InvalidCiphertext,
    InvalidSignature,
    InvalidInput(String),
    SerializationError(String),
}
```

**Variants:**
- `KeyGenerationFailed` - Failed to generate keypair
- `EncryptionFailed` - Encryption operation failed
- `DecryptionFailed` - Decryption operation failed
- `SigningFailed` - Signing operation failed
- `VerificationFailed` - Signature verification failed
- `InvalidCiphertext` - Malformed ciphertext
- `InvalidSignature` - Malformed signature
- `InvalidInput(String)` - Invalid input parameter
- `SerializationError(String)` - JSON serialization error

### Result

Type alias for operations.

```rust
pub type Result<T> = std::result::Result<T, Error>;
```

---

## Prelude Module

Convenience re-exports.

```rust
pub mod prelude {
    pub use crate::{HybridCrypto, PublicKeys, PrivateKeys, KeyPair, Result};
    pub use crate::{HybridCiphertext, HybridSignature};
}
```

**Usage:**
```rust
use quantum_shield::prelude::*;
```

---

## Algorithm Details

### Encryption Stack

```
User Data
    ↓
AES-256-GCM (symmetric)
    ↓
RSA-4096-OAEP (classical KEK)
    ↓
Kyber-1024 (post-quantum KEK)
    ↓
HybridCiphertext
```

### Signature Stack

```
Message
    ↓
SHA3-256 (hash)
    ↓
RSA-4096-PSS (classical sig) + Dilithium5 (PQ sig)
    ↓
HybridSignature
```

---

## Constants

```rust
// Key sizes
const RSA_KEY_SIZE: usize = 4096;
const KYBER_VARIANT: Kyber = Kyber1024;
const DILITHIUM_VARIANT: Dilithium = Dilithium5;

// Nonce size
const AES_NONCE_SIZE: usize = 12;  // 96 bits

// Security level
const NIST_LEVEL: u8 = 5;  // AES-256 equivalent
```

---

## Performance Characteristics

| Operation | Time | Throughput |
|-----------|------|------------|
| `generate_keypair()` | ~100ms | 10/sec |
| `encrypt()` | ~1-2ms | 500-1000/sec |
| `decrypt()` | ~1-2ms | 500-1000/sec |
| `sign()` | ~0.5ms | 2000/sec |
| `verify()` | ~0.3ms | 3000/sec |

---

## Size Reference

| Type | Size |
|------|------|
| `PublicKeys` (serialized) | ~2KB |
| `HybridCiphertext` overhead | ~1KB |
| `HybridSignature` | ~4.5KB |
| Message size impact | + 1KB overhead |

---

## Thread Safety

All types are `Send + Sync`:
- `HybridCrypto`: Thread-safe
- `PublicKeys`: Thread-safe
- `HybridCiphertext`: Thread-safe
- `HybridSignature`: Thread-safe

Safe for concurrent operations across threads.

---

## Example Patterns

### Key Management

```rust
// Generate and save
let alice = HybridCrypto::generate_keypair()?;
let json = alice.public_keys().to_json()?;
std::fs::write("alice.pub", json)?;

// Load
let json = std::fs::read_to_string("alice.pub")?;
let keys = PublicKeys::from_json(&json)?;
```

### Secure Communication

```rust
// Alice sends to Bob
let encrypted = alice.encrypt(message, &bob.public_keys())?;
let signature = alice.sign(message)?;

// Bob receives from Alice
let decrypted = bob.decrypt(&encrypted)?;
let valid = HybridCrypto::verify(&decrypted, &signature, &alice.public_keys())?;
```

### Data at Rest

```rust
// Encrypt for self
let encrypted = alice.encrypt(data, &alice.public_keys())?;
// Store encrypted...

// Decrypt later
let decrypted = alice.decrypt(&encrypted)?;
```

---

## Version Compatibility

Current version: `0.1.0`

**Backward Compatibility:** The `CryptoVersion` field in `HybridCiphertext` enables future algorithm upgrades while maintaining backward compatibility.

**Forward Compatibility:** Code using v0.1 will work with future versions. Decryption of future-versioned ciphertexts will fail gracefully with clear error.

