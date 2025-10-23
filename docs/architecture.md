# Architecture

## System Overview

Quantum Shield implements a **hybrid cryptographic system** that combines classical and post-quantum algorithms to provide defense-in-depth security against both current and future threats.

```
┌─────────────────────────────────────────────────────────────┐
│                     Quantum Shield                           │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐         ┌──────────────┐                  │
│  │ HybridCrypto │         │  Key Pairs   │                  │
│  │              │◄────────┤              │                  │
│  │ - encrypt()  │         │ - Classical  │                  │
│  │ - decrypt()  │         │ - Post-Q     │                  │
│  │ - sign()     │         └──────────────┘                  │
│  │ - verify()   │                                            │
│  └──────┬───────┘                                            │
│         │                                                     │
│    ┌────┴────────────────────────┐                          │
│    │                              │                          │
│    ▼                              ▼                          │
│ ┌──────────────┐          ┌──────────────┐                  │
│ │  Classical   │          │ Post-Quantum │                  │
│ │  Crypto      │          │   Crypto     │                  │
│ ├──────────────┤          ├──────────────┤                  │
│ │ RSA-4096     │          │ Kyber-1024   │                  │
│ │ RSA-PSS      │          │ Dilithium5   │                  │
│ │ AES-256-GCM  │          │ SHA3-256     │                  │
│ └──────────────┘          └──────────────┘                  │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. HybridCrypto

Main interface for all cryptographic operations.

**Responsibilities:**
- Key pair generation
- Hybrid encryption/decryption
- Hybrid signing/verification
- Automatic failover management

**Location:** `src/crypto.rs`

### 2. KeyPair System

Manages both classical and post-quantum key pairs.

**Components:**
- `PublicKeys` - Container for public RSA and Kyber keys
- `PrivateKeys` - Container for private RSA, Kyber, and Dilithium keys
- `KeyPair` - Wrapper combining public and private keys

**Location:** `src/keys.rs`

### 3. Cryptographic Types

Type definitions for encrypted data and signatures.

**Components:**
- `HybridCiphertext` - Encrypted data with versioning
- `HybridSignature` - Dual signatures (RSA + Dilithium)
- `CryptoVersion` - Version tracking for algorithm changes

**Location:** `src/types.rs`

### 4. Error Handling

Comprehensive error types for all operations.

**Location:** `src/error.rs`

## Hybrid Encryption Flow

### Encryption Process

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Generate Random AES-256 Key                               │
└────────────────────┬────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Encrypt Message with AES-256-GCM                          │
│    Output: Ciphertext + Nonce                                │
└────────────────────┬────────────────────────────────────────┘
                     ▼
      ┌──────────────┴──────────────┐
      │                              │
      ▼                              ▼
┌──────────────┐              ┌──────────────┐
│ 3a. Encrypt  │              │ 3b. Encrypt  │
│ AES key with │              │ AES key with │
│ RSA-4096-OAEP│              │ Kyber-1024   │
└──────┬───────┘              └──────┬───────┘
       │                              │
       └──────────────┬───────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Combine into HybridCiphertext                             │
│    - version                                                  │
│    - ciphertext (AES encrypted data)                         │
│    - nonce (AES-GCM nonce)                                   │
│    - encrypted_key_rsa (RSA-wrapped key)                     │
│    - encrypted_key_kyber (Kyber-wrapped key)                 │
└─────────────────────────────────────────────────────────────┘
```

### Decryption Process

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Receive HybridCiphertext                                  │
└────────────────────┬────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Try to decrypt AES key with RSA                          │
└────────────────────┬────────────────────────────────────────┘
                     ▼
              ┌──────┴──────┐
              │             │
         Success         Failure
              │             │
              │             ▼
              │      ┌──────────────┐
              │      │ 3. Fallback: │
              │      │ Decrypt with │
              │      │ Kyber-1024   │
              │      └──────┬───────┘
              │             │
              └──────┬──────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Decrypt message with recovered AES key                    │
└─────────────────────────────────────────────────────────────┘
```

**Key Insight:** Security = MAX(RSA security, Kyber security)

If either layer is broken, the other maintains confidentiality.

## Hybrid Signature Flow

### Signing Process

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Hash message with SHA3-256                                │
└────────────────────┬────────────────────────────────────────┘
                     ▼
      ┌──────────────┴──────────────┐
      │                              │
      ▼                              ▼
┌──────────────┐              ┌──────────────┐
│ 2a. Sign     │              │ 2b. Sign     │
│ with RSA-PSS │              │ with         │
│              │              │ Dilithium5   │
└──────┬───────┘              └──────┬───────┘
       │                              │
       └──────────────┬───────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Combine into HybridSignature                              │
│    - rsa_signature                                           │
│    - dilithium_signature                                     │
└─────────────────────────────────────────────────────────────┘
```

### Verification Process

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Receive message + HybridSignature                         │
└────────────────────┬────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Hash message with SHA3-256                                │
└────────────────────┬────────────────────────────────────────┘
                     ▼
      ┌──────────────┴──────────────┐
      │                              │
      ▼                              ▼
┌──────────────┐              ┌──────────────┐
│ 3a. Verify   │              │ 3b. Verify   │
│ RSA-PSS      │              │ Dilithium5   │
│ signature    │              │ signature    │
└──────┬───────┘              └──────┬───────┘
       │                              │
       └──────────────┬───────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Both must be valid for success                            │
└─────────────────────────────────────────────────────────────┘
```

**Key Insight:** Both signatures must validate. This provides the strongest authentication guarantee.

## Security Architecture

### Defense-in-Depth Layers

1. **Layer 1: Classical Cryptography**
   - RSA-4096 for encryption (current best practice)
   - RSA-4096-PSS for signatures
   - AES-256-GCM for symmetric encryption

2. **Layer 2: Post-Quantum Cryptography**
   - Kyber-1024 for key encapsulation (NIST Level 5)
   - Dilithium5 for signatures (NIST Level 5)
   - SHA3-256 for hashing

3. **Layer 3: Hybrid Construction**
   - Independent operation of both layers
   - Automatic failover on decryption
   - Dual verification on signatures

### Threat Model

**Protected Against:**
- ✅ Classical attacks (brute force, cryptanalysis)
- ✅ Shor's algorithm (quantum factoring)
- ✅ Grover's algorithm (quantum search)
- ✅ Unknown weaknesses in individual algorithms
- ✅ Future quantum computers

**Not Protected Against:**
- ❌ Side-channel attacks (timing, power analysis)
- ❌ Compromised keys (secure storage required)
- ❌ Implementation bugs (audits recommended)
- ❌ Man-in-the-middle (needs separate authentication)

## Data Structures

### HybridCiphertext

```rust
pub struct HybridCiphertext {
    pub version: CryptoVersion,           // Algorithm version
    pub ciphertext: Vec<u8>,              // AES-256-GCM encrypted data
    pub nonce: [u8; 12],                  // AES-GCM nonce
    pub encrypted_key_rsa: Vec<u8>,       // RSA-wrapped AES key
    pub encrypted_key_kyber: Vec<u8>,     // Kyber-wrapped AES key
}
```

**Size:** ~1KB + message size

### HybridSignature

```rust
pub struct HybridSignature {
    pub rsa_signature: Vec<u8>,           // RSA-PSS signature
    pub dilithium_signature: Vec<u8>,     // Dilithium5 signature
}
```

**Size:** ~4.5KB (512 bytes RSA + ~4KB Dilithium)

### PublicKeys

```rust
pub struct PublicKeys {
    pub rsa: RsaPublicKey,                // Classical public key
    pub kyber: Vec<u8>,                   // PQ public key (1568 bytes)
}
```

**Serialized Size:** ~2KB

## Algorithm Selection

### Why These Algorithms?

| Algorithm | Purpose | Reason |
|-----------|---------|--------|
| RSA-4096 | Classical encryption/signing | Industry standard, well-vetted, 128-bit security |
| Kyber-1024 | PQ key encapsulation | NIST selected, lattice-based, NIST Level 5 |
| Dilithium5 | PQ signatures | NIST selected, lattice-based, NIST Level 5 |
| AES-256-GCM | Symmetric encryption | Quantum-resistant, authenticated encryption |
| SHA3-256 | Hashing | Quantum-resistant, NIST approved |

### NIST Security Levels

- **Level 1**: Equivalent to AES-128 (broken by quantum search)
- **Level 2**: Better than Level 1
- **Level 3**: Equivalent to AES-192
- **Level 4**: Better than Level 3
- **Level 5**: Equivalent to AES-256 ← **We use this**

## Performance Characteristics

### Key Generation
- **Time:** ~100-150ms
- **Bottleneck:** RSA key generation
- **Recommendation:** Generate once, reuse

### Encryption
- **Time:** ~1-2ms per message
- **Bottleneck:** RSA encryption
- **Throughput:** ~500-1000 messages/sec

### Decryption
- **Time:** ~1-2ms per message
- **Success:** RSA first (fast), Kyber fallback
- **Throughput:** ~500-1000 messages/sec

### Signing
- **Time:** ~0.5ms per message
- **Note:** Dilithium is faster than RSA
- **Throughput:** ~2000 signatures/sec

### Verification
- **Time:** ~0.3ms per message
- **Note:** Both signatures checked
- **Throughput:** ~3000 verifications/sec

## Future Extensions

### v0.2 Roadmap
- Async support (tokio integration)
- No-std support (embedded systems)
- Streaming API (large files)

### v0.3 Roadmap
- WASM support (browser)
- Additional PQ algorithms (SPHINCS+)
- Hardware acceleration (AES-NI, AVX2)

### v0.4 Roadmap
- Key rotation mechanisms
- Forward secrecy
- Threshold cryptography

