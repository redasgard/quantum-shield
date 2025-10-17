# Quantum Shield

Hybrid quantum-resistant cryptography library using NIST-standardized post-quantum algorithms.

Combines classical cryptography (RSA-4096) with post-quantum algorithms (Kyber-1024, Dilithium5) for defense-in-depth against both current and future quantum computer attacks.

## Features

- Hybrid Encryption: RSA-4096 + Kyber-1024 (NIST Level 5)
- Hybrid Signatures: RSA-4096-PSS + Dilithium5 (NIST Level 5)
- Defense in Depth: Multiple independent security layers
- Automatic Failover: Falls back to Kyber if RSA decryption fails
- Minimal allocations where possible

## Security Level

NIST Level 5 (equivalent to AES-256 security)
- Uses lattice-based cryptography (Kyber, Dilithium)
- Resistant to Shor's algorithm
- Mitigates Grover's algorithm impact
- Maintains classical security guarantees

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
quantum-shield = "0.1"
```

### Hybrid Encryption Example

```rust
use quantum_shield::{HybridCrypto, KeyPair};

// Generate keypairs
let alice = HybridCrypto::generate_keypair()?;
let bob = HybridCrypto::generate_keypair()?;

// Alice encrypts a message for Bob
let message = b"Secret quantum-resistant message";
let encrypted = alice.encrypt(message, &bob.public_keys())?;

// Bob decrypts the message
let decrypted = bob.decrypt(&encrypted)?;

assert_eq!(message, &decrypted[..]);
```

### Hybrid Signatures Example

```rust
use quantum_shield::HybridCrypto;

let alice = HybridCrypto::generate_keypair()?;

// Alice signs a message
let message = b"I agree to these terms";
let signature = alice.sign(message)?;

// Anyone can verify with Alice's public key
let valid = alice.verify(message, &signature, &alice.public_keys())?;
assert!(valid);
```

## Use Cases

- Secure Communication: Server-worker, client-server, peer-to-peer
- Digital Signatures: Code signing, document signing, authentication
- Data Protection: Long-term data encryption
- Blockchain/Web3: Quantum-resistant transactions
- IoT Security: Post-quantum protection for embedded systems

## Algorithms

### Encryption
- **AES-256-GCM**: Symmetric encryption (NIST approved)
- **RSA-4096-OAEP**: Classical public-key encryption
- **Kyber-1024**: NIST-selected post-quantum KEM (FIPS 203)

### Signatures
- **RSA-4096-PSS**: Classical digital signatures
- **Dilithium5**: NIST-selected post-quantum signatures (FIPS 204)

### Hashing
- **SHA3-256**: Quantum-resistant hashing (NIST approved)

## Architecture

### Hybrid Encryption

```
1. Generate random AES-256 key
2. Encrypt message with AES-256-GCM
3. Encrypt AES key with RSA-4096      ← Classical layer
4. Encrypt AES key with Kyber-1024    ← Post-quantum layer
5. Return: [ciphertext, enc_key_rsa, enc_key_kyber]

Decryption:
1. Try to decrypt key with RSA
2. If RSA fails, use Kyber (automatic failover)
3. Decrypt message with recovered key

Security = MAX(RSA security, Kyber security)
```

### Why Hybrid?

Defense against unknown threats:
- If quantum computers break RSA → Kyber maintains security
- If Kyber has undiscovered weakness → RSA maintains security
- Security = MAX(RSA security, Kyber security)

## Performance

| Operation | Time | Note |
|-----------|------|------|
| Key generation | ~100ms | RSA is slow, but one-time |
| Encryption | ~1-2ms | Per message |
| Decryption | ~1-2ms | Per message |
| Signing | ~0.5ms | Per message |
| Verification | ~0.3ms | Per message |

Note: Post-quantum algorithms (Kyber, Dilithium) have faster signing/verification than RSA-4096.

## API Overview

```rust
// Core functionality
HybridCrypto::generate_keypair()         // Generate all keys
encrypt(data, recipient_pubkeys)         // Hybrid encrypt
decrypt(encrypted_data)                  // Hybrid decrypt (auto-failover)
sign(message)                            // Hybrid sign
verify(message, signature, pubkeys)      // Verify hybrid signature

// Key management
public_keys()                            // Export public keys
PublicKeys::to_json()                    // Serialize to JSON
PublicKeys::from_json(json)              // Deserialize from JSON
```

## Examples

See [`examples/basic_usage.rs`](examples/basic_usage.rs) for a complete example showing encryption, decryption, signing, and verification.

## Testing

```bash
# Run tests
cargo test

# Run example
cargo run --example basic_usage
```

## Security Considerations

### Strengths
- NIST-standardized algorithms (FIPS 203, FIPS 204)
- Multiple independent security layers
- Automatic failover on decryption
- Resistant to known quantum attacks
- Maintains classical security properties

### Limitations
- Not a complete protocol (no key exchange mechanism)
- Requires secure key storage
- Vulnerable to side-channel attacks without constant-time implementations
- Larger key and ciphertext sizes than classical-only crypto

### Recommendations
1. Security audit recommended before deployment
2. Store private keys securely (encrypted storage, access controls)
3. Implement key rotation policies
4. Monitor NIST updates for algorithm changes
5. Consider HSM for key storage in sensitive applications

## Standards Compliance

- FIPS 203: Module-Lattice-Based Key-Encapsulation (Kyber)
- FIPS 204: Module-Lattice-Based Digital Signature (Dilithium)
- FIPS 202: SHA-3 Standard
- NIST SP 800-56B: RSA Key Agreement
- NIST SP 800-131A: Cryptographic Algorithm Policy

## Roadmap

- [x] Core hybrid encryption (v0.1)
- [x] Core hybrid signatures (v0.1)
- [x] Key management (v0.1)
- [ ] Async support (v0.2)
- [ ] No-std support (v0.2)
- [ ] WASM support (v0.3)
- [ ] Hardware acceleration (v0.4)
- [ ] Additional PQC algorithms (SPHINCS+, etc.) (v0.5)

## Security Audits

This library has not undergone professional security audit.

For security vulnerabilities, email security@redasgard.com instead of opening public issues.

## License

MIT License - see [LICENSE-MIT](LICENSE-MIT)

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203: Kyber](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: Dilithium](https://csrc.nist.gov/pubs/fips/204/final)
- [pqcrypto Rust library](https://github.com/rustpq/pqcrypto)


