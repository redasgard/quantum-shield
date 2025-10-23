# Quantum Shield Documentation

Welcome to the Quantum Shield documentation. This library provides hybrid quantum-resistant cryptography using NIST-standardized post-quantum algorithms.

## Documentation Structure

- **[Architecture](./architecture.md)** - System design and component overview
- **[Getting Started](./getting-started.md)** - Quick start guide and basic usage
- **[User Guide](./user-guide.md)** - Comprehensive usage examples and patterns
- **[API Reference](./api-reference.md)** - Detailed API documentation
- **[Security Model](./security-model.md)** - Security guarantees and threat model
- **[Performance](./performance.md)** - Benchmarks and optimization guide
- **[Migration Guide](./migration-guide.md)** - Migrating from classical crypto
- **[FAQ](./faq.md)** - Frequently asked questions

## Quick Links

- [Why Quantum-Resistant Cryptography?](./why-quantum-resistant.md)
- [Algorithm Details](./algorithms.md)
- [Use Cases](./use-cases.md)
- [Contributing](./contributing.md)

## Overview

Quantum Shield combines classical cryptography (RSA-4096) with post-quantum algorithms (Kyber-1024, Dilithium5) for defense-in-depth against both current and future quantum computer attacks.

### Key Features

- ✅ **Hybrid Encryption**: RSA-4096 + Kyber-1024 (NIST Level 5)
- ✅ **Hybrid Signatures**: RSA-4096-PSS + Dilithium5 (NIST Level 5)
- ✅ **Defense in Depth**: Multiple independent security layers
- ✅ **Automatic Failover**: Falls back to Kyber if RSA decryption fails
- ✅ **NIST Standardized**: Uses FIPS 203 and FIPS 204 algorithms

### Quick Example

```rust
use quantum_shield::HybridCrypto;

// Generate keypairs
let alice = HybridCrypto::generate_keypair()?;
let bob = HybridCrypto::generate_keypair()?;

// Encrypt
let message = b"Secret message";
let encrypted = alice.encrypt(message, &bob.public_keys())?;

// Decrypt
let decrypted = bob.decrypt(&encrypted)?;
assert_eq!(message, &decrypted[..]);
```

## Support

- **GitHub**: https://github.com/redasgard/quantum-shield
- **Email**: hello@redasgard.com
- **Security Issues**: security@redasgard.com (private disclosure)

## License

MIT License - See [LICENSE-MIT](../LICENSE-MIT)

