# FAQ

## General Questions

### What is Quantum Shield?

Quantum Shield is a hybrid quantum-resistant cryptography library that combines classical (RSA-4096) and post-quantum (Kyber-1024, Dilithium5) algorithms for defense-in-depth security.

### Why do I need quantum-resistant cryptography?

Future quantum computers will break RSA and ECC encryption. Data encrypted today can be stored and decrypted later when quantum computers are available ("harvest now, decrypt later" attack). Quantum Shield protects against this threat.

### When will quantum computers break current encryption?

Estimates range from 5-20 years. The threat isn't when quantum computers are available, but that adversaries are collecting encrypted data NOW to decrypt LATER.

### Is Quantum Shield production-ready?

The library is functional and uses NIST-standardized algorithms (FIPS 203, 204). However, it hasn't undergone professional security audit. Professional audit recommended before production deployment with sensitive data.

## Technical Questions

### How does hybrid cryptography work?

Data is encrypted with AES-256. The AES key is encrypted with BOTH RSA-4096 AND Kyber-1024. An attacker must break both layers to access the data. Security = MAX(RSA security, Kyber security).

### What happens if one algorithm is broken?

If RSA is broken (by quantum computers), Kyber protects the data. If Kyber has an undiscovered weakness, RSA protects the data. This is the core value of the hybrid approach.

### Why not use only post-quantum algorithms?

Post-quantum algorithms are new (~5 years of analysis) compared to RSA (40+ years). Hybrid approach provides insurance against undiscovered weaknesses in PQC while still protecting against quantum attacks.

### What is the performance overhead?

10-150% slower than classical-only crypto:
- Key generation: +11% (~100ms)
- Encryption: +41% (~1.2ms per KB)
- Decryption: +33% (~1.0ms per KB)
- Signing: +67% (~0.5ms)
- Verification: +150% (~0.3ms)

For most applications, this is acceptable. See [Performance Guide](./performance.md).

### What is the security level?

NIST Level 5 - equivalent to AES-256 security (256-bit security parameter). This is the highest standardized security level, suitable for Top Secret data.

### Can I use this for [specific use case]?

See [Use Cases](./use-cases.md) for examples. Quantum Shield is suitable for:
- ✅ Long-term data protection (5+ years)
- ✅ High-value targets (medical, financial, government)
- ✅ Blockchain applications
- ✅ Compliance requirements
- ✅ IoT security
- ✅ Zero-knowledge systems

## Implementation Questions

### How do I get started?

See [Getting Started Guide](./getting-started.md). Basic usage:

```rust
use quantum_shield::HybridCrypto;

let alice = HybridCrypto::generate_keypair()?;
let bob = HybridCrypto::generate_keypair()?;

let encrypted = alice.encrypt(b"secret", &bob.public_keys())?;
let decrypted = bob.decrypt(&encrypted)?;
```

### How do I store keys?

Public keys can be shared openly. Private keys should be encrypted at rest:

```rust
// Save public keys (safe to share)
let json = public_keys.to_json()?;
std::fs::write("public.json", json)?;

// Private keys - encrypt before saving
let encrypted_private = encrypt_with_password(private_keys, password)?;
std::fs::write("private.enc", encrypted_private)?;
```

### Can I use this with async/await?

Current version (0.1) is synchronous. Async support planned for v0.2.

Workaround:
```rust
let result = tokio::task::spawn_blocking(|| {
    crypto.encrypt(data, &keys)
}).await??;
```

### Is this thread-safe?

Yes. All types implement `Send + Sync`. Safe to use across multiple threads:

```rust
use rayon::prelude::*;

let encrypted: Vec<_> = messages
    .par_iter()
    .map(|msg| crypto.encrypt(msg, &keys))
    .collect();
```

### How do I migrate from RSA?

See [Migration Guide](./migration-guide.md). Key steps:
1. Add Quantum Shield dependency
2. Update key generation
3. Update encrypt/decrypt calls
4. Update sign/verify calls
5. Migrate stored keys
6. Test thoroughly

### What about forward secrecy?

Not currently provided (uses long-term keys). Planned for v0.2.

Workaround: Implement Diffie-Hellman key exchange at application level, use Quantum Shield for the exchanged keys.

## Security Questions

### Has this been audited?

No professional security audit yet. Recommended before production deployment with sensitive data.

### What attacks are you protected against?

✅ Protected:
- Classical attacks (brute force, cryptanalysis)
- Quantum attacks (Shor's algorithm)
- Replay attacks
- Man-in-the-middle (with proper key verification)
- Signature forgery

❌ Not protected:
- Side-channel attacks (timing, power analysis)
- Key management issues
- Endpoint compromise
- Protocol misuse

See [Security Model](./security-model.md) for details.

### Is RSA-4096 enough for now?

RSA-4096 is secure against current attacks and will likely remain so for 10-20 years. However:
1. Data encrypted today could be stored and decrypted later
2. Cryptographic agility requires advance planning
3. Hybrid approach provides insurance

Better to adopt quantum resistance now than scramble later.

### Why Kyber and Dilithium specifically?

NIST selected these algorithms after 6+ years of analysis by the global cryptography community. They are now official FIPS standards (203 and 204). They represent the best peer-reviewed post-quantum algorithms available.

### Can quantum computers break this?

Quantum computers can break RSA but not Kyber, Dilithium, or AES-256. Since both layers must be broken to compromise the system, Quantum Shield remains secure even with large-scale quantum computers.

## Compatibility Questions

### Does this work on [platform]?

Tested on:
- ✅ Linux (x86_64, aarch64)
- ✅ macOS (Intel, Apple Silicon)
- ✅ Windows (x86_64)
- 🟡 WebAssembly (planned v0.3)
- 🟡 Embedded (planned v0.2)

### Can I use this with [LLM framework]?

Yes, language-agnostic. Quantum Shield is a Rust library that can be:
- Used directly in Rust applications
- Exposed via FFI to C/C++/Python
- Compiled to WebAssembly
- Used via microservices API

### Is there a [language] binding?

Current: Rust only

Planned:
- v0.2: C FFI
- v0.3: Python bindings
- v0.4: JavaScript/WASM

### Can I interoperate with other implementations?

If they follow the same standards (FIPS 203, 204), theoretically yes. However, implementation details (key formats, serialization) may differ. Test carefully.

## Troubleshooting

### Key generation is slow

This is expected. RSA-4096 key generation takes ~90ms, which dominates the ~100ms total time. This is a one-time cost. Generate once and reuse keys.

### Signatures are huge (~4.5KB)

This is expected. Dilithium5 signatures are ~4KB. This is the cost of quantum resistance at NIST Level 5. If size is critical, consider:
- Using lower security level (not recommended for long-term)
- Compressing signatures
- Accepting the cost of quantum resistance

### Decryption fails

Check:
1. Using correct recipient's private keys
2. Ciphertext not corrupted
3. Same library version for encrypt/decrypt
4. Error message for specific issue

### Performance is poor

Optimizations:
1. Cache generated keys (don't regenerate)
2. Use parallel processing for batches
3. Stream large files instead of loading entirely
4. Check for debug builds (use --release)

See [Performance Guide](./performance.md).

## Licensing and Support

### What is the license?

MIT License. Free to use, modify, and distribute. See [LICENSE-MIT](../LICENSE-MIT).

### Is commercial use allowed?

Yes. MIT license allows commercial use without restrictions.

### How do I report security vulnerabilities?

Email: security@redasgard.com (private disclosure)

**Do NOT** open public GitHub issues for security vulnerabilities.

### How do I get help?

- Documentation: `/docs/` directory
- Examples: `/examples/` directory
- Issues: https://github.com/redasgard/quantum-shield/issues
- Email: hello@redasgard.com

### Can I contribute?

Yes! Contributions welcome. See [Contributing Guide](./contributing.md).

## Roadmap

### What's coming in v0.2?

- Async support (tokio integration)
- No-std support (embedded systems)
- Streaming API (large files)
- Forward secrecy

### What's coming in v0.3?

- WASM support (browser)
- Additional PQ algorithms (SPHINCS+)
- Hardware acceleration (AES-NI, AVX2)

### What's coming in v0.4?

- Key rotation mechanisms
- Threshold cryptography
- HSM integration

### When will X be released?

No fixed timeline. Follow GitHub for updates.

## Comparison Questions

### vs. libsodium?

Libsodium uses classical crypto (Curve25519, XSalsa20). Not quantum-resistant. Quantum Shield provides quantum resistance with hybrid approach.

### vs. liboqs?

liboqs provides pure post-quantum crypto. Quantum Shield adds classical layer for defense-in-depth and maturity.

### vs. AWS-LC / BoringSSL?

These are general-purpose crypto libraries with some PQC support. Quantum Shield is specialized for hybrid quantum-resistant crypto with focus on defense-in-depth.

### vs. rolling my own crypto?

**Don't roll your own crypto.** Use vetted libraries. If you need customization, contribute to existing projects rather than creating from scratch.

