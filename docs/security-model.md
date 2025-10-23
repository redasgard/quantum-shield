# Security Model

## Overview

Quantum Shield provides hybrid quantum-resistant cryptography with defense-in-depth through dual independent layers: classical (RSA-4096) and post-quantum (Kyber-1024, Dilithium5).

## Security Level

**NIST Level 5** - Equivalent to AES-256 security (256-bit security parameter)

This is the highest standardized security level, suitable for:
- Top Secret government data
- Long-term classified information
- High-value financial data
- Critical infrastructure

## Threat Model

### Protected Against

✅ **Classical Attacks**
- Brute force attacks (2^256 complexity)
- Cryptanalysis of RSA-4096
- Meet-in-the-middle attacks
- Birthday attacks
- Known plaintext attacks
- Chosen ciphertext attacks (via OAEP/GCM)

✅ **Quantum Attacks**
- Shor's algorithm (breaks RSA, protected by Kyber)
- Grover's algorithm (weakens symmetric crypto, mitigated by AES-256)
- Quantum cryptanalysis of lattice problems (current unknowns)

✅ **Protocol Attacks**
- Replay attacks (via nonces)
- Man-in-the-middle (with proper key verification)
- Signature forgery (dual signature requirement)
- Downgrade attacks (version field)

✅ **Implementation Attacks**
- Memory corruption (Rust memory safety)
- Type confusion (Rust type system)
- Concurrent access issues (Send + Sync bounds)

### NOT Protected Against

❌ **Side-Channel Attacks**
- Timing attacks
- Power analysis
- Electromagnetic emanations
- Cache timing attacks
- Spectre/Meltdown variants

**Mitigation:** Use constant-time implementations in production, HSMs for sensitive keys

❌ **Key Management Issues**
- Weak random number generation
- Insecure key storage
- Key exposure through logs/dumps
- Social engineering for keys

**Mitigation:** Proper key storage, access controls, key rotation policies

❌ **Protocol Misuse**
- Using same nonce twice
- Encrypting authentication tokens
- Missing signature verification
- Incorrect key usage

**Mitigation:** Follow API correctly, use high-level abstractions

❌ **Endpoint Compromise**
- Malware on client/server
- Keyloggers
- Memory dumps
- Root/admin access attacks

**Mitigation:** Endpoint security, anti-malware, least privilege

❌ **Post-Quantum Unknowns**
- Undiscovered attacks on lattice problems
- Future quantum algorithms beyond Shor/Grover
- Mathematical breakthroughs

**Mitigation:** Hybrid approach hedges against this risk

## Cryptographic Guarantees

### Confidentiality

**Guarantee:** Ciphertext reveals no information about plaintext to any attacker without private keys.

**Formal:** `Pr[A(encrypt(m0)) = m0] ≤ Pr[A(encrypt(m1)) = m0]` for random m0, m1

**Strength:** Security = MAX(RSA-4096 security, Kyber-1024 security)
- RSA-4096: 2^128 classical security
- Kyber-1024: 2^256 quantum security
- Combined: 2^256 against all known attacks

### Authenticity

**Guarantee:** Valid signatures can only be created by holder of private signing keys.

**Formal:** `Pr[A() → (m, σ) where verify(m, σ, pk) = true] ≤ negligible`

**Strength:** Both RSA-4096-PSS AND Dilithium5 must be broken
- RSA-4096-PSS: 2^128 classical security
- Dilithium5: 2^256 quantum security
- Combined: MIN(RSA security, Dilithium security) but requires breaking both

### Integrity

**Guarantee:** Any modification to ciphertext is detected with overwhelming probability.

**Mechanism:**
- AES-GCM provides authenticated encryption (AEAD)
- Signature verification ensures message integrity
- Nonces prevent replay attacks

**Strength:** 2^128 forgery resistance (GCM authentication tag)

### Forward Secrecy

**Current:** ❌ Not provided (uses long-term keys)

**Future:** Planned for v0.2 with ephemeral key exchange

**Workaround:** Implement Diffie-Hellman key exchange at application level, use Quantum Shield for the exchanged keys

## Algorithm Security Analysis

### RSA-4096

**Status:** Secure against classical attacks, broken by Shor's algorithm

**Security Level:** 128-bit classical, 0-bit quantum

**Attacks:**
- Factoring: Best classical attack requires ~2^128 operations
- Shor's algorithm: Polynomial time on quantum computer

**Conclusion:** Secure until large-scale quantum computers

### Kyber-1024

**Status:** NIST standardized (FIPS 203), secure against quantum attacks

**Security Level:** 256-bit quantum (NIST Level 5)

**Based On:** Module Learning With Errors (MLWE) lattice problem

**Attacks:**
- Best known quantum attack: 2^256 operations
- Best known classical attack: 2^256 operations

**Conclusion:** Quantum-resistant, no known efficient attacks

### Dilithium5

**Status:** NIST standardized (FIPS 204), secure against quantum attacks

**Security Level:** 256-bit quantum (NIST Level 5)

**Based On:** Module Short Integer Solution (MSIS) and MLWE

**Attacks:**
- Best known quantum attack: 2^256 operations
- Best known classical attack: 2^256 operations

**Conclusion:** Quantum-resistant, no known efficient attacks

### AES-256-GCM

**Status:** NIST approved, quantum-weakened but still secure

**Security Level:** 128-bit quantum (Grover), 256-bit classical

**Attacks:**
- Classical brute force: 2^256 operations
- Grover's algorithm: 2^128 operations (still impractical)

**Conclusion:** Quantum-resistant with 256-bit keys

### SHA3-256

**Status:** NIST approved, quantum-resistant

**Security Level:** 128-bit quantum (collision resistance), 256-bit classical

**Based On:** Keccak sponge construction

**Conclusion:** Quantum-resistant for hashing purposes

## Hybrid Security Proof

### Theorem

The hybrid cryptosystem is secure if at least one layer is secure.

### Proof Sketch

**Encryption:**
```
Security(Hybrid) = Security(AES) ∧ MAX(Security(RSA), Security(Kyber))
```

- AES key encrypted by both RSA and Kyber
- Adversary must break AES AND (RSA OR Kyber)
- If RSA broken, Kyber protects
- If Kyber broken, RSA protects
- Must break both to compromise

**Signatures:**
```
Security(Hybrid) = MIN(Security(RSA-PSS), Security(Dilithium))
```

- Message signed by both RSA-PSS and Dilithium
- Both signatures must verify
- If one broken, other still provides authenticity
- Must break both to forge

### Conclusion

Hybrid approach provides maximum security against known and unknown threats.

## Security Recommendations

### Key Generation

✅ **DO:**
- Use `generate_keypair()` which uses cryptographically secure RNG
- Generate keys on secure, trusted systems
- Generate unique keypairs per user/application

❌ **DON'T:**
- Reuse keys across different contexts
- Generate keys on compromised systems
- Use weak entropy sources

### Key Storage

✅ **DO:**
- Encrypt private keys at rest
- Use OS keychain/keyring services
- Implement access controls
- Use HSMs for high-value keys

❌ **DON'T:**
- Store keys in plaintext
- Commit keys to version control
- Log private key material
- Share private keys

### Key Distribution

✅ **DO:**
- Share only public keys
- Use authenticated channels for public key exchange
- Implement public key infrastructure (PKI)
- Verify public key fingerprints out-of-band

❌ **DON'T:**
- Share private keys
- Accept public keys without verification
- Trust public keys from untrusted sources

### Usage Patterns

✅ **DO:**
- Always verify signatures
- Use unique recipients per encryption
- Handle errors appropriately
- Implement proper random nonce generation

❌ **DON'T:**
- Skip signature verification
- Encrypt to same recipient multiple times without key rotation
- Ignore errors
- Reuse nonces

## Compliance

### Standards

- ✅ FIPS 203 (Kyber)
- ✅ FIPS 204 (Dilithium)
- ✅ FIPS 202 (SHA-3)
- ✅ FIPS 197 (AES)
- ✅ NIST SP 800-56B (RSA)
- ✅ NIST SP 800-131A (Crypto Policy)

### Certifications

- 🟡 FIPS 140-3: Not certified (library level)
- 🟡 Common Criteria: Not evaluated
- 🟡 CNSA 2.0: Compatible (uses required algorithms)

**Note:** For certified deployments, integrate with FIPS 140-3 validated crypto modules.

## Security Audits

### Current Status

⚠️ **No professional security audit completed**

### Recommendations

Before production deployment:
1. Professional cryptographic audit
2. Penetration testing
3. Code review by crypto experts
4. Fuzzing and vulnerability scanning

### Responsible Disclosure

Security vulnerabilities: security@redasgard.com

**DO NOT** open public GitHub issues for vulnerabilities.

## Known Limitations

### 1. No Forward Secrecy

Long-term keys used for all operations. If private key compromised, all past communications compromised.

**Impact:** High for long-term secrets
**Mitigation:** Implement ephemeral key exchange, rotate keys regularly

### 2. No Key Rotation

Manual key rotation required.

**Impact:** Medium
**Mitigation:** Application-level key rotation policies

### 3. No Key Revocation

No built-in certificate revocation mechanism.

**Impact:** Medium
**Mitigation:** Implement revocation lists at application level

### 4. Side-Channel Vulnerabilities

Implementation may leak information through timing, power, etc.

**Impact:** High for physical access scenarios
**Mitigation:** Use HSMs, constant-time implementations

### 5. Large Signature Size

~4.5KB signatures (Dilithium5 overhead).

**Impact:** Low (bandwidth/storage)
**Mitigation:** Accept as cost of quantum resistance

## Security Comparison

### vs. Classical Crypto (RSA-4096 only)

| Aspect | Classical | Quantum Shield |
|--------|-----------|----------------|
| Quantum resistance | ❌ No | ✅ Yes |
| Current security | ✅ High | ✅ High |
| Key size | Smaller | Larger |
| Performance | Faster | Slightly slower |

### vs. Pure PQC (Kyber/Dilithium only)

| Aspect | Pure PQC | Quantum Shield |
|--------|----------|----------------|
| Maturity | New (~5 years) | Combines proven + new |
| Unknown attacks | Risky | Hedged |
| Classical security | ✅ Yes | ✅ Yes |
| Quantum security | ✅ Yes | ✅ Yes |

### Conclusion

Quantum Shield provides best-of-both-worlds security.

## Future Improvements

### v0.2
- Forward secrecy support
- Key rotation mechanisms
- Side-channel hardening

### v0.3
- Certificate infrastructure
- Key revocation system
- Multi-party computation

### v0.4
- Threshold cryptography
- Homomorphic encryption
- Zero-knowledge proofs

