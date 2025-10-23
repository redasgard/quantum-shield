# Algorithms

Detailed explanation of cryptographic algorithms used in Quantum Shield.

## Algorithm Stack

```
Classical Layer          Post-Quantum Layer
─────────────────       ──────────────────
RSA-4096-OAEP    ←─┐    ┌─→ Kyber-1024
RSA-4096-PSS       │    │   Dilithium5
                   │    │
AES-256-GCM    ────┴────┴─── SHA3-256
```

## Encryption Algorithms

### AES-256-GCM

**Purpose:** Symmetric encryption of actual data

**Type:** Authenticated Encryption with Associated Data (AEAD)

**Parameters:**
- Key size: 256 bits
- Block size: 128 bits
- Nonce size: 96 bits (12 bytes)
- Tag size: 128 bits

**Security:**
- Confidentiality: 256-bit classical, 128-bit quantum (Grover's algorithm)
- Authenticity: 128-bit forgery resistance

**Why GCM?**
- Authenticated encryption (prevents tampering)
- Parallelizable (fast)
- NIST approved (FIPS 197)
- Quantum-resistant with 256-bit keys

**Algorithm:**
```
1. Generate random 256-bit AES key
2. Generate random 96-bit nonce
3. Encrypt: C = AES-GCM_Encrypt(K, N, P)
4. Output: (C, N, T) where T is authentication tag
```

### RSA-4096-OAEP

**Purpose:** Classical public-key encryption of AES key

**Type:** Asymmetric encryption with Optimal Asymmetric Encryption Padding

**Parameters:**
- Key size: 4096 bits
- Public exponent: 65537 (0x10001)
- Padding: OAEP with SHA-256

**Security:**
- Classical: ~128-bit (needs ~2^128 operations to factor)
- Quantum: 0-bit (Shor's algorithm polynomial time)

**Why RSA-4096?**
- Well-studied (40+ years)
- Industry standard
- High classical security
- Backward compatible

**Algorithm:**
```
1. K_pub = (n, e) where n = p × q (4096-bit primes)
2. M = AES key (256 bits)
3. Pad M using OAEP(M, SHA-256)
4. C = M_padded^e mod n
```

**Decryption:**
```
1. K_priv = (n, d) where d = e^(-1) mod φ(n)
2. M_padded = C^d mod n
3. M = Unpad(M_padded)
```

### Kyber-1024

**Purpose:** Post-quantum encryption of AES key

**Type:** Key Encapsulation Mechanism (KEM) based on lattices

**Parameters:**
- Security level: NIST Level 5
- Public key: 1568 bytes
- Ciphertext: 1568 bytes
- Shared secret: 32 bytes

**Security:**
- Based on Module Learning With Errors (MLWE)
- Quantum: 256-bit (hardness of SVP)
- Classical: 256-bit

**Why Kyber-1024?**
- NIST standardized (FIPS 203)
- Highest security level
- Efficient implementation
- Quantum-resistant

**Algorithm (Simplified):**
```
Key Generation:
1. A ← random matrix in R_q
2. s, e ← small error vectors
3. t = A·s + e
4. pk = (A, t), sk = s

Encapsulation (Encrypt):
1. m ← random message (becomes AES key)
2. r, e1, e2 ← small error vectors  
3. u = A^T·r + e1
4. v = t^T·r + e2 + encode(m)
5. c = (u, v)
6. K = KDF(m)

Decapsulation (Decrypt):
7. m' = decode(v - s^T·u)
8. K' = KDF(m')
```

## Signature Algorithms

### RSA-4096-PSS

**Purpose:** Classical digital signatures

**Type:** Probabilistic Signature Scheme with SHA-256

**Parameters:**
- Key size: 4096 bits
- Hash: SHA-256
- Salt length: 32 bytes
- Signature: 512 bytes

**Security:**
- Classical: ~128-bit
- Quantum: 0-bit (Shor's algorithm)

**Why RSA-PSS?**
- Provably secure (tight reduction)
- Randomized (prevents attacks)
- Industry standard

**Algorithm:**
```
Signing:
1. H = SHA-256(message)
2. salt ← random 32 bytes
3. H' = SHA-256(padding || H || salt)
4. DB = padding || salt
5. dbMask = MGF1(H', len(DB))
6. maskedDB = DB ⊕ dbMask
7. EM = maskedDB || H' || 0xBC
8. s = EM^d mod n
```

**Verification:**
```
1. EM = s^e mod n
2. Extract H', maskedDB from EM
3. dbMask = MGF1(H', len(maskedDB))
4. DB = maskedDB ⊕ dbMask
5. Extract salt from DB
6. Recompute H'
7. Compare H' values
```

### Dilithium5

**Purpose:** Post-quantum digital signatures

**Type:** Lattice-based signatures (CRYSTALS-Dilithium)

**Parameters:**
- Security level: NIST Level 5
- Public key: 2592 bytes
- Signature: ~4595 bytes
- Private key: 4864 bytes

**Security:**
- Based on Module SIS and MLWE
- Quantum: 256-bit
- Classical: 256-bit

**Why Dilithium5?**
- NIST standardized (FIPS 204)
- Highest security level
- Faster than RSA for signing
- Quantum-resistant

**Algorithm (Simplified):**
```
Key Generation:
1. A ← random matrix in R_q
2. s1, s2 ← small secret vectors
3. t = A·s1 + s2
4. pk = (A, t), sk = (A, s1, s2, t)

Signing:
1. μ = CRH(tr || message)
2. κ ← 0
3. Repeat:
   a. y ← sample from secret distribution
   b. w = A·y
   c. c = H(μ || w)
   d. z = y + c·s1
   e. If ||z|| or ||w - c·s2|| too large: κ++, continue
4. Return σ = (c, z)

Verification:
1. μ = CRH(tr || message)
2. w' = A·z - c·t
3. Accept if H(μ || w') = c and ||z|| small
```

## Hash Algorithms

### SHA3-256

**Purpose:** Message hashing for signatures

**Type:** Keccak sponge construction

**Parameters:**
- Output: 256 bits
- Capacity: 512 bits
- Rate: 1088 bits

**Security:**
- Collision resistance: 128-bit quantum
- Preimage resistance: 256-bit quantum
- Second preimage: 256-bit quantum

**Why SHA3?**
- NIST approved (FIPS 202)
- Quantum-resistant
- Different construction than SHA-2 (diversity)

**Algorithm:**
```
1. Pad message to multiple of rate
2. Absorb: XOR message blocks into state, apply Keccak-f
3. Squeeze: Output bits from state
4. Return first 256 bits
```

## Key Derivation

### Random Number Generation

**Source:** Operating system CSPRNG
- Linux: `/dev/urandom`
- Windows: `BCryptGenRandom`
- macOS: `getentropy()`

**Quality:** Cryptographically secure, unpredictable

### Key Generation Flow

```
OS CSPRNG
    │
    ├─→ RSA key generation
    │   └─→ Generate primes p, q
    │       └─→ Compute n = p×q, φ(n), d
    │
    ├─→ Kyber key generation
    │   └─→ Sample polynomials s, e
    │       └─→ Compute t = A·s + e
    │
    └─→ Dilithium key generation
        └─→ Sample polynomials s1, s2
            └─→ Compute t = A·s1 + s2
```

## Hybrid Construction

### Encryption Hybrid

```
Plaintext (P)
    │
    ├─→ AES-256-GCM
    │   └─→ Ciphertext (C), Nonce (N)
    │
    ├─→ RSA-4096-OAEP(AES_key)
    │   └─→ C_rsa
    │
    └─→ Kyber-1024-Encaps(AES_key)
        └─→ C_kyber

Output: (C, N, C_rsa, C_kyber)
```

**Security Proof:**
- If RSA broken → Kyber protects key
- If Kyber broken → RSA protects key
- Must break both to recover AES key
- Security = MAX(RSA, Kyber)

### Signature Hybrid

```
Message (M)
    │
    ├─→ SHA3-256
    │   └─→ Hash (H)
    │
    ├─→ RSA-4096-PSS(H)
    │   └─→ σ_rsa
    │
    └─→ Dilithium5(H)
        └─→ σ_dilithium

Output: (σ_rsa, σ_dilithium)
```

**Security Proof:**
- Both signatures must verify
- If one broken, other still authenticates
- Forgery requires breaking both
- Security = MIN(RSA, Dilithium) in practice

## Security Reductions

### AES-256-GCM Security

**Theorem:** AES-GCM is IND-CPA and INT-CTXT secure if AES is a pseudorandom permutation and GHASH is a universal hash.

**Reduction:** Advantage of adversary:
```
Adv ≤ q²/2^129 + (q·l)/2^128
```
where q = queries, l = max message length

### RSA-OAEP Security

**Theorem:** RSA-OAEP is IND-CCA2 secure in the random oracle model if RSA is hard to invert.

**Reduction:** 
```
Adv_OAEP ≤ Adv_RSA + 2q_H/2^k
```
where q_H = hash queries, k = hash output length

### Kyber Security

**Theorem:** Kyber is IND-CCA2 secure if MLWE is hard.

**Reduction:**
```
Adv_Kyber ≤ Adv_MLWE + δ
```
where δ is decryption failure probability (~2^-138)

### Dilithium Security

**Theorem:** Dilithium is EU-CMA secure if MSIS and MLWE are hard.

**Reduction:**
```
Adv_Dilithium ≤ Adv_MSIS + Adv_MLWE + 2^-128
```

## Parameter Justification

### Why 4096-bit RSA?

- 2048-bit: 112-bit security (not sufficient for long-term)
- 3072-bit: 128-bit security (marginal)
- 4096-bit: 128-bit+ security (comfortable margin)

### Why Kyber-1024?

- Kyber-512: NIST Level 1 (not sufficient)
- Kyber-768: NIST Level 3 (good but not maximum)
- Kyber-1024: NIST Level 5 (maximum security)

### Why Dilithium5?

- Dilithium2: NIST Level 2 (not sufficient)
- Dilithium3: NIST Level 3 (good but not maximum)
- Dilithium5: NIST Level 5 (maximum security)

### Why AES-256 over AES-128?

- AES-128: 64-bit quantum security (marginal)
- AES-256: 128-bit quantum security (sufficient)

## Implementation Details

### Constant-Time Operations

Critical operations implemented in constant time:
- ✅ Kyber polynomial operations
- ✅ Dilithium signing
- ⚠️ RSA operations (library dependent)

### Side-Channel Resistance

**Mitigations:**
- No branching on secret data
- No secret-dependent memory access
- Constant-time comparisons

**Limitations:**
- Cache timing still possible
- Power analysis not addressed
- Requires hardware support for full protection

## Standards Compliance

- ✅ FIPS 197 (AES)
- ✅ FIPS 202 (SHA-3)
- ✅ FIPS 203 (Kyber)
- ✅ FIPS 204 (Dilithium)
- ✅ NIST SP 800-56B (RSA KEM)
- ✅ NIST SP 800-131A (Transitioning to cryptographic algorithms)

## References

1. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
2. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
3. NIST FIPS 202: SHA-3 Standard
4. RFC 8017: PKCS #1: RSA Cryptography Specifications
5. NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)

