# Migrating from quantum-shield 0.1.x to 0.2

## Why v1 artifacts are rejected

quantum-shield 0.1.x had two critical design flaws:

1. **Encryption was OR-composed.** The same AES data key was wrapped
   independently by RSA-4096 and by Kyber, and either wrap alone recovered
   it. Breaking RSA (which a quantum computer does) was sufficient to
   decrypt — the "post-quantum" layer added no quantum resistance.
2. **Signatures could be stripped.** The Dilithium signature was optional
   and verification passed on RSA alone, so an attacker could remove the
   post-quantum component entirely.

Because the v1 format is unsafe *by construction*, 0.2 does not read it.
Any v1 input fails with `Error::LegacyV1Artifact`. Continuing to support
decryption would have preserved the vulnerability indefinitely.

0.2 also replaces the deprecated round-3 `pqcrypto-kyber`/`pqcrypto-dilithium`
implementations with the final FIPS 203/204 algorithms (ML-KEM, ML-DSA), so
v1 Kyber ciphertexts are not decryptable by the new stack even in principle.

## Migration steps

1. **Decrypt all v1 data with a 0.1.x build** (pin `quantum-shield = "=0.1.0"`
   in a one-off migration tool).
2. Generate new keypairs with 0.2 (`HybridCrypto::generate()`); v1 keys
   cannot be imported — they were RSA/Kyber/Dilithium keys, and the new
   suite uses X25519/ML-KEM/Ed25519/ML-DSA.
3. Re-encrypt with `seal_for` / re-sign with `sign`, and distribute the new
   public key bundles.
4. Treat all data that was protected only by v1 as having had, at most,
   classical (RSA-4096) protection when assessing exposure.

## API changes

| 0.1.x | 0.2 |
|---|---|
| `HybridCrypto::generate_keypair()` | `HybridCrypto::generate()` |
| `crypto.encrypt(msg, &pubkeys)` | `crypto.seal_for(msg, &bundle)` or `seal(msg, &bundle)` |
| `crypto.decrypt(&ciphertext)` | `crypto.open(&envelope)` |
| `crypto.sign(msg)` | `crypto.sign(msg, context)` — context may be `b""` |
| `HybridCrypto::verify(...) -> bool` | `verify(msg, context, &sig, &bundle) -> Result<()>` |
| `PublicKeys` (JSON, base64 fields) | `PublicKeyBundle` (binary `to_bytes`/`from_bytes`) |
| `HybridCiphertext` (JSON) | `Envelope` (binary) |
| `PrivateKeys` | opaque; `to_secret_bytes()`/`from_secret_bytes()` (166-byte seed bundle) |
| `SecurityManager`, `EntropyMonitor`, `TimingProtection`, `SecureMemory`, `AlgorithmAgility`, `audit_security()` | removed — these provided no real protection |
| `constant_time_compare`, `constant_time_select` | removed — use the [`subtle`](https://crates.io/crates/subtle) crate directly |

Serialization moved from JSON+base64 to compact versioned binary. If you
need JSON transport, enable the `serde` feature or hex/base64-encode the
`to_bytes()` output yourself.
