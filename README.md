# Quantum Shield

Hybrid post-quantum cryptography for Rust.

- **Encryption**: X25519 + ML-KEM-1024 (FIPS 203) hybrid KEM with a SHA3-256
  combiner, payload encrypted with AES-256-GCM
- **Signatures**: Ed25519 + ML-DSA-87 (FIPS 204), both always present, both
  required to verify

The hybrid constructions are **AND-composed**: an attacker must break *both*
the classical and the post-quantum component to decrypt a message or forge a
signature. A future cryptographically relevant quantum computer breaks
X25519/Ed25519 but not ML-KEM/ML-DSA; a catastrophic new lattice attack
breaks ML-KEM/ML-DSA but not X25519/Ed25519. Either way your data stays
protected.

All algorithm implementations are pure Rust (RustCrypto `ml-kem`/`ml-dsa`,
dalek `x25519`/`ed25519`), so the crate builds natively on Apple Silicon,
x86-64, and other targets with no C toolchain. CI runs the full test suite
on Linux and on macOS arm64 (Apple Silicon) runners.

## ⚠️ Security status

- This library has **not been independently audited**. The underlying
  `ml-kem` and `ml-dsa` crates state the same. Evaluate accordingly.
- The library implements the FIPS 203/204 *algorithms*; the library itself
  is **not FIPS-validated**.
- Version 0.1.x had a broken hybrid construction; its artifacts are
  **rejected by design** (see the [migration guide](docs/migration-v1-to-v2.md)).

## Quick start

```toml
[dependencies]
quantum-shield = "0.2"
```

### Encryption

```rust
use quantum_shield::HybridCrypto;

fn main() -> quantum_shield::Result<()> {
    let alice = HybridCrypto::generate()?;
    let bob = HybridCrypto::generate()?;

    // Alice encrypts a message for Bob.
    let envelope = alice.seal_for(b"Secret hybrid PQ message", bob.public_keys())?;

    // Envelopes serialize to a stable, versioned binary format.
    let wire = envelope.to_bytes();

    // Bob decrypts.
    let received = quantum_shield::Envelope::from_bytes(&wire)?;
    let plaintext = bob.open(&received)?;
    assert_eq!(plaintext, b"Secret hybrid PQ message");
    Ok(())
}
```

### Signatures

```rust
use quantum_shield::{HybridCrypto, verify};

fn main() -> quantum_shield::Result<()> {
    let alice = HybridCrypto::generate()?;

    // The context string (up to 255 bytes) domain-separates different uses
    // of the same key. Use b"" if you don't need one.
    let signature = alice.sign(b"I agree to these terms", b"contract")?;

    verify(b"I agree to these terms", b"contract", &signature, alice.public_keys())?;
    Ok(())
}
```

### Key storage

```rust
use quantum_shield::HybridCrypto;

fn main() -> quantum_shield::Result<()> {
    let keypair = HybridCrypto::generate()?;

    // Private keys export as 166 bytes of seeds; the buffer zeroizes on drop.
    let secret = keypair.to_secret_bytes();
    // ... store `secret` in your KMS/keychain, then later:
    let restored = HybridCrypto::from_secret_bytes(&secret)?;
    assert_eq!(restored.public_keys(), keypair.public_keys());

    // Public keys are a single 4230-byte bundle, validated on parse.
    let _shareable = keypair.public_keys().to_bytes();
    Ok(())
}
```

## Design

Encryption is KEM-DEM: each message runs a fresh X25519 exchange and a fresh
ML-KEM-1024 encapsulation, and the AES-256-GCM key is

```text
SHA3-256( label || ss_mlkem || ss_x25519
          || ct_mlkem || epk_x25519 || ek_mlkem || pk_x25519 )
```

— the X-Wing combiner construction ported to ML-KEM-1024, hardened to hash
the full transcript. There is no wrapped data key that a single layer could
reveal (the flaw that made 0.1.x not quantum-resistant). The entire envelope
header, including format version and cipher suite, is bound into the GCM tag
as associated data, so nothing about an envelope can be reinterpreted.

Signatures frame the message as `label || len(ctx) || ctx || message` and
sign it with both Ed25519 and ML-DSA-87 in pure (non-prehashed) mode. Both
signatures are fixed-size wire fields: there is no encoding of a "signature
without the post-quantum part", and verification enforces both.

Wire objects are versioned binary (`QSE2`/`QSS2`/`QSP2`/`QSK2`); unknown
versions and suites are rejected, and there is no algorithm negotiation. The
full format specification lives in [docs/design.md](docs/design.md); the
threat model in [docs/security-model.md](docs/security-model.md).

| Wire object | Size |
|---|---|
| Envelope | plaintext + 1634 bytes |
| Signature | 4697 bytes |
| Public key bundle | 4230 bytes |
| Secret key bundle (seeds) | 166 bytes |

Beyond single-recipient `seal`/`open`, the crate also provides:

- **Multi-recipient** — `seal_multi(payload, &[&bundle, …])` / `open_multi`:
  one payload to many recipients, the recipient set bound into the payload
  authentication.
- **Streaming** — `StreamSealer` / `StreamOpener`: chunked AEAD for payloads
  larger than the 64 MiB single-shot limit.
- **Key rotation** — `PublicKeyBundle::key_id` and `attest_rotation` /
  `verify_rotation`: a hybrid-signed old→new link so peers can follow a key
  change from a trusted anchor.

All are specified in [docs/design.md](docs/design.md).

## Features

- `std` (on by default): standard-library integration. Disable it for a
  `no_std` build.
- `serde` (off by default): `Serialize`/`Deserialize` for the wire types as
  validated byte strings.
- `pem` (off by default): `PublicKeyBundle::{to_pem, from_pem}` — per-component
  PEM export of the public keys (standard SPKI for ML-KEM/ML-DSA/Ed25519, a raw
  block for X25519). The compact `QSP2` bundle remains the primary format.

## `no_std`

The crate is `#![no_std]` and depends only on `alloc`:

```toml
quantum-shield = { version = "0.2", default-features = false }
```

It builds for bare-metal targets (CI checks `thumbv7em-none-eabi`). On a
target without an OS randomness source you must supply a `getrandom` backend —
see the [getrandom custom-backend docs](https://docs.rs/getrandom/latest/getrandom/#custom-backend).
Without one, key generation and encryption cannot obtain entropy and the crate
will not link.

## Minimum supported Rust version

1.85, driven by the `ml-kem`/`ml-dsa` dependencies.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).
