# Gap Matrix — quantum-shield vs. production-grade

Baseline: a general-purpose, production-grade hybrid post-quantum
cryptography library. Updated as of **v0.3.2**.

**Legend:** ✅ done · 🟡 partial · ❌ missing · ⬜ out of scope by design (v2)

The section tables mark which release landed each item. The remaining open
items are external (audit, supply-chain attestation); see the end.

## 1. Cryptographic core

| Capability | Status | Notes / gap |
|---|---|---|
| Hybrid KEM (X25519 + ML-KEM-1024), KDF-combined | ✅ | SHA3-256 combiner over both secrets + full transcript (`src/hybrid_kem.rs`) |
| Hybrid signatures (Ed25519 + ML-DSA-87), both mandatory | ✅ | Non-short-circuit verify, `verify_strict` (`src/sign.rs`) |
| AEAD payload (AES-256-GCM) with header bound as AAD | ✅ | `src/seal.rs` |
| FIPS 203/204 algorithms (final, not round-3) | ✅ | RustCrypto `ml-kem` 0.3 / `ml-dsa` 0.1, checked against NIST ACVP vectors (0.3.2) |
| Domain separation + injective framing | ✅ | Labels + length-prefixed context |
| Degenerate public keys rejected at parse | ✅ | Low-order X25519, non-canonical / small-order Ed25519, FIPS 203 ML-KEM key check (0.3.2) |
| Combiner with a published security proof | 🟡 | Full-transcript, Chempat / CFRG "universal combiner" style. Not X-Wing (an individual IETF draft, ML-KEM-768); no dedicated proof for this exact construction |
| Randomized ("hedged") ML-DSA signing | 🟡 | Deterministic by choice (FIPS 204 permits it). `ml-dsa` 0.1 does offer `sign_randomized`; hedging is a candidate for a later release |
| Multi-recipient encryption | ✅ | `seal_multi`/`open_multi` (`QSM2`), recipient set bound into payload (0.3.0); constant work across wraps (0.3.2) |
| Streaming / chunked AEAD for >64 MiB | ✅ | `StreamSealer`/`StreamOpener` (`QST2`), STREAM construction (0.3.0) |
| Key rotation (signed old→new attestation) | ✅ | `key_id` + `RotationAttestation` (`QSR2`) (0.3.0) |
| Forward secrecy for recipient (ratchet) | ⬜ | Static recipient KEM keys; rotation gives bounded-exposure re-keying, not per-message FS |
| Authenticated sender (signcryption) | ⬜ | `seal` is anonymous by design |

## 2. Side-channel & memory hardening

| Capability | Status | Notes / gap |
|---|---|---|
| Zeroization of private key material | ✅ | Seeds, expanded keys (upstream), and both component shared secrets |
| `Debug` redaction of secrets | ✅ | `KeyPair`/`PublicKeyBundle` |
| Uniform decryption/verification errors (no oracle) | ✅ | `Error::DecryptionFailed` carries no detail |
| Constant-time primitives | 🟡 | Relies on dalek / RustCrypto. dalek and `aes-gcm` document constant-time intent; `ml-kem`/`ml-dsa` make no formal claim (ml-dsa had a timing advisory, RUSTSEC-2025-0144, fixed before the locked version) |
| Constant-time regression harness (dudect) | 🟡 | `examples/dudect.rs` on `open`, non-gating CI. A statistical tripwire: it can flag a leak, never prove absence |
| Fault-injection / EM resistance | ❌ | No claims, no mitigations |

## 3. API & interoperability

| Capability | Status | Notes / gap |
|---|---|---|
| seal/open, sign/verify, key export/import | ✅ | `src/api.rs`, `src/lib.rs` |
| Versioned binary wire format, unknown-version rejection | ✅ | `src/wire.rs`, `docs/design.md` |
| serde support (optional feature) | ✅ | `Envelope`, `HybridSignature`, `PublicKeyBundle` (`src/serde_impls.rs`) |
| Interop with an independent implementation | ✅ | `ci/interop/cleanroom.py`, written from `docs/design.md` on unrelated libraries, opens/verifies all seven formats in CI (0.3.2) |
| Standard key encodings (SPKI/PEM) | 🟡 | `pem` feature: public keys only — SPKI PEM for ML-KEM/ML-DSA/Ed25519, a raw block for X25519. No PKCS#8 private-key export (`QSK2` seeds are the private format) |
| `no_std` support | ✅ | `#![no_std]` + `alloc` without the `std` feature; bare-metal `cargo check` in CI (`thumbv7em-none-eabi`) with a custom `getrandom` backend (0.2.2) |
| Async API | ⬜ | Removed; ops are CPU-bound, not IO-bound |

## 4. Testing & QA

| Capability | Status | Notes / gap |
|---|---|---|
| Unit, integration, and doc tests | ✅ | `cargo test --all-features`; every doc example executes |
| Adversarial: byte-flip, splice, downgrade, stripping | ✅ | `tests/tamper.rs`, `tests/downgrade.rs`, `tests/stream.rs`, `tests/multi.rs`, `tests/rotate.rs` |
| Property-based tests | ✅ | `tests/proptests.rs` |
| NIST ACVP vectors (ML-KEM-1024, ML-DSA-87) | ✅ | `tests/acvp.rs`, incl. NIST seeds through the crate's `QSK2` import (0.3.2) |
| RFC 7748 / RFC 8032 vectors | ✅ | `tests/kat_x25519.rs`, `tests/kat_ed25519.rs` (0.2.1) |
| Wire-format golden vectors | ✅ | Regression pins of this crate's output: `QSE2`, `QSS2`, key derivation, `key_id`, `QSR2` (`tests/golden.rs`) |
| Fuzzing (`cargo-fuzz`) of all parsers | ✅ | `fuzz/`: ten targets, all `from_bytes` + roundtrips; 30 s smoke run per target in CI |
| Benchmarks (`criterion`) | ✅ | `benches/crypto.rs`, `benches/codec.rs`; no numbers are published — run them on your hardware |
| Coverage measurement | ✅ | `cargo-llvm-cov` → Codecov CI job (non-gating) |

## 5. CI, supply chain & release

| Capability | Status | Notes / gap |
|---|---|---|
| Multi-OS CI incl. macOS arm64 (Apple Silicon) | ✅ | `ubuntu-latest` + `macos-15` |
| fmt + clippy (`-D warnings`) + doc | ✅ | `.github/workflows/ci.yml` |
| MSRV (1.85) check | ✅ | Dedicated job |
| `cargo-deny` (advisories/licenses/sources/yanked) | ✅ | `deny.toml` |
| SemVer breakage check (`cargo-semver-checks`) | ✅ | Against the latest crates.io release |
| Signed releases / SLSA provenance / SBOM | ❌ | No supply-chain attestation |
| Git tags + GitHub releases | ✅ | `v0.3.1` onward |

## 6. Docs, governance & assurance

| Capability | Status | Notes / gap |
|---|---|---|
| README, design spec, threat model, migration guide | ✅ | `docs/design.md`, `docs/security-model.md`, `docs/migration-v1-to-v2.md` |
| Honest "not audited / not FIPS-validated" disclosure | ✅ | README + SECURITY.md |
| Threat model with explicit non-goals | ✅ | `docs/security-model.md` |
| Independent third-party security audit | ❌ | **Largest gap** for a security-critical library |
| Formal verification of the combiner/framing | ❌ | No machine-checked proof |
| FIPS validation | ⬜ | A CMVP certificate applies to a validated module, not to a crate that implements the algorithms |

## Remaining gaps

1. **Independent audit**: the one gap that external work, not code, must
   close.
2. **Signed releases / SLSA / SBOM**: supply-chain attestation.
3. **Hedged ML-DSA signing**: available upstream, not yet adopted.
