# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-04

New capabilities. All additive — the single-recipient `Envelope` (`QSE2`),
signatures, and keys are unchanged, and existing code keeps working. New
wire objects use new magics (`QSM2`/`QST2`/`QSR2`) and keep `version = 2`,
`suite = 1`.

### Added

- **Multi-recipient envelopes** (`QSM2`): `seal_multi` / `open_multi` /
  `MultiRecipientEnvelope`. One payload under a random CEK; the CEK is wrapped
  per recipient with a full hybrid KEM. The payload authentication binds the
  entire recipient set, so add/remove/reorder/duplicate tampering fails.
  Opening trial-decrypts with no recipient identifier on the wire;
  `MAX_RECIPIENTS = 1024` bounds the cost.
- **Streaming AEAD** (`QST2`): `StreamSealer` / `StreamOpener` for payloads
  over `MAX_PLAINTEXT_LEN`. One hybrid KEM keys a STREAM of 64 KiB chunks;
  each chunk binds its index and a last-flag, so reorder/duplicate/drop/
  truncate all fail (`StreamTruncated` at `finish`).
- **Key rotation** (`QSR2`): `PublicKeyBundle::key_id` (`SHA3-256(QSP2)[..16]`)
  and `RotationAttestation` — the old keypair hybrid-signs `old_key_id ||
  new_public`, giving verifiers a cryptographic old→new link
  (`HybridCrypto::attest_rotation`, `verify_rotation`).
- New parser fuzz targets, normative `docs/design.md` sections for all three
  formats, and golden vectors (`key_id`, deterministic rotation attestation).
- New `Error` variants (`NoRecipients`, `TooManyRecipients`, `StreamFinished`,
  `StreamTruncated`); the enum is `#[non_exhaustive]`, so this is non-breaking.

### Security (hardening from the validation pass)

- **Multi-recipient key commitment.** Because AES-GCM is not key-committing, a
  malicious sender could otherwise wrap different CEKs to different recipients
  and craft one payload that decrypts to different plaintexts per recipient.
  `QSM2` now carries `SHA3-256(CEK)`, bound into the payload AAD and checked
  (constant-time) on open, so every recipient verifies the same CEK.
- **Rotation rollback protection.** `RotationAttestation` now binds a
  caller-supplied monotonic `epoch` (signed, exposed via `epoch()`), so a
  verifier can reject a replayed, superseded attestation.
  `attest_rotation` takes an `epoch` argument.
- **AES-GCM state is now zeroized** (`aes-gcm` `zeroize` feature), so the key
  schedule no longer lingers after the KEM secret is wiped.
- **serde deserialization caps its pre-allocation**, closing an allocation-DoS
  from an attacker-controlled `size_hint` in binary formats.
- **Streaming counter-overflow guard moved before encryption**, removing an
  internal nonce-reuse edge at the 2^32-chunk limit; per-chunk size is bounded
  to the 32-bit frame length.

## [0.2.2] - 2026-07-04

Hardening. `std` remains a default feature, so existing users are unaffected;
all additions are opt-in.

### Added

- `no_std` support: the crate is `#![no_std]` and needs only `alloc`. Disable
  the default `std` feature for embedded targets (supply a `getrandom` backend;
  CI compiles the full API for `thumbv7em-none-eabi`).
- `pem` feature: `PublicKeyBundle::{to_pem, from_pem}` — per-component PEM for
  the public keys (standard SubjectPublicKeyInfo for ML-KEM/ML-DSA/Ed25519, a
  raw block for X25519). The `QSP2` bundle stays the primary format; PEM import
  round-trips through it, so it enforces the same validation. A fuzz target
  covers the new parser.
- `examples/dudect.rs`: a dudect constant-time regression harness on `open`
  (decapsulate + AEAD), wired as a non-gating CI job. Measures low t-values
  locally, confirming decryption-failure timing does not leak.

### Changed

- Dependencies are built with `default-features = false` + `alloc`; `ml-dsa`
  drops its `getrandom` default (signing is deterministic) and `ed25519-dalek`
  uses `alloc` instead of `std` unless the `std` feature is on.

## [0.2.1] - 2026-07-04

Assurance and tooling; no source or wire-format changes (API-compatible with
0.2.0).

### Added

- Criterion benchmarks (`benches/crypto.rs`, `benches/codec.rs`) for key
  generation, seal/open, sign/verify, and the wire codecs — measured numbers
  replacing the fabricated ones removed in 0.2.0.
- In-crate known-answer tests: RFC 7748 (X25519) and RFC 8032 (Ed25519)
  official vectors, plus deterministic stability KATs for ML-KEM-1024 and
  ML-DSA-87 that pin the parameter set and FIPS sizes against the locked
  crate versions (full ACVP conformance remains covered upstream).
- `fuzz/` cargo-fuzz crate: six libFuzzer targets covering every `from_bytes`
  parser and the seal/open and sign/verify roundtrips.
- CI jobs: `cargo-semver-checks` (baseline `v0.2.0`), coverage
  (`cargo-llvm-cov` → Codecov, non-gating), and a nightly fuzz smoke run.

## [0.2.0] - 2026-07-04

Complete cryptographic rewrite. **Breaking in every dimension: algorithms,
wire format, and API.** Artifacts produced by 0.1.x cannot be read by 0.2.0
— this is deliberate; see the security notes below and
[docs/migration-v1-to-v2.md](docs/migration-v1-to-v2.md).

### Security

Version 0.1.x was not quantum-resistant despite its claims:

- **The hybrid encryption was OR-composed.** The same AES data key was
  wrapped independently by RSA-4096 and by Kyber-1024; recovering *either*
  wrap revealed the key, so a quantum attacker only had to break RSA. 0.2.0
  derives the AEAD key from a SHA3-256 combiner over **both** shared secrets
  and the full public transcript (X-Wing construction ported to
  ML-KEM-1024) — both layers must now be broken.
- **Signatures could be downgraded.** The Dilithium signature was optional
  and verification passed on RSA alone, so stripping the post-quantum
  component was trivial. 0.2.0 makes both signature components fixed,
  mandatory wire fields, verified non-short-circuit.
- **Deprecated round-3 algorithms replaced.** `pqcrypto-kyber`/
  `pqcrypto-dilithium` (pre-standard Kyber/Dilithium) are replaced by the
  final FIPS 203 ML-KEM-1024 and FIPS 204 ML-DSA-87 (RustCrypto, pure Rust).
- **Security theater removed.** The 0.1.x `security` module (sleep-based
  timing "jitter", XOR "blinding" that discarded its factor, an entropy
  counter that measured nothing, an audit that always returned 100%)
  provided no protection and is deleted.
- Private keys now exist only in seed form (166-byte bundle), zeroized on
  drop; `Debug` output redacts key material; decryption/verification errors
  are uniform and carry no oracle-friendly detail.

### Changed

- Algorithms: X25519 + ML-KEM-1024 hybrid KEM (AES-256-GCM payload),
  Ed25519 + ML-DSA-87 hybrid signatures. RSA is gone, and with it
  multi-second key generation.
- Wire format: compact versioned binary (`QSE2`/`QSS2`/`QSP2`/`QSK2`)
  replacing JSON+base64; the envelope header is bound into the AEAD tag;
  unknown versions/suites are rejected; no algorithm negotiation. Specified
  normatively in [docs/design.md](docs/design.md).
- API: `generate()`, `seal`/`seal_for`/`open`, `sign(msg, context)`,
  free-function `verify(...) -> Result<()>`; wire types expose
  `to_bytes`/`from_bytes`. JSON support moved behind the optional `serde`
  feature.
- Dependencies: pure-Rust stack (`ml-kem`, `ml-dsa`, `x25519-dalek`,
  `ed25519-dalek`, `aes-gcm`, `sha3`, `getrandom`, `zeroize`); removed
  `rsa`, `pqcrypto-*`, `anyhow`, `tokio`, `rand`, `base64`, `sha2`. MSRV is
  1.85.

### Added

- Size limits enforced (64 MiB plaintext), 0–255-byte signing contexts with
  injective framing.
- Adversarial test suites: per-region byte-flip and cross-envelope splicing
  tests, downgrade and signature-stripping tests, v1-artifact rejection,
  property-based corruption sweeps, and pinned known-answer vectors
  (including a stored golden envelope that every future version must
  decrypt).
- CI: Linux + macOS arm64 (Apple Silicon) matrix running fmt, clippy
  (warnings denied), tests across feature combinations, docs, an MSRV
  check, and cargo-deny (advisories/licenses/sources).
- Honest documentation: normative format spec, threat model with explicit
  non-goals, migration guide. Removed fabricated benchmarks and unfounded
  "FIPS compliant" / "battle-tested" claims.

### Fixed

- `cargo test` compiles and passes (0.1.0 shipped with a non-compiling
  integration test and a deterministically failing unit test).

## [0.1.0] - 2024-10-23

Initial release: RSA-4096 + Kyber-1024 encryption, RSA-PSS + Dilithium5
signatures. **Withdrawn — see 0.2.0 security notes.**
