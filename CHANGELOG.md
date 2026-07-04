# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
