# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2026-10-05

Maintenance and verification release. No wire-format or public API changes:
everything produced by 0.3.0/0.3.1 still opens and verifies. The one
behaviour change is that public-key bundles carrying degenerate keys are now
rejected (see Security).

### Security

- **Degenerate public keys are rejected at parse.** `PublicKeyBundle::from_bytes`
  (and so `from_pem`, serde, and `RotationAttestation::from_bytes`) now
  rejects low-order X25519 keys, including all-zero, which would have
  silently reduced the hybrid KEM to ML-KEM alone for that recipient. It also
  rejects non-canonically encoded or small-order Ed25519 keys, which gave one
  key several encodings and `key_id`s. 0.3.1 accepted all of these.
- **`open_multi` does constant work across wraps.** It previously stopped at
  the first matching wrap, so timing revealed the recipient's position.
- The ML-KEM component shared secret is now zeroized after use, and the
  ephemeral X25519 seed is no longer copied out of its `Zeroizing` buffer.

### Changed

- `x25519-dalek` / `ed25519-dalek` 2 → 3 (`curve25519-dalek` 5). The
  dependency tree is now on one RustCrypto generation (one `getrandom`, one
  `rand_core`, one `digest`, one `pkcs8`). Also `aes-gcm` 0.11.1,
  `zeroize` 1.9, `pem-rfc7468` 1.0. MSRV stays 1.85; the lockfile is resolved
  MSRV-aware (`.cargo/config.toml`), and the README explains how to get
  compatible transitive versions on 1.85–1.88 (`aes` 0.9.3 needs 1.89).
- Lockfile refreshed: the previously locked `der` 0.8.0 and `chacha20`
  0.10.1 were yanked upstream, which had made the `cargo-deny` CI job fail.

### Added

- `tests/acvp.rs`: the official NIST ACVP vectors for ML-KEM-1024 (key
  generation, encapsulation, decapsulation incl. implicit rejection, key
  checks) and ML-DSA-87 (key generation, deterministic and hedged signing,
  verification). They include NIST seeds imported through the crate's own
  `QSK2` format. Repository-only; excluded from the published package.
- `ci/interop/`: an independent Python implementation of all seven wire
  formats, written from `docs/design.md` on unrelated libraries, plus the
  `interop_gen` example. A new CI job checks that it opens and verifies what
  the crate produces.
- `tests/weak_keys.rs` for the new key checks.

### Fixed (documentation)

- The KEM combiner was described as "the X-Wing combiner ported to
  ML-KEM-1024". It is not X-Wing; the docs now describe what it is.
- Streaming chunk size: documented as fixed at 64 KiB, but the caller has
  always chosen it. `STREAM_CHUNK_SIZE` is now documented as the
  recommended size.
- `examples/dudect.rs` flipped a byte of the X25519 key, not the ML-KEM
  ciphertext, so implicit rejection was never measured.
- SECURITY.md and the migration guide referred to 0.2.x, which was never
  published. CONTRIBUTING.md still described 0.1.x (Rust 1.70, a `tracing`
  feature, tests that don't exist).
- `docs/design.md`: byte order of integer fields, the full list of magics,
  public-key validation rules, and which formats are covered by which tests.
- The `QSM2` layout in the rustdoc was missing `cek_commitment`; several
  CHANGELOG entries misdescribed things (rotation message, CEK commitment,
  dudect, benchmarks, the 0.1.0 date).
- Doc examples that never executed (`no_run`, or bodies inside an uncalled
  `fn run`) now run.
- 545 build artifacts committed under `ci/no_std_check/target/` were removed.

## [0.3.1] - 2026-07-05

Documentation-only patch; no code or API changes.

### Fixed

- README quick-start snippets now reference `quantum-shield = "0.3"` (they
  still said `"0.2"`). Re-released so the crates.io / docs.rs copy of the
  README is correct.

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
  over `MAX_PLAINTEXT_LEN`. One hybrid KEM keys a STREAM of caller-sized chunks (64 KiB recommended);
  each chunk binds its index and a last-flag, so reorder/duplicate/drop/
  truncate all fail (`StreamTruncated` at `finish`).
- **Key rotation** (`QSR2`): `PublicKeyBundle::key_id` (`SHA3-256(QSP2)[..16]`)
  and `RotationAttestation` — the old keypair hybrid-signs `old_key_id ||
  epoch || new_public`, giving verifiers a cryptographic old→new link
  (`HybridCrypto::attest_rotation`, `verify_rotation`).
- New parser fuzz targets, normative `docs/design.md` sections for all three
  formats, and golden vectors (`key_id`, deterministic rotation attestation).
- New `Error` variants (`NoRecipients`, `TooManyRecipients`, `StreamFinished`,
  `StreamTruncated`); the enum is `#[non_exhaustive]`, so this is non-breaking.

### Security (hardening from the validation pass)

- **Multi-recipient key commitment.** Because AES-GCM is not key-committing, a
  malicious sender could otherwise wrap different CEKs to different recipients
  and craft one payload that decrypts to different plaintexts per recipient.
  `QSM2` now carries `SHA3-256(label || CEK)`, bound into the payload AAD and checked
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

## [0.2.2] - 2026-07-04 (not published to crates.io)

Hardening. `std` remains a default feature, so existing users are unaffected;
all additions are opt-in.

### Added

- `no_std` support: the crate is `#![no_std]` and needs only `alloc`. Disable
  the default `std` feature for embedded targets (supply a `getrandom` backend;
  CI type-checks the full API with `cargo check` for `thumbv7em-none-eabi`).
- `pem` feature: `PublicKeyBundle::{to_pem, from_pem}` — per-component PEM for
  the public keys (standard SubjectPublicKeyInfo for ML-KEM/ML-DSA/Ed25519, a
  raw block for X25519). The `QSP2` bundle stays the primary format; PEM import
  round-trips through it, so it enforces the same validation. A fuzz target
  covers the new parser.
- `examples/dudect.rs`: a dudect constant-time regression harness on `open`
  (decapsulate + AEAD), wired as a non-gating CI job. It measured low
  t-values locally; as a statistical tripwire it can flag a leak but cannot
  show there is none. (Its tamper case flipped the wrong byte until 0.3.2.)

### Changed

- Dependencies are built with `default-features = false` + `alloc`; `ml-dsa`
  drops its `getrandom` default (signing is deterministic) and `ed25519-dalek`
  uses `alloc` instead of `std` unless the `std` feature is on.

## [0.2.1] - 2026-07-04 (not published to crates.io)

Assurance and tooling; no source or wire-format changes (API-compatible with
0.2.0).

### Added

- Criterion benchmarks (`benches/crypto.rs`, `benches/codec.rs`) for key
  generation, seal/open, sign/verify, and the wire codecs, replacing the
  fabricated numbers removed in 0.2.0. No numbers are published; run them on
  your own hardware.
- In-crate known-answer tests: RFC 7748 (X25519) and RFC 8032 (Ed25519)
  official vectors, plus deterministic stability KATs for ML-KEM-1024 and
  ML-DSA-87 that pin the parameter set and FIPS sizes against the locked
  crate versions (full ACVP conformance remains covered upstream).
- `fuzz/` cargo-fuzz crate: six libFuzzer targets covering every `from_bytes`
  parser and the seal/open and sign/verify roundtrips.
- CI jobs: `cargo-semver-checks` (baseline `v0.2.0`), coverage
  (`cargo-llvm-cov` → Codecov, non-gating), and a fuzz smoke run (nightly
  toolchain) on every push.

## [0.2.0] - 2026-07-04 (not published to crates.io)

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
  and the full public transcript (a Chempat-style full-transcript combiner;
  earlier docs misnamed it X-Wing) — both layers must now be broken.
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
- Private keys are now stored and exported only in seed form (166-byte
  bundle), zeroized on drop; `Debug` output redacts key material; decryption/verification errors
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

## [0.1.0] - 2025-10-24

Initial release: RSA-4096 + Kyber-1024 encryption, RSA-PSS + Dilithium5
signatures. **Insecure by design; do not use. See the 0.2.0 security notes.**
