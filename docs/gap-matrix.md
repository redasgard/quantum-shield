# Gap Matrix — quantum-shield vs. production-grade

Baseline: a general-purpose, production-grade hybrid post-quantum
cryptography library. Updated as of **v0.2.1** on branch
`claude/crate-analysis-2gpwdm`.

**Legend:** ✅ done · 🟡 partial · ❌ missing · ⬜ out of scope by design (v2)

Gap-closing shipped across releases: **0.2.1** (assurance/tooling),
**0.2.2** (hardening: no_std, constant-time, PKCS#8/PEM), **0.3.0**
(features: multi-recipient, streaming, rotation). The section tables mark
which release landed each item. The remaining open items are external
(audit, supply-chain attestation) — see the end.

## 1. Cryptographic core

| Capability | Status | Notes / gap |
|---|---|---|
| Hybrid KEM (X25519 + ML-KEM-1024), KDF-combined | ✅ | SHA3-256 combiner over both secrets + full transcript (`src/hybrid_kem.rs`) |
| Hybrid signatures (Ed25519 + ML-DSA-87), both mandatory | ✅ | Non-short-circuit verify, `verify_strict` (`src/sign.rs`) |
| AEAD payload (AES-256-GCM) with header bound as AAD | ✅ | `src/seal.rs` |
| FIPS 203/204 algorithms (final, not round-3) | ✅ | RustCrypto `ml-kem` 0.3 / `ml-dsa` 0.1 |
| Domain separation + injective framing | ✅ | Labels + length-prefixed context |
| Combiner is standard X-Wing (ML-KEM-768) | 🟡 | Deliberately adapted to ML-KEM-1024; not the ratified draft. No formal proof for the ported construction |
| Randomized ("hedged") ML-DSA signing | ❌ | Deterministic only; `ml-dsa` 0.1 doesn't expose hedged path |
| Multi-recipient encryption | ✅ | `seal_multi`/`open_multi` (`QSM2`), recipient set bound into payload (0.3.0) |
| Streaming / chunked AEAD for >64 MiB | ✅ | `StreamSealer`/`StreamOpener` (`QST2`), STREAM construction (0.3.0) |
| Key rotation (signed old→new attestation) | ✅ | `key_id` + `RotationAttestation` (`QSR2`) (0.3.0) |
| Forward secrecy for recipient (ratchet) | ⬜ | Static recipient KEM keys; rotation gives bounded-exposure re-keying, not per-message FS |
| Authenticated sender (signcryption) | ⬜ | `seal` is anonymous by design |

## 2. Side-channel & memory hardening

| Capability | Status | Notes / gap |
|---|---|---|
| Zeroization of private key material | ✅ | Seeds + shared secrets, `zeroize`/`Zeroizing` |
| `Debug` redaction of secrets | ✅ | `KeyPair`/`PublicKeyBundle` |
| Uniform decryption/verification errors (no oracle) | ✅ | `Error::DecryptionFailed` carries no detail |
| Constant-time primitives | 🟡 | Inherited from dalek/RustCrypto; not independently verified, but now regression-checked (below) |
| Constant-time regression harness (dudect) | ✅ | `examples/dudect.rs` on `open`; low t locally; non-gating CI (0.2.2) |
| Fault-injection / EM resistance | ❌ | No claims, no mitigations |

## 3. API & interoperability

| Capability | Status | Notes / gap |
|---|---|---|
| seal/open, sign/verify, key export/import | ✅ | `src/api.rs`, `src/lib.rs` |
| Versioned binary wire format, unknown-version rejection | ✅ | `src/wire.rs`, `docs/design.md` |
| serde support (optional feature) | ✅ | `src/serde_impls.rs` |
| Interop with an independent implementation | 🟡 | Format is specified (`docs/design.md`) but no second implementation validated against it |
| Standard key encodings (PKCS#8/SPKI/PEM) | ✅ | `pem` feature: per-component SPKI PEM for ML-KEM/ML-DSA/Ed25519, raw block for X25519 (0.2.2) |
| `no_std` support | ✅ | `#![no_std]` + `alloc`; bare-metal CI gate (`thumbv7em-none-eabi`) (0.2.2) |
| Async API | ⬜ | Removed; ops are CPU-bound, not IO-bound |

## 4. Testing & QA

| Capability | Status | Notes / gap |
|---|---|---|
| Unit + integration tests (61 total) | ✅ | lib + roundtrip/tamper/downgrade |
| Adversarial: byte-flip, splice, downgrade, stripping | ✅ | `tests/tamper.rs`, `tests/downgrade.rs` |
| Property-based tests | ✅ | `tests/proptests.rs` |
| Wire-format golden / KAT vectors | ✅ | Self-generated (`tests/golden.rs`, `src/hybrid_kem.rs`) |
| RFC 7748 / RFC 8032 sanity vectors | ✅ | `tests/kat_x25519.rs`, `tests/kat_ed25519.rs` (0.2.1) |
| ML-KEM / ML-DSA in-crate vectors | 🟡 | `tests/kat_mlkem.rs`, `tests/kat_mldsa.rs` pin param-set/sizes/derivation (0.2.1); full ACVP conformance stays upstream |
| Fuzzing (`cargo-fuzz`) of all parsers | ✅ | `fuzz/` — six targets, all `from_bytes` + roundtrips (0.2.1) |
| Benchmarks (`criterion`) | ✅ | `benches/crypto.rs`, `benches/codec.rs` (0.2.1) |
| Coverage measurement | ✅ | `cargo-llvm-cov` → Codecov CI job (0.2.1, non-gating) |

## 5. CI, supply chain & release

| Capability | Status | Notes / gap |
|---|---|---|
| Multi-OS CI incl. macOS arm64 (Apple Silicon) | 🟡 | Workflow runs on `claude/**` pushes now; the arm64 job is green **once the push CI completes** (verify on GitHub) |
| fmt + clippy (`-D warnings`) + doc | ✅ | `.github/workflows/ci.yml` |
| MSRV (1.85) check | ✅ | Dedicated job |
| `cargo-deny` (advisories/licenses/sources) | ✅ | `deny.toml` |
| SemVer breakage check (`cargo-semver-checks`) | ✅ | CI job vs. the 0.2.0 baseline commit (0.2.1) |
| Signed releases / SLSA provenance / SBOM | ❌ | No supply-chain attestation |
| Git tags for releases | 🟡 | Tags created locally; this environment's remote rejects tag pushes, so release refs are commit SHAs |
| `cargo publish` dry-run passes | ✅ | Verified locally |

## 6. Docs, governance & assurance

| Capability | Status | Notes / gap |
|---|---|---|
| README, design spec, threat model, migration guide | ✅ | `docs/design.md`, `docs/security-model.md`, `docs/migration-v1-to-v2.md` |
| Honest "not audited / not FIPS-validated" disclosure | ✅ | README + SECURITY.md |
| Threat model with explicit non-goals | ✅ | `docs/security-model.md` |
| Independent third-party security audit | ❌ | **Largest gap** for a security-critical library |
| Formal verification of the combiner/framing | ❌ | No machine-checked proof |
| FIPS validation | ⬜ | Not attainable for a pure-Rust crate without a CAVP/CMVP program |

## Remaining gaps (post-0.2.1)

Closed in 0.2.1: parser fuzzing, RFC/ML-KEM/ML-DSA in-crate vectors, criterion
benchmarks, coverage, `cargo-semver-checks`. Closed in 0.2.2: `no_std`+`alloc`
(bare-metal CI gate), dudect constant-time regression harness, PKCS#8/PEM
public-key interop. Closed in 0.3.0: multi-recipient envelopes, streaming
AEAD, key rotation. Still open:

1. **Confirm the Apple Silicon CI gate is green** — CI runs on this branch;
   verify the `macos-15` job passed on GitHub (the requirement isn't met until
   it does).
2. **Signed releases / SLSA / SBOM** — supply-chain attestation.
3. **Independent audit** — the one gap that external work, not code, must close
   before "production-grade" is fully honest.

The code-level gaps from the original matrix are now closed; what remains is
external assurance (audit) and release-infrastructure (attestation) work.
