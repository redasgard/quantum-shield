# Gap Matrix — quantum-shield v0.2.0 vs. production-grade

Baseline: a general-purpose, production-grade hybrid post-quantum
cryptography library. Status as of the v0.2.0 rewrite on branch
`claude/crate-analysis-2gpwdm`.

**Legend:** ✅ done · 🟡 partial · ❌ missing · ⬜ out of scope by design (v2)

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
| Multi-recipient encryption | ⬜ | One envelope → one recipient in v2 |
| Streaming / chunked AEAD for >64 MiB | ⬜ | Single-shot, 64 MiB cap |
| Forward secrecy for recipient (ratchet/rotation) | ⬜ | Static recipient KEM keys; documented in security model |
| Authenticated sender (signcryption) | ⬜ | `seal` is anonymous by design |

## 2. Side-channel & memory hardening

| Capability | Status | Notes / gap |
|---|---|---|
| Zeroization of private key material | ✅ | Seeds + shared secrets, `zeroize`/`Zeroizing` |
| `Debug` redaction of secrets | ✅ | `KeyPair`/`PublicKeyBundle` |
| Uniform decryption/verification errors (no oracle) | ✅ | `Error::DecryptionFailed` carries no detail |
| Constant-time primitives | 🟡 | Inherited from dalek/RustCrypto; **not independently verified** |
| Constant-time verification (dudect / ctgrind) | ❌ | No timing-leakage test harness |
| Fault-injection / EM resistance | ❌ | No claims, no mitigations |

## 3. API & interoperability

| Capability | Status | Notes / gap |
|---|---|---|
| seal/open, sign/verify, key export/import | ✅ | `src/api.rs`, `src/lib.rs` |
| Versioned binary wire format, unknown-version rejection | ✅ | `src/wire.rs`, `docs/design.md` |
| serde support (optional feature) | ✅ | `src/serde_impls.rs` |
| Interop with an independent implementation | 🟡 | Format is specified (`docs/design.md`) but no second implementation validated against it |
| Standard key encodings (PKCS#8/SPKI/PEM) | ❌ | Custom binary bundles only |
| `no_std` support | ❌ | std-only (crate `no-std` category was removed) |
| Async API | ⬜ | Removed; ops are CPU-bound, not IO-bound |

## 4. Testing & QA

| Capability | Status | Notes / gap |
|---|---|---|
| Unit + integration tests (61 total) | ✅ | lib + roundtrip/tamper/downgrade |
| Adversarial: byte-flip, splice, downgrade, stripping | ✅ | `tests/tamper.rs`, `tests/downgrade.rs` |
| Property-based tests | ✅ | `tests/proptests.rs` |
| Wire-format golden / KAT vectors | ✅ | Self-generated (`tests/golden.rs`, `src/hybrid_kem.rs`) |
| RFC 7748 / RFC 8032 sanity vectors | ❌ | Planned but not added; relies on dalek's own tests |
| NIST ACVP vectors for ML-KEM/ML-DSA in-crate | ❌ | Relies on upstream crates' vectors |
| Fuzzing (`cargo-fuzz`) of all parsers | ❌ | No fuzz targets for `from_bytes` paths |
| Benchmarks (`criterion`) | ❌ | No real benchmarks (fabricated ones were removed) |
| Coverage measurement | ❌ | Not wired into CI |

## 5. CI, supply chain & release

| Capability | Status | Notes / gap |
|---|---|---|
| Multi-OS CI incl. macOS arm64 (Apple Silicon) | 🟡 | Workflow written; **not yet executed on GitHub** — the arm64 gate is unproven until it runs |
| fmt + clippy (`-D warnings`) + doc | ✅ | `.github/workflows/ci.yml` |
| MSRV (1.85) check | ✅ | Dedicated job |
| `cargo-deny` (advisories/licenses/sources) | ✅ | `deny.toml` |
| SemVer breakage check (`cargo-semver-checks`) | ❌ | Useful from 0.2.x onward |
| Signed releases / SLSA provenance / SBOM | ❌ | No supply-chain attestation |
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

## Highest-value gaps to close next

1. **Parser fuzzing** (`cargo-fuzz` over every `from_bytes`) — cheap, high assurance on attacker-controlled input.
2. **Confirm the Apple Silicon CI gate actually runs green** — the requirement isn't met until a `macos-15` job passes.
3. **RFC 7748 / 8032 + a handful of ML-KEM/ML-DSA ACVP vectors in-crate** — guards against a feature/wiring mistake that upstream tests wouldn't catch here.
4. **Real `criterion` benchmarks** — replaces the deleted fabricated numbers with measured ones.
5. **`cargo-semver-checks` in CI** — protects the now-stable API/wire format going forward.
6. **Independent audit** — the one gap that external work, not code, must close before "production-grade" is fully honest.
