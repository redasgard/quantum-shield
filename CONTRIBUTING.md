# Contributing to Quantum Shield

Thanks for your interest. Quantum Shield is a security-critical library, so
changes are held to a high bar: every claim in the docs must be true of the
code, and every behaviour change needs a test.

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

**Security issues:** do not open a public issue. Email
security@redasgard.com (see [SECURITY.md](SECURITY.md)).

## Prerequisites

- Rust 1.85+ (the MSRV, set by the `ml-kem`/`ml-dsa` and dalek 3 dependencies)
- For fuzzing: a nightly toolchain and `cargo install cargo-fuzz`
- For the interop check: Python 3.10+

## Project layout

```text
src/
  lib.rs           crate root, re-exports
  api.rs           HybridCrypto convenience wrapper
  keys.rs          KeyPair, PublicKeyBundle (QSP2), secret seeds (QSK2), key_id
  hybrid_kem.rs    X25519 + ML-KEM-1024 KEM and the SHA3-256 combiner
  seal.rs          single-recipient envelope (QSE2)
  sign.rs          hybrid Ed25519 + ML-DSA-87 signatures (QSS2)
  multi.rs         multi-recipient envelope (QSM2)
  stream.rs        streaming AEAD (QST2)
  rotate.rs        rotation attestations (QSR2)
  types.rs wire.rs constants.rs error.rs
  pem.rs           `pem` feature
  serde_impls.rs   `serde` feature
tests/             integration, adversarial, golden, NIST ACVP, RFC vectors
benches/           criterion benchmarks
examples/          basic_usage, dudect (constant-time tripwire), interop_gen
fuzz/              cargo-fuzz targets (separate crate)
ci/no_std_check/   bare-metal no_std build gate
ci/interop/        independent Python implementation of the wire formats
docs/              design.md (normative format spec), security-model.md,
                   gap-matrix.md, migration-v1-to-v2.md
```

## Before opening a PR

Run what CI runs:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
cargo check --manifest-path ci/no_std_check/Cargo.toml   # bare-metal no_std
cargo deny check advisories bans licenses sources

# Independent implementation must still open what the crate produces:
pip install -r ci/interop/requirements.txt
cargo run --example interop_gen -- /tmp/qs-artifacts
python ci/interop/cleanroom.py /tmp/qs-artifacts
```

Useful focused runs:

```bash
cargo test --test acvp          # NIST ACVP vectors
cargo test --test tamper        # adversarial byte-flip / splice suite
cargo test --test downgrade     # v1 / unknown-version rejection
cargo +nightly fuzz run envelope_from_bytes -- -max_total_time=60
cargo run --release --example dudect
```

## Rules for cryptographic changes

- **Wire formats are frozen.** A change to any format in `docs/design.md`
  needs a new magic/version or suite id, never an edit to the pinned golden
  vectors in `tests/golden.rs`. Update `docs/design.md` and
  `ci/interop/cleanroom.py` together.
- **No algorithm negotiation.** New algorithms are new suite ids.
- **Every secret is zeroized**, every comparison of secret-dependent data is
  constant-time (`subtle`), and errors on decryption/verification stay
  uniform.
- **Docs must not overclaim.** Do not describe the crate as audited,
  FIPS-validated, or proven secure; say what is tested and how.

## Releases

1. Bump `version` in `Cargo.toml` and add a `CHANGELOG.md` entry.
2. Merge a release PR with CI green (including `semver-checks`).
3. Tag `vX.Y.Z` on the merge commit and create a GitHub release.
4. `cargo publish`.
