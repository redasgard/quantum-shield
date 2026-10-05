# Fuzzing quantum-shield

Parser and roundtrip fuzz targets built on [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
(libFuzzer). This crate is intentionally **outside** the main workspace so
its nightly/sanitizer build does not affect the library.

## Targets

| Target | Property checked |
|---|---|
| `envelope_from_bytes` | `Envelope::from_bytes` never panics; parsed envelopes round-trip |
| `signature_from_bytes` | `HybridSignature::from_bytes` never panics; round-trips |
| `public_bundle_from_bytes` | `PublicKeyBundle::from_bytes` never panics; round-trips |
| `secret_from_bytes` | `HybridCrypto::from_secret_bytes` never panics; round-trips |
| `public_bundle_from_pem` | `PublicKeyBundle::from_pem` never panics (`pem` feature) |
| `multi_from_bytes` | `MultiRecipientEnvelope::from_bytes` never panics; round-trips |
| `stream_parse` | stream header and chunk-frame parsing never panic |
| `rotation_from_bytes` | `RotationAttestation::from_bytes` never panics; round-trips |
| `roundtrip_seal_open` | `seal → to_bytes → from_bytes → open` recovers the plaintext |
| `roundtrip_sign_verify` | `sign → to_bytes → from_bytes → verify` accepts |

## Running

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

cargo +nightly fuzz run envelope_from_bytes            # runs until a crash
cargo +nightly fuzz run envelope_from_bytes -- -max_total_time=60   # timed
```

Corpora are written to `corpus/<target>/`, which is git-ignored: none are
committed, so each run starts from an empty corpus. CI smoke-runs every target
for 30 seconds on each push.
