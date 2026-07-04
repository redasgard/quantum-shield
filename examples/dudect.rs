//! Constant-time regression harness (dudect t-test).
//!
//! This is a **tripwire, not a proof.** The real constant-time guarantees come
//! from the underlying dalek / RustCrypto primitives; this harness only flags
//! if a change to *this* crate introduced a secret-dependent timing branch in
//! `open`, the one operation an attacker can probe with chosen ciphertexts
//! while the recipient's **secret key** is in use (decapsulate + AEAD).
//!
//! Only `open` is tested. `sign` runs on a fixed secret with a public message,
//! and `verify` runs entirely on public data (message, public key, signature)
//! — a timing difference between valid and invalid signatures there leaks
//! nothing secret and is expected (ML-DSA legitimately fast-rejects malformed
//! signatures), so measuring it would be a false tripwire.
//!
//! dudect is noisy, so it is run manually / on a schedule, never as a PR gate:
//!
//! ```text
//! cargo run --release --example dudect
//! cargo run --release --example dudect -- --filter open_wrong_recipient
//! ```
//!
//! Interpretation: a small |t| (roughly < 10) that does not grow with more
//! samples is good. A large, growing |t| is the signal to investigate a
//! secret-dependent branch.

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use quantum_shield::{seal, Envelope, HybridCrypto};

const SAMPLES: usize = 100_000;

/// Can an attacker distinguish a ciphertext that decrypts (Left) from one that
/// fails (Right, addressed to a different recipient) by timing `open`? Both run
/// a full ML-KEM decapsulation and a full AES-GCM pass under the same secret
/// key, so timing must not separate them.
fn open_wrong_recipient(runner: &mut CtRunner, rng: &mut BenchRng) {
    let recipient = HybridCrypto::generate().unwrap();
    let other = HybridCrypto::generate().unwrap();

    let inputs: Vec<(Envelope, Class)> = (0..SAMPLES)
        .map(|_| {
            if rng.random::<bool>() {
                (
                    seal(b"constant-time probe", recipient.public_keys()).unwrap(),
                    Class::Left,
                )
            } else {
                (
                    seal(b"constant-time probe", other.public_keys()).unwrap(),
                    Class::Right,
                )
            }
        })
        .collect();

    for (envelope, class) in inputs {
        runner.run_one(class, || {
            let _ = recipient.open(&envelope);
        });
    }
}

/// The chosen-ciphertext timing concern: a valid envelope (Left) versus the
/// same envelope with a flipped ML-KEM ciphertext byte (Right), which triggers
/// ML-KEM implicit rejection. The rejection path must take the same time as a
/// success, or decryption-failure timing could leak information about the
/// secret key.
fn open_tampered_ciphertext(runner: &mut CtRunner, rng: &mut BenchRng) {
    let recipient = HybridCrypto::generate().unwrap();

    let inputs: Vec<(Envelope, Class)> = (0..SAMPLES)
        .map(|_| {
            let envelope = seal(b"constant-time probe", recipient.public_keys()).unwrap();
            if rng.random::<bool>() {
                (envelope, Class::Left)
            } else {
                // Flip one byte inside the ML-KEM ciphertext region.
                let mut bytes = envelope.to_bytes();
                bytes[10] ^= 0x01;
                (Envelope::from_bytes(&bytes).unwrap(), Class::Right)
            }
        })
        .collect();

    for (envelope, class) in inputs {
        runner.run_one(class, || {
            let _ = recipient.open(&envelope);
        });
    }
}

ctbench_main!(open_wrong_recipient, open_tampered_ciphertext);
