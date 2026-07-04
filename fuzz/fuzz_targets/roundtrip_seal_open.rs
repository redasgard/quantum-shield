#![no_main]
//! seal → to_bytes → from_bytes → open must recover any plaintext for a
//! deterministically derived recipient keypair.

use libfuzzer_sys::fuzz_target;
use quantum_shield::{seal, Envelope, HybridCrypto};

fuzz_target!(|data: &[u8]| {
    // Derive a recipient from a fixed seed bundle so the fuzzer explores the
    // plaintext space, not key generation (which uses the OS RNG).
    let mut secret = Vec::with_capacity(166);
    secret.extend_from_slice(b"QSK2");
    secret.push(2);
    secret.push(1);
    secret.extend_from_slice(&[0x11; 32]);
    secret.extend_from_slice(&[0x22; 64]);
    secret.extend_from_slice(&[0x33; 32]);
    secret.extend_from_slice(&[0x44; 32]);
    let recipient = HybridCrypto::from_secret_bytes(&secret).unwrap();

    // Bound to the crate's own plaintext limit to keep iterations fast.
    let plaintext = if data.len() > 4096 { &data[..4096] } else { data };

    let envelope = seal(plaintext, recipient.public_keys()).unwrap();
    let bytes = envelope.to_bytes();
    let parsed = Envelope::from_bytes(&bytes).unwrap();
    let recovered = recipient.open(&parsed).unwrap();
    assert_eq!(recovered, plaintext);
});
