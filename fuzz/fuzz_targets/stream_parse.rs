#![no_main]
//! Streaming header parsing and chunk opening must never panic on arbitrary
//! input, using a fixed recipient keypair so the fuzzer explores the parser.

use libfuzzer_sys::fuzz_target;
use quantum_shield::HybridCrypto;

fn recipient() -> HybridCrypto {
    let mut secret = Vec::with_capacity(166);
    secret.extend_from_slice(b"QSK2");
    secret.push(2);
    secret.push(1);
    secret.extend_from_slice(&[0x91; 32]);
    secret.extend_from_slice(&[0x92; 64]);
    secret.extend_from_slice(&[0x93; 32]);
    secret.extend_from_slice(&[0x94; 32]);
    HybridCrypto::from_secret_bytes(&secret).unwrap()
}

fuzz_target!(|data: &[u8]| {
    let kp = recipient();
    // Split arbitrary input into a header candidate and a chunk-frame candidate.
    let split = data.len() / 2;
    let (header, frame) = data.split_at(split);
    if let Ok(mut opener) = kp.stream_opener(header) {
        // Opening an arbitrary frame must not panic (it will almost always fail
        // authentication).
        let _ = opener.open_chunk(frame);
    }
});
