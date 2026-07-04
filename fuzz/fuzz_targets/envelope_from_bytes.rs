#![no_main]
//! Parsing arbitrary bytes as an Envelope must never panic.

use libfuzzer_sys::fuzz_target;
use quantum_shield::Envelope;

fuzz_target!(|data: &[u8]| {
    // Round-trip any successfully parsed envelope: to_bytes ∘ from_bytes
    // must re-parse identically (codec is a total inverse on valid data).
    if let Ok(env) = Envelope::from_bytes(data) {
        let reserialized = env.to_bytes();
        let reparsed = Envelope::from_bytes(&reserialized).expect("reparse of own output");
        assert_eq!(env, reparsed);
    }
});
