#![no_main]
//! Parsing arbitrary bytes as a HybridSignature must never panic.

use libfuzzer_sys::fuzz_target;
use quantum_shield::HybridSignature;

fuzz_target!(|data: &[u8]| {
    if let Ok(sig) = HybridSignature::from_bytes(data) {
        let reparsed = HybridSignature::from_bytes(&sig.to_bytes()).expect("reparse of own output");
        assert_eq!(sig, reparsed);
    }
});
