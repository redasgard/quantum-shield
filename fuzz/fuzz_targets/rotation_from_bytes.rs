#![no_main]
//! Parsing arbitrary bytes as a rotation attestation must never panic.

use libfuzzer_sys::fuzz_target;
use quantum_shield::RotationAttestation;

fuzz_target!(|data: &[u8]| {
    if let Ok(att) = RotationAttestation::from_bytes(data) {
        let reparsed =
            RotationAttestation::from_bytes(&att.to_bytes()).expect("reparse of own output");
        assert_eq!(att, reparsed);
    }
});
