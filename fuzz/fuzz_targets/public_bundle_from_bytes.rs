#![no_main]
//! Parsing arbitrary bytes as a PublicKeyBundle must never panic, and any
//! bundle that parses must survive a serialize/parse round-trip.

use libfuzzer_sys::fuzz_target;
use quantum_shield::PublicKeyBundle;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = PublicKeyBundle::from_bytes(data) {
        let reparsed = PublicKeyBundle::from_bytes(&bundle.to_bytes()).expect("reparse of own output");
        assert_eq!(bundle, reparsed);
    }
});
