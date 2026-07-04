#![no_main]
//! Parsing arbitrary text as a PEM public-key bundle must never panic.

use libfuzzer_sys::fuzz_target;
use quantum_shield::PublicKeyBundle;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(bundle) = PublicKeyBundle::from_pem(text) {
            // A bundle that parses from PEM must re-export and re-parse.
            let pem = bundle.to_pem().expect("valid bundle re-encodes");
            let reparsed = PublicKeyBundle::from_pem(&pem).expect("reparse of own output");
            assert_eq!(bundle, reparsed);
        }
    }
});
