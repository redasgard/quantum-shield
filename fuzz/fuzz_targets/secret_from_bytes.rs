#![no_main]
//! Parsing arbitrary bytes as a secret-key bundle must never panic.

use libfuzzer_sys::fuzz_target;
use quantum_shield::HybridCrypto;

fuzz_target!(|data: &[u8]| {
    if let Ok(crypto) = HybridCrypto::from_secret_bytes(data) {
        // A parsed keypair must re-export to a bundle that parses back to the
        // same public keys.
        let secret = crypto.to_secret_bytes();
        let restored = HybridCrypto::from_secret_bytes(&secret).expect("reparse of own output");
        assert_eq!(restored.public_keys(), crypto.public_keys());
    }
});
