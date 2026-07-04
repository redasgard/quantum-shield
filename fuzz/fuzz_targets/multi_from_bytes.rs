#![no_main]
//! Parsing arbitrary bytes as a multi-recipient envelope must never panic.

use libfuzzer_sys::fuzz_target;
use quantum_shield::MultiRecipientEnvelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = MultiRecipientEnvelope::from_bytes(data) {
        let reparsed = MultiRecipientEnvelope::from_bytes(&env.to_bytes())
            .expect("reparse of own output");
        assert_eq!(env, reparsed);
    }
});
