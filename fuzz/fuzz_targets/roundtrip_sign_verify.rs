#![no_main]
//! sign → to_bytes → from_bytes → verify must accept for any (message,
//! context) pair within the crate's limits.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use quantum_shield::{verify, HybridCrypto, HybridSignature};

#[derive(Arbitrary, Debug)]
struct Input {
    message: Vec<u8>,
    context: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Fixed signer keypair (deterministic) so the fuzzer explores messages.
    let mut secret = Vec::with_capacity(166);
    secret.extend_from_slice(b"QSK2");
    secret.push(2);
    secret.push(1);
    secret.extend_from_slice(&[0x55; 32]);
    secret.extend_from_slice(&[0x66; 64]);
    secret.extend_from_slice(&[0x77; 32]);
    secret.extend_from_slice(&[0x88; 32]);
    let signer = HybridCrypto::from_secret_bytes(&secret).unwrap();

    // Context is capped at 255 bytes by the API; longer must be a clean error.
    match signer.sign(&input.message, &input.context) {
        Ok(sig) => {
            assert!(input.context.len() <= 255);
            let parsed = HybridSignature::from_bytes(&sig.to_bytes()).unwrap();
            verify(&input.message, &input.context, &parsed, signer.public_keys()).unwrap();
        }
        Err(_) => assert!(input.context.len() > 255),
    }
});
