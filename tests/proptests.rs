//! Property-based tests over plaintexts, contexts, and corruption.

use proptest::prelude::*;
use quantum_shield::{seal, verify, Envelope, HybridCrypto, HybridSignature};
use std::sync::OnceLock;

/// Key generation is expensive; share one keypair across all cases.
fn keypair() -> &'static HybridCrypto {
    static KP: OnceLock<HybridCrypto> = OnceLock::new();
    KP.get_or_init(|| HybridCrypto::generate().unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn seal_open_roundtrips(msg in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let kp = keypair();
        let envelope = seal(&msg, kp.public_keys()).unwrap();
        let reparsed = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
        prop_assert_eq!(kp.open(&reparsed).unwrap(), msg);
    }

    #[test]
    fn sign_verify_roundtrips(
        msg in proptest::collection::vec(any::<u8>(), 0..4096),
        ctx in proptest::collection::vec(any::<u8>(), 0..=255),
    ) {
        let kp = keypair();
        let sig = kp.sign(&msg, &ctx).unwrap();
        let reparsed = HybridSignature::from_bytes(&sig.to_bytes()).unwrap();
        prop_assert!(verify(&msg, &ctx, &reparsed, kp.public_keys()).is_ok());
    }

    /// Corrupting any single byte anywhere in a serialized envelope must
    /// never yield a *different* plaintext. (Parse errors and decryption
    /// failures are both acceptable outcomes; silent corruption is not.)
    #[test]
    fn corruption_never_changes_plaintext(
        msg in proptest::collection::vec(any::<u8>(), 1..2048),
        offset_seed in any::<usize>(),
        flip in 1u8..=255,
    ) {
        let kp = keypair();
        let bytes = seal(&msg, kp.public_keys()).unwrap().to_bytes();
        let offset = offset_seed % bytes.len();

        let mut corrupted = bytes.clone();
        corrupted[offset] ^= flip;

        if let Ok(env) = Envelope::from_bytes(&corrupted) {
            if let Ok(plaintext) = kp.open(&env) {
                prop_assert_eq!(plaintext, msg, "corruption at offset {} accepted", offset);
            }
        }
    }

    /// Wire codecs are inverses on valid data.
    #[test]
    fn envelope_codec_is_inverse(msg in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let kp = keypair();
        let envelope = seal(&msg, kp.public_keys()).unwrap();
        let bytes = envelope.to_bytes();
        let reparsed = Envelope::from_bytes(&bytes).unwrap();
        prop_assert_eq!(reparsed.to_bytes(), bytes);
    }
}
