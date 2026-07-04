//! RFC 8032 §7.1 known-answer tests for Ed25519.
//!
//! Run against the exact `ed25519-dalek` version/features this crate uses:
//! deterministic signing must reproduce the RFC signatures, and verification
//! (strict, as used in `src/sign.rs`) must accept them.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hex_literal::hex;

fn check(sk: [u8; 32], pk_expected: [u8; 32], msg: &[u8], sig_expected: [u8; 64]) {
    let signing = SigningKey::from_bytes(&sk);
    assert_eq!(
        signing.verifying_key().to_bytes(),
        pk_expected,
        "derived public key mismatch"
    );

    let sig = signing.sign(msg);
    assert_eq!(
        sig.to_bytes(),
        sig_expected,
        "deterministic signature mismatch"
    );

    let vk = VerifyingKey::from_bytes(&pk_expected).unwrap();
    vk.verify_strict(msg, &Signature::from_bytes(&sig_expected))
        .expect("RFC signature must verify strictly");
}

#[test]
fn rfc8032_test_1_empty_message() {
    check(
        hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        &[],
        hex!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a3"
            "3bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    );
}

#[test]
fn rfc8032_test_2_one_byte() {
    check(
        hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
        hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        &hex!("72"),
        hex!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15"
            "996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    );
}
