//! Key-rotation attestation tests.

use quantum_shield::{verify_rotation, HybridCrypto, RotationAttestation, HEADER_LEN};

#[test]
fn valid_attestation_verifies() {
    let old = HybridCrypto::generate().unwrap();
    let new = HybridCrypto::generate().unwrap();

    let att = old.attest_rotation(new.public_keys()).unwrap();
    let trusted = verify_rotation(old.public_keys(), &att).unwrap();
    assert_eq!(trusted, new.public_keys());
}

#[test]
fn wire_roundtrip() {
    let old = HybridCrypto::generate().unwrap();
    let new = HybridCrypto::generate().unwrap();
    let att = old.attest_rotation(new.public_keys()).unwrap();

    let bytes = att.to_bytes();
    let parsed = RotationAttestation::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, att);
    // Still verifies after a wire round-trip.
    assert_eq!(
        verify_rotation(old.public_keys(), &parsed).unwrap(),
        new.public_keys()
    );
}

#[test]
fn forged_by_different_key_fails() {
    let old = HybridCrypto::generate().unwrap();
    let mallory = HybridCrypto::generate().unwrap();
    let new = HybridCrypto::generate().unwrap();

    // Mallory signs the new key, but a verifier trusting `old` must reject it.
    let forged = mallory.attest_rotation(new.public_keys()).unwrap();
    assert!(verify_rotation(old.public_keys(), &forged).is_err());
}

#[test]
fn wrong_trust_anchor_fails() {
    let old = HybridCrypto::generate().unwrap();
    let new = HybridCrypto::generate().unwrap();
    let other = HybridCrypto::generate().unwrap();

    let att = old.attest_rotation(new.public_keys()).unwrap();
    // Verifying against the wrong old key fails (the key_id in the message
    // differs, and the signer doesn't match).
    assert!(verify_rotation(other.public_keys(), &att).is_err());
}

#[test]
fn tampered_new_public_fails() {
    let old = HybridCrypto::generate().unwrap();
    let new = HybridCrypto::generate().unwrap();
    let attacker = HybridCrypto::generate().unwrap();

    let att = old.attest_rotation(new.public_keys()).unwrap();
    let mut bytes = att.to_bytes();
    // Overwrite the embedded new_public bundle with the attacker's key.
    let start = HEADER_LEN;
    let attacker_bundle = attacker.public_keys().to_bytes();
    bytes[start..start + attacker_bundle.len()].copy_from_slice(&attacker_bundle);

    let parsed = RotationAttestation::from_bytes(&bytes).unwrap();
    // The signature no longer covers this bundle.
    assert!(verify_rotation(old.public_keys(), &parsed).is_err());
}

#[test]
fn key_id_is_stable_and_distinct() {
    let a = HybridCrypto::generate().unwrap();
    let b = HybridCrypto::generate().unwrap();
    assert_eq!(a.public_keys().key_id(), a.public_keys().key_id());
    assert_ne!(a.public_keys().key_id(), b.public_keys().key_id());
}

#[test]
fn truncated_attestation_rejected() {
    let old = HybridCrypto::generate().unwrap();
    let new = HybridCrypto::generate().unwrap();
    let bytes = old.attest_rotation(new.public_keys()).unwrap().to_bytes();
    assert!(RotationAttestation::from_bytes(&bytes[..bytes.len() - 1]).is_err());
}
