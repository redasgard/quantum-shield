//! Downgrade-resistance tests: legacy formats, unknown versions/suites, and
//! signature-stripping must all be rejected.

use quantum_shield::{
    verify, Envelope, Error, HybridCrypto, HybridSignature, KeyPair, PublicKeyBundle,
    ED25519_SIG_LEN, HEADER_LEN,
};

/// v0.1.x artifacts were JSON objects. They must be rejected with a
/// dedicated error, not a generic parse failure.
#[test]
fn v1_json_artifacts_rejected() {
    let v1_ciphertext = br#"{"version":1,"ciphertext":"bm9wZQ==","encrypted_key_rsa":"...","encrypted_key_kyber":"...","algorithm":"AES-256-GCM + RSA-4096-OAEP + Kyber-1024"}"#;
    assert_eq!(
        Envelope::from_bytes(v1_ciphertext).unwrap_err(),
        Error::LegacyV1Artifact
    );

    let v1_signature = br#"{"version":1,"rsa_signature":"...","dilithium_signature":null}"#;
    assert_eq!(
        HybridSignature::from_bytes(v1_signature).unwrap_err(),
        Error::LegacyV1Artifact
    );

    let v1_pubkeys = br#"{"rsa_pem":"-----BEGIN PUBLIC KEY-----","kyber_base64":"...","dilithium_base64":"...","version":1}"#;
    assert_eq!(
        PublicKeyBundle::from_bytes(v1_pubkeys).unwrap_err(),
        Error::LegacyV1Artifact
    );
    assert_eq!(
        KeyPair::from_secret_bytes(v1_pubkeys).unwrap_err(),
        Error::LegacyV1Artifact
    );
}

#[test]
fn unknown_version_and_suite_rejected() {
    let bob = HybridCrypto::generate().unwrap();
    let bytes = bob.seal_for(b"m", bob.public_keys()).unwrap().to_bytes();

    for (version, suite, expected) in [
        (1u8, 1u8, Error::UnsupportedVersion(1)),
        (3, 1, Error::UnsupportedVersion(3)),
        (2, 0, Error::UnsupportedSuite(0)),
        (2, 2, Error::UnsupportedSuite(2)),
    ] {
        let mut altered = bytes.clone();
        altered[4] = version;
        altered[5] = suite;
        assert_eq!(Envelope::from_bytes(&altered).unwrap_err(), expected);
    }
}

/// The v1 vulnerability: verification passing with the post-quantum
/// signature absent. In v2 the ML-DSA component is a fixed-size field —
/// there is no encoding without it — and zeroing it must fail verification.
#[test]
fn signature_stripping_impossible() {
    let alice = HybridCrypto::generate().unwrap();
    let sig = alice.sign(b"message", b"").unwrap();
    let bytes = sig.to_bytes();

    // Truncating to just the Ed25519 half fails to parse.
    assert_eq!(
        HybridSignature::from_bytes(&bytes[..HEADER_LEN + ED25519_SIG_LEN]).unwrap_err(),
        Error::InvalidSignature
    );

    // Zeroing the ML-DSA half fails verification.
    let mut stripped = bytes.clone();
    stripped[HEADER_LEN + ED25519_SIG_LEN..].fill(0);
    let parsed = HybridSignature::from_bytes(&stripped).unwrap();
    assert_eq!(
        verify(b"message", b"", &parsed, alice.public_keys()).unwrap_err(),
        Error::VerificationFailed
    );

    // Zeroing the Ed25519 half also fails: both layers are enforced.
    let mut classical_stripped = bytes.clone();
    classical_stripped[HEADER_LEN..HEADER_LEN + ED25519_SIG_LEN].fill(0);
    let parsed = HybridSignature::from_bytes(&classical_stripped).unwrap();
    assert_eq!(
        verify(b"message", b"", &parsed, alice.public_keys()).unwrap_err(),
        Error::VerificationFailed
    );
}

/// A signature over one (context, message) pair must not verify for any
/// other split of the same byte stream.
#[test]
fn framing_is_injective() {
    let alice = HybridCrypto::generate().unwrap();
    let sig = alice.sign(b"b", b"ca").unwrap();
    assert!(verify(b"ab", b"c", &sig, alice.public_keys()).is_err());
    assert!(verify(b"cab", b"", &sig, alice.public_keys()).is_err());
    assert!(verify(b"", b"cab", &sig, alice.public_keys()).is_err());
    // And the original still verifies.
    verify(b"b", b"ca", &sig, alice.public_keys()).unwrap();
}

/// Signatures must not be transplantable between signers.
#[test]
fn signature_not_transferable() {
    let alice = HybridCrypto::generate().unwrap();
    let mallory = HybridCrypto::generate().unwrap();
    let sig = alice.sign(b"pay mallory $100", b"").unwrap();
    assert!(verify(b"pay mallory $100", b"", &sig, mallory.public_keys()).is_err());
}
