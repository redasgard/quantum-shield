//! Adversarial tests: every byte of an envelope is load-bearing.

use quantum_shield::{
    seal, Envelope, Error, HybridCrypto, ENVELOPE_AAD_LEN, HEADER_LEN, MLKEM1024_CT_LEN, NONCE_LEN,
    X25519_PK_LEN,
};

/// Flipping any single byte of a serialized envelope must prevent decryption
/// (either at parse time or as a uniform DecryptionFailed).
#[test]
fn any_single_byte_flip_defeats_decryption() {
    let bob = HybridCrypto::generate().unwrap();
    let msg = b"integrity is not optional";
    let envelope = seal(msg, bob.public_keys()).unwrap();
    let bytes = envelope.to_bytes();

    // Representative offsets from every region: magic, version, suite, epk,
    // ct_mlkem (start/middle/end), nonce, AEAD ciphertext, tag.
    let ct_off = HEADER_LEN + X25519_PK_LEN;
    let nonce_off = ct_off + MLKEM1024_CT_LEN;
    let offsets = [
        0,          // magic
        4,          // version
        5,          // suite
        HEADER_LEN, // epk first byte
        HEADER_LEN + X25519_PK_LEN - 1,
        ct_off, // ML-KEM ct first byte
        ct_off + MLKEM1024_CT_LEN / 2,
        nonce_off - 1, // ML-KEM ct last byte
        nonce_off,     // nonce
        nonce_off + NONCE_LEN - 1,
        ENVELOPE_AAD_LEN, // AEAD ciphertext first byte
        bytes.len() - 1,  // tag last byte
    ];

    for off in offsets {
        let mut corrupted = bytes.clone();
        corrupted[off] ^= 0x01;
        let result = Envelope::from_bytes(&corrupted).and_then(|env| bob.open(&env));
        assert!(result.is_err(), "byte flip at offset {off} was accepted");
    }
}

/// Swapping KEM components between two valid envelopes for the same
/// recipient must fail: the KDF transcript and the AAD bind them.
#[test]
fn cross_splicing_envelopes_fails() {
    let bob = HybridCrypto::generate().unwrap();
    let env_a = seal(b"message A", bob.public_keys()).unwrap().to_bytes();
    let env_b = seal(b"message B", bob.public_keys()).unwrap().to_bytes();

    let ct_off = HEADER_LEN + X25519_PK_LEN;
    let nonce_off = ct_off + MLKEM1024_CT_LEN;

    // Splice B's ML-KEM ciphertext into A.
    let mut spliced = env_a.clone();
    spliced[ct_off..nonce_off].copy_from_slice(&env_b[ct_off..nonce_off]);
    let result = Envelope::from_bytes(&spliced).and_then(|env| bob.open(&env));
    assert_eq!(result.unwrap_err(), Error::DecryptionFailed);

    // Splice B's ephemeral X25519 key into A.
    let mut spliced = env_a.clone();
    spliced[HEADER_LEN..ct_off].copy_from_slice(&env_b[HEADER_LEN..ct_off]);
    let result = Envelope::from_bytes(&spliced).and_then(|env| bob.open(&env));
    assert_eq!(result.unwrap_err(), Error::DecryptionFailed);

    // Splice B's entire KEM header but keep A's payload.
    let mut spliced = env_b.clone();
    spliced.truncate(ENVELOPE_AAD_LEN);
    spliced.extend_from_slice(&env_a[ENVELOPE_AAD_LEN..]);
    let result = Envelope::from_bytes(&spliced).and_then(|env| bob.open(&env));
    assert_eq!(result.unwrap_err(), Error::DecryptionFailed);
}

#[test]
fn wrong_recipient_gets_uniform_error() {
    let alice = HybridCrypto::generate().unwrap();
    let bob = HybridCrypto::generate().unwrap();
    let envelope = seal(b"for alice only", alice.public_keys()).unwrap();
    assert_eq!(bob.open(&envelope).unwrap_err(), Error::DecryptionFailed);
}

#[test]
fn truncation_and_extension_rejected() {
    let bob = HybridCrypto::generate().unwrap();
    let bytes = seal(b"msg", bob.public_keys()).unwrap().to_bytes();

    for len in [0, 3, HEADER_LEN, ENVELOPE_AAD_LEN, bytes.len() - 1] {
        assert!(
            Envelope::from_bytes(&bytes[..len]).is_err()
                || bob
                    .open(&Envelope::from_bytes(&bytes[..len]).unwrap())
                    .is_err(),
            "truncation to {len} accepted"
        );
    }

    // Appending data lands in the AEAD ciphertext and breaks the tag.
    let mut extended = bytes.clone();
    extended.push(0);
    let result = Envelope::from_bytes(&extended).and_then(|env| bob.open(&env));
    assert!(result.is_err());
}
