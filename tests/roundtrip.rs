//! End-to-end roundtrip tests over the serialized wire formats.

use quantum_shield::{seal, verify, Envelope, HybridCrypto, HybridSignature, PublicKeyBundle};

#[test]
fn seal_open_various_sizes() {
    let bob = HybridCrypto::generate().unwrap();
    // Recipient parses their own public bundle from bytes, like a real peer.
    let bob_pub = PublicKeyBundle::from_bytes(&bob.public_keys().to_bytes()).unwrap();

    for size in [0usize, 1, 12, 4096, 1024 * 1024] {
        let msg: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let envelope = seal(&msg, &bob_pub).unwrap();

        // Through the wire format.
        let bytes = envelope.to_bytes();
        let parsed = Envelope::from_bytes(&bytes).unwrap();
        let plaintext = bob.open(&parsed).unwrap();
        assert_eq!(plaintext, msg, "size={size}");
    }
}

#[test]
fn envelope_size_matches_documented_overhead() {
    let bob = HybridCrypto::generate().unwrap();
    let msg = vec![7u8; 1000];
    let envelope = seal(&msg, bob.public_keys()).unwrap();
    assert_eq!(
        envelope.to_bytes().len(),
        msg.len() + quantum_shield::ENVELOPE_OVERHEAD
    );
}

#[test]
fn sign_verify_through_wire_format() {
    let alice = HybridCrypto::generate().unwrap();
    let alice_pub = PublicKeyBundle::from_bytes(&alice.public_keys().to_bytes()).unwrap();

    for ctx in [&b""[..], &[0xABu8; 255][..]] {
        let sig = alice.sign(b"message", ctx).unwrap();
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), quantum_shield::SIGNATURE_LEN);
        let parsed = HybridSignature::from_bytes(&bytes).unwrap();
        verify(b"message", ctx, &parsed, &alice_pub).unwrap();
    }
}

#[test]
fn secret_export_reimport_interoperates() {
    let alice = HybridCrypto::generate().unwrap();
    let bob = HybridCrypto::generate().unwrap();

    // Bob persists and restores his keypair.
    let bob_restored = HybridCrypto::from_secret_bytes(&bob.to_secret_bytes()).unwrap();
    assert_eq!(bob_restored.public_keys(), bob.public_keys());

    // A message sealed to the original opens with the restored keypair.
    let envelope = alice.seal_for(b"persisted", bob.public_keys()).unwrap();
    assert_eq!(bob_restored.open(&envelope).unwrap(), b"persisted");

    // Signatures from the restored keypair verify against the original bundle.
    let sig = bob_restored.sign(b"still me", b"").unwrap();
    verify(b"still me", b"", &sig, bob.public_keys()).unwrap();
}
