//! Multi-recipient envelope tests, including the tamper suite that proves the
//! recipient set is bound into the payload authentication.

use quantum_shield::{
    seal_multi, Error, HybridCrypto, MultiRecipientEnvelope, CEK_COMMIT_LEN, HEADER_LEN,
    MAX_RECIPIENTS, WRAP_LEN,
};

fn recipients(n: usize) -> Vec<HybridCrypto> {
    (0..n).map(|_| HybridCrypto::generate().unwrap()).collect()
}

/// Byte offset of the first wrap: header + u16 count + CEK commitment.
const WRAPS_OFFSET: usize = HEADER_LEN + 2 + CEK_COMMIT_LEN;

#[test]
fn every_recipient_can_open() {
    let people = recipients(4);
    let pubs: Vec<_> = people.iter().map(|p| p.public_keys()).collect();
    let msg = b"one message, many recipients";
    let env = seal_multi(msg, &pubs).unwrap();
    assert_eq!(env.recipient_count(), 4);

    // Through the wire format.
    let bytes = env.to_bytes();
    let parsed = MultiRecipientEnvelope::from_bytes(&bytes).unwrap();
    for person in &people {
        assert_eq!(person.open_multi(&parsed).unwrap(), msg);
    }
}

#[test]
fn non_recipient_cannot_open() {
    let people = recipients(3);
    let pubs: Vec<_> = people.iter().map(|p| p.public_keys()).collect();
    let stranger = HybridCrypto::generate().unwrap();
    let env = seal_multi(b"secret", &pubs).unwrap();
    assert_eq!(
        stranger.open_multi(&env).unwrap_err(),
        Error::DecryptionFailed
    );
}

#[test]
fn single_recipient_works() {
    let bob = HybridCrypto::generate().unwrap();
    let env = seal_multi(b"just bob", &[bob.public_keys()]).unwrap();
    assert_eq!(bob.open_multi(&env).unwrap(), b"just bob");
}

#[test]
fn empty_and_oversized_recipient_lists_rejected() {
    let msg = b"x";
    assert_eq!(seal_multi(msg, &[]).unwrap_err(), Error::NoRecipients);
}

#[test]
fn reordering_wraps_fails() {
    let people = recipients(3);
    let pubs: Vec<_> = people.iter().map(|p| p.public_keys()).collect();
    let bytes = seal_multi(b"order matters", &pubs).unwrap().to_bytes();

    // Swap wrap 0 and wrap 1 (payload AAD binds all wraps in order).
    let base = WRAPS_OFFSET;
    let mut swapped = bytes.clone();
    let (a, b) = (base, base + WRAP_LEN);
    swapped[a..a + WRAP_LEN].copy_from_slice(&bytes[b..b + WRAP_LEN]);
    swapped[b..b + WRAP_LEN].copy_from_slice(&bytes[a..a + WRAP_LEN]);

    let env = MultiRecipientEnvelope::from_bytes(&swapped).unwrap();
    for person in &people {
        assert_eq!(
            person.open_multi(&env).unwrap_err(),
            Error::DecryptionFailed
        );
    }
}

#[test]
fn dropping_a_wrap_fails() {
    let people = recipients(3);
    let pubs: Vec<_> = people.iter().map(|p| p.public_keys()).collect();
    let bytes = seal_multi(b"complete set", &pubs).unwrap().to_bytes();

    // Remove the last wrap and decrement the count: the wrap AAD (which binds
    // the count) changes, so the remaining recipients' wraps no longer yield
    // the CEK.
    let base = WRAPS_OFFSET;
    let mut tampered = Vec::new();
    tampered.extend_from_slice(&bytes[..HEADER_LEN]);
    tampered.extend_from_slice(&2u16.to_be_bytes()); // count 3 -> 2
    tampered.extend_from_slice(&bytes[HEADER_LEN + 2..base]); // CEK commitment
    tampered.extend_from_slice(&bytes[base..base + 2 * WRAP_LEN]); // first two wraps
    tampered.extend_from_slice(&bytes[base + 3 * WRAP_LEN..]); // nonce + payload
    let env = MultiRecipientEnvelope::from_bytes(&tampered).unwrap();
    assert_eq!(env.recipient_count(), 2);
    for person in &people {
        assert!(person.open_multi(&env).is_err());
    }
}

#[test]
fn duplicating_a_wrap_fails() {
    let people = recipients(2);
    let pubs: Vec<_> = people.iter().map(|p| p.public_keys()).collect();
    let bytes = seal_multi(b"no dupes", &pubs).unwrap().to_bytes();

    // Duplicate wrap 0 into a third slot and bump the count to 3.
    let base = WRAPS_OFFSET;
    let wrap0 = &bytes[base..base + WRAP_LEN];
    let mut tampered = Vec::new();
    tampered.extend_from_slice(&bytes[..HEADER_LEN]);
    tampered.extend_from_slice(&3u16.to_be_bytes());
    tampered.extend_from_slice(&bytes[HEADER_LEN + 2..base]); // CEK commitment
    tampered.extend_from_slice(&bytes[base..base + 2 * WRAP_LEN]);
    tampered.extend_from_slice(wrap0);
    tampered.extend_from_slice(&bytes[base + 2 * WRAP_LEN..]);
    let env = MultiRecipientEnvelope::from_bytes(&tampered).unwrap();
    for person in &people {
        assert!(person.open_multi(&env).is_err());
    }
}

#[test]
fn count_mismatch_rejected_at_parse() {
    let people = recipients(2);
    let pubs: Vec<_> = people.iter().map(|p| p.public_keys()).collect();
    let bytes = seal_multi(b"x", &pubs).unwrap().to_bytes();

    // Claim 3 recipients but supply 2 wraps: parse runs out of bytes.
    let mut lying = bytes.clone();
    lying[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&3u16.to_be_bytes());
    assert!(MultiRecipientEnvelope::from_bytes(&lying).is_err());
}

#[test]
fn zero_count_rejected() {
    let people = recipients(1);
    let pubs: Vec<_> = people.iter().map(|p| p.public_keys()).collect();
    let bytes = seal_multi(b"x", &pubs).unwrap().to_bytes();
    let mut zero = bytes.clone();
    zero[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        MultiRecipientEnvelope::from_bytes(&zero).unwrap_err(),
        Error::NoRecipients
    );
}

#[test]
fn too_many_recipients_rejected_at_parse() {
    let people = recipients(1);
    let pubs: Vec<_> = people.iter().map(|p| p.public_keys()).collect();
    let bytes = seal_multi(b"x", &pubs).unwrap().to_bytes();
    let mut huge = bytes.clone();
    huge[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&((MAX_RECIPIENTS + 1) as u16).to_be_bytes());
    assert!(matches!(
        MultiRecipientEnvelope::from_bytes(&huge).unwrap_err(),
        Error::TooManyRecipients { .. }
    ));
}

#[test]
fn empty_plaintext_roundtrips() {
    let bob = HybridCrypto::generate().unwrap();
    let env = seal_multi(b"", &[bob.public_keys()]).unwrap();
    assert_eq!(bob.open_multi(&env).unwrap(), b"");
}

#[test]
fn corrupting_the_cek_commitment_fails() {
    // The commitment is bound into the payload AAD and explicitly checked, so
    // tampering it must fail the open. This is the mechanism that prevents a
    // malicious sender from wrapping different CEKs to different recipients.
    let bob = HybridCrypto::generate().unwrap();
    let mut bytes = seal_multi(b"committed", &[bob.public_keys()])
        .unwrap()
        .to_bytes();
    bytes[HEADER_LEN + 2] ^= 0x01; // first byte of the CEK commitment
    let env = MultiRecipientEnvelope::from_bytes(&bytes).unwrap();
    assert_eq!(bob.open_multi(&env).unwrap_err(), Error::DecryptionFailed);
}
