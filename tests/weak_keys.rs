//! Public-key bundles carrying degenerate component keys are rejected at parse
//! time.

use hex_literal::hex;
use quantum_shield::{Error, HybridCrypto, PublicKeyBundle, HEADER_LEN};

const X25519_AT: usize = HEADER_LEN;
const ED25519_AT: usize = HEADER_LEN + 32 + 1568;

fn bundle_with(at: usize, key: &[u8; 32]) -> Vec<u8> {
    let mut b = HybridCrypto::generate().unwrap().public_keys().to_bytes();
    b[at..at + 32].copy_from_slice(key);
    b
}

#[test]
fn valid_bundle_still_parses() {
    let b = HybridCrypto::generate().unwrap().public_keys().to_bytes();
    assert!(PublicKeyBundle::from_bytes(&b).is_ok());
}

#[test]
fn low_order_x25519_rejected() {
    // The X25519 low-order points (and their non-canonical twins), from the
    // well-known list used by libsodium's `has_small_order` check.
    let low_order: [[u8; 32]; 7] = [
        [0; 32],
        hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        hex!("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex!("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ];
    for pk in &low_order {
        assert_eq!(
            PublicKeyBundle::from_bytes(&bundle_with(X25519_AT, pk)).unwrap_err(),
            Error::InvalidKey,
            "accepted low-order X25519 key {}",
            hex::encode(pk)
        );
    }
}

#[test]
fn non_canonical_ed25519_rejected() {
    // y-coordinates p..p+18 encoded without reduction, both sign bits. Several
    // of these decompress (dalek reduces y mod p), so canonicity must be
    // enforced explicitly.
    for k in 0u8..19 {
        for sign in [0u8, 0x80] {
            let mut y = [0xff; 32];
            y[0] = 0xed + k;
            y[31] = 0x7f | sign;
            assert!(
                PublicKeyBundle::from_bytes(&bundle_with(ED25519_AT, &y)).is_err(),
                "accepted non-canonical Ed25519 key y=p+{k} sign={sign}"
            );
        }
    }
}

#[test]
fn small_order_ed25519_rejected() {
    // The identity (y = 1) and the order-2 point (y = -1), canonically encoded.
    let identity = hex!("0100000000000000000000000000000000000000000000000000000000000000");
    let order2 = hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    for pk in [&identity, &order2] {
        assert!(PublicKeyBundle::from_bytes(&bundle_with(ED25519_AT, pk)).is_err());
    }
}
