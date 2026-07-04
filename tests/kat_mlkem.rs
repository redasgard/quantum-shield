//! Deterministic stability / wiring KAT for ML-KEM-1024.
//!
//! Full FIPS 203 ACVP conformance is exercised upstream in the `ml-kem`
//! crate's own test suite. The purpose of *these* vectors is to pin the exact
//! behavior this crate depends on — the correct parameter set (1024, not 768),
//! the FIPS-defined sizes, and a stable seed→key→encaps→decaps path — so a
//! feature/version change that silently altered any of those fails here.
//!
//! The pinned digests are produced by the exact `ml-kem` version in the
//! lockfile; they are stability anchors, not externally sourced NIST vectors.

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024};
use sha3::{Digest, Sha3_256};

const EK_LEN: usize = 1568;
const CT_LEN: usize = 1568;

#[test]
fn mlkem1024_deterministic_encaps_decaps() {
    let seed = [0x42u8; 64];
    let dk = DecapsulationKey1024::from_seed(seed.into());
    let ek: &EncapsulationKey1024 = dk.encapsulation_key();

    // FIPS 203 ML-KEM-1024 sizes — guards against an accidental 768 downgrade.
    let ek_bytes = ek.to_bytes();
    assert_eq!(ek_bytes.len(), EK_LEN, "ML-KEM-1024 ek must be 1568 bytes");

    // Deterministic encapsulation with fixed randomness m.
    let m = [0x17u8; 32];
    let (ct, ss_enc) = ek.encapsulate_deterministic(&m.into());
    let ct_bytes: [u8; CT_LEN] = ct.into();

    // Decapsulation recovers the same shared key (ML-KEM decaps is infallible).
    let ss_dec = dk.decapsulate(&ct_bytes.into());
    assert_eq!(ss_enc, ss_dec, "encaps/decaps shared keys must agree");

    // Stability anchors: any change to the derivation shifts these.
    assert_eq!(
        hex::encode(Sha3_256::digest(ek_bytes)),
        "e60f89059cd63c1228bfbed9a91dc42b3207d57747692782b747b893aea730bb"
    );
    assert_eq!(
        hex::encode(Sha3_256::digest(ct_bytes)),
        "ee975518d87795c32cbc7f7c60825038cdf35a0e37b12141a1b775b106037c18"
    );
    assert_eq!(
        hex::encode(ss_enc),
        "c1ede42fa5562ac32b4fd4b61c7f4fc59fab8dc8ba99b0344e16b0c2bb903e14"
    );
}

#[test]
fn mlkem1024_tampered_ciphertext_implicit_rejection() {
    let seed = [0x42u8; 64];
    let dk = DecapsulationKey1024::from_seed(seed.into());
    let ek = dk.encapsulation_key();
    let (ct, ss) = ek.encapsulate_deterministic(&[0x17u8; 32].into());
    let mut ct_bytes: [u8; CT_LEN] = ct.into();
    ct_bytes[0] ^= 0x01;
    // Implicit rejection: decaps never errors, but returns a different key.
    let ss_bad = dk.decapsulate(&ct_bytes.into());
    assert_ne!(ss, ss_bad);
}
