//! Deterministic stability / wiring KAT for ML-DSA-87.
//!
//! Full FIPS 204 ACVP conformance is exercised upstream in the `ml-dsa`
//! crate's own test suite. These vectors pin the behavior this crate depends
//! on — the correct parameter set (87), the FIPS-defined sizes, deterministic
//! signing, and a stable seed→key→sign→verify path — so a feature/version
//! change that silently altered any of those fails here.
//!
//! The pinned digests come from the exact `ml-dsa` version in the lockfile;
//! they are stability anchors, not externally sourced NIST vectors.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{EncodedSignature, MlDsa87, Signature, SigningKey};
use sha3::{Digest, Sha3_256};

const VK_LEN: usize = 2592;
const SIG_LEN: usize = 4627;

#[test]
fn mldsa87_deterministic_sign_verify() {
    let seed = [0x24u8; 32];
    let sk = SigningKey::<MlDsa87>::from_seed(&seed.into());
    let vk = sk.verifying_key();

    // FIPS 204 ML-DSA-87 sizes — guards against an accidental 44/65 downgrade.
    let vk_bytes = vk.encode();
    assert_eq!(vk_bytes.len(), VK_LEN, "ML-DSA-87 vk must be 2592 bytes");

    // Signing is deterministic: identical calls produce identical signatures.
    let msg = b"quantum-shield ml-dsa stability vector";
    let sig1: Signature<MlDsa87> = sk.sign(msg);
    let sig2: Signature<MlDsa87> = sk.sign(msg);
    let sig1_bytes: [u8; SIG_LEN] = sig1.encode().into();
    let sig2_bytes: [u8; SIG_LEN] = sig2.encode().into();
    assert_eq!(
        sig1_bytes, sig2_bytes,
        "ML-DSA signing must be deterministic"
    );

    // Verification accepts the signature.
    vk.verify(msg, &sig1).expect("valid signature must verify");

    // Stability anchors.
    assert_eq!(
        hex::encode(Sha3_256::digest(vk_bytes)),
        "a42e4d509e20a24638f01c1553033618733c1d8a85f8b3b9db5ad9be6dcaac19"
    );
    assert_eq!(
        hex::encode(Sha3_256::digest(sig1_bytes)),
        "7271b2347589b4279c441ec35c8c778f8a92b8d4d6f15b410e0a4cdbb4cbcdbf"
    );
}

#[test]
fn mldsa87_tampered_signature_rejected() {
    let sk = SigningKey::<MlDsa87>::from_seed(&[0x24u8; 32].into());
    let vk = sk.verifying_key();
    let msg = b"tamper target";
    let sig: Signature<MlDsa87> = sk.sign(msg);
    let mut sig_bytes: [u8; SIG_LEN] = sig.encode().into();
    sig_bytes[0] ^= 0x01;
    let encoded = EncodedSignature::<MlDsa87>::from(sig_bytes);
    // Either the tampered signature is rejected at decode, or it decodes but
    // fails verification — both are acceptable; silent acceptance is not.
    if let Some(bad) = Signature::<MlDsa87>::decode(&encoded) {
        assert!(vk.verify(msg, &bad).is_err());
    }
}
