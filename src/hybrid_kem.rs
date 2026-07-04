//! Hybrid X25519 + ML-KEM-1024 key encapsulation.
//!
//! The shared secret is derived by hashing **both** component secrets and the
//! full public transcript with SHA3-256:
//!
//! ```text
//! ss = SHA3-256( label || ss_mlkem || ss_x25519
//!                || ct_mlkem || epk_x25519 || ek_mlkem || pk_x25519 )
//! ```
//!
//! This is the X-Wing construction (draft-connolly-cfrg-xwing-kem) ported to
//! ML-KEM-1024 with a distinct label, made more conservative by hashing the
//! full transcript (Chempat-style): both ciphertext components *and* both
//! recipient public keys enter the KDF, so the derivation does not rely on
//! any ML-KEM-specific binding property. Because every field is fixed-size,
//! plain concatenation is injective and needs no length framing.
//!
//! Security is the AND of the components: an attacker must break **both**
//! X25519 (classical) and ML-KEM-1024 (post-quantum) to recover `ss`. This
//! is also why no X25519 contributory-behavior check is needed: even if a
//! malicious peer forces a low-order `ss_x25519`, the ML-KEM secret and the
//! transcript still randomize the output.
//!
//! ML-KEM decapsulation never fails (implicit rejection): a tampered
//! ciphertext yields a uniformly random secret, surfacing only as an AEAD
//! authentication failure — one uniform error, no decryption oracle.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::keys::{KeyPair, PublicKeyBundle};
use ml_kem::kem::{Decapsulate as _, KeyExport as _};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// The public output of encapsulation, sent inside the envelope.
pub(crate) struct KemCiphertext {
    pub(crate) epk_x25519: [u8; X25519_PK_LEN],
    pub(crate) ct_mlkem: Box<[u8; MLKEM1024_CT_LEN]>,
}

/// Encapsulate to `recipient`, returning the KEM ciphertext and the combined
/// 32-byte shared secret.
pub(crate) fn encapsulate(
    recipient: &PublicKeyBundle,
) -> Result<(KemCiphertext, Zeroizing<[u8; 32]>)> {
    let mut eph_bytes = Zeroizing::new([0u8; X25519_SK_LEN]);
    getrandom::fill(eph_bytes.as_mut()).map_err(|_| Error::RandomnessUnavailable)?;
    let mut m = Zeroizing::new([0u8; 32]);
    getrandom::fill(m.as_mut()).map_err(|_| Error::RandomnessUnavailable)?;
    Ok(encapsulate_deterministic(recipient, *eph_bytes, &m))
}

/// The deterministic core of encapsulation: all randomness is supplied by
/// the caller. `eph_bytes` seeds the ephemeral X25519 secret; `m` is the
/// ML-KEM encapsulation randomness (FIPS 203 `m`). Only [`encapsulate`] and
/// known-answer tests may call this.
fn encapsulate_deterministic(
    recipient: &PublicKeyBundle,
    eph_bytes: [u8; X25519_SK_LEN],
    m: &[u8; 32],
) -> (KemCiphertext, Zeroizing<[u8; 32]>) {
    // StaticSecret rather than EphemeralSecret because the latter cannot be
    // built from caller-provided bytes; the secret still lives only for this
    // function call.
    let eph_sk = x25519_dalek::StaticSecret::from(eph_bytes);
    let epk = x25519_dalek::PublicKey::from(&eph_sk);
    let ss_x25519 = eph_sk.diffie_hellman(&recipient.x25519);

    let (ct_mlkem, ss_mlkem) = recipient.mlkem.encapsulate_deterministic(&(*m).into());

    let ct_mlkem_bytes: [u8; MLKEM1024_CT_LEN] = ct_mlkem.into();
    let ss = combine(
        &ss_mlkem,
        ss_x25519.as_bytes(),
        &ct_mlkem_bytes,
        epk.as_bytes(),
        recipient,
    );

    (
        KemCiphertext {
            epk_x25519: *epk.as_bytes(),
            ct_mlkem: Box::new(ct_mlkem_bytes),
        },
        ss,
    )
}

/// Decapsulate `ct` with our private keys, returning the combined secret.
pub(crate) fn decapsulate(keypair: &KeyPair, ct: &KemCiphertext) -> Zeroizing<[u8; 32]> {
    let epk = x25519_dalek::PublicKey::from(ct.epk_x25519);
    let ss_x25519 = keypair.x25519_sk.diffie_hellman(&epk);

    let ct_mlkem = ml_kem::ml_kem_1024::Ciphertext::from(*ct.ct_mlkem);
    let ss_mlkem = keypair.mlkem_dk.decapsulate(&ct_mlkem);

    combine(
        &ss_mlkem,
        ss_x25519.as_bytes(),
        ct.ct_mlkem.as_ref(),
        &ct.epk_x25519,
        keypair.public_keys(),
    )
}

/// The shared-secret combiner. See the module docs for the construction.
fn combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8; 32],
    ct_mlkem: &[u8; MLKEM1024_CT_LEN],
    epk_x25519: &[u8; X25519_PK_LEN],
    recipient: &PublicKeyBundle,
) -> Zeroizing<[u8; 32]> {
    debug_assert_eq!(ss_mlkem.len(), 32);
    let mut hasher = Sha3_256::new();
    hasher.update(KEM_COMBINER_LABEL);
    hasher.update(ss_mlkem);
    hasher.update(ss_x25519);
    hasher.update(ct_mlkem);
    hasher.update(epk_x25519);
    hasher.update(recipient.mlkem.to_bytes());
    hasher.update(recipient.x25519.as_bytes());
    Zeroizing::new(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encap_decap_agree() {
        let kp = KeyPair::generate().unwrap();
        let (ct, ss_sender) = encapsulate(kp.public_keys()).unwrap();
        let ss_recipient = decapsulate(&kp, &ct);
        assert_eq!(*ss_sender, *ss_recipient);
    }

    #[test]
    fn wrong_recipient_disagrees() {
        let alice = KeyPair::generate().unwrap();
        let mallory = KeyPair::generate().unwrap();
        let (ct, ss_sender) = encapsulate(alice.public_keys()).unwrap();
        let ss_mallory = decapsulate(&mallory, &ct);
        assert_ne!(*ss_sender, *ss_mallory);
    }

    #[test]
    fn tampered_mlkem_ciphertext_changes_secret() {
        let kp = KeyPair::generate().unwrap();
        let (mut ct, ss_sender) = encapsulate(kp.public_keys()).unwrap();
        ct.ct_mlkem[0] ^= 0x01;
        // Implicit rejection: decapsulation succeeds but yields a different key.
        let ss_recipient = decapsulate(&kp, &ct);
        assert_ne!(*ss_sender, *ss_recipient);
    }

    #[test]
    fn tampered_epk_changes_secret() {
        let kp = KeyPair::generate().unwrap();
        let (mut ct, ss_sender) = encapsulate(kp.public_keys()).unwrap();
        ct.epk_x25519[0] ^= 0x01;
        let ss_recipient = decapsulate(&kp, &ct);
        assert_ne!(*ss_sender, *ss_recipient);
    }

    /// Known-answer test: fixed seeds and fixed encapsulation randomness must
    /// produce this exact shared secret forever. Any change to the combiner,
    /// the label, the transcript ordering, or the underlying ML-KEM/X25519
    /// implementations will show up here.
    #[test]
    fn deterministic_kat() {
        use crate::keys::Seeds;

        let kp = KeyPair::from_seeds(Seeds {
            x25519_sk: [0x01; 32],
            mlkem_seed: [0x02; 64],
            ed25519_seed: [0x03; 32],
            mldsa_seed: [0x04; 32],
        });
        let (ct, ss) = encapsulate_deterministic(kp.public_keys(), [0x05; 32], &[0x06; 32]);

        // Deterministic: same inputs, same outputs.
        let (ct2, ss2) = encapsulate_deterministic(kp.public_keys(), [0x05; 32], &[0x06; 32]);
        assert_eq!(ct.epk_x25519, ct2.epk_x25519);
        assert_eq!(ct.ct_mlkem, ct2.ct_mlkem);
        assert_eq!(*ss, *ss2);

        // Decapsulation agrees.
        assert_eq!(*decapsulate(&kp, &ct), *ss);

        // Pinned values (update only on a deliberate, versioned format change).
        assert_eq!(
            hex::encode(*ss),
            "bf0314748b5e99e0c147a4ab1e51bbdea39798abcec5af015ca4f8689daa5556"
        );
        assert_eq!(
            hex::encode(ct.epk_x25519),
            "50a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495d"
        );
        assert_eq!(
            hex::encode(sha3::Sha3_256::digest(ct.ct_mlkem.as_ref())),
            "99a43f1aa309cf15a3109784e11bb28956c35aede3663811a66a4a24d3ebe771"
        );
    }

    /// The combiner must match its specification exactly: this pins the hash
    /// construction against an independent reimplementation.
    #[test]
    fn combiner_matches_spec() {
        let kp = KeyPair::generate().unwrap();
        let ss_mlkem = [0x11u8; 32];
        let ss_x25519 = [0x22u8; 32];
        let ct_mlkem = [0x33u8; MLKEM1024_CT_LEN];
        let epk = [0x44u8; X25519_PK_LEN];

        let got = combine(&ss_mlkem, &ss_x25519, &ct_mlkem, &epk, kp.public_keys());

        let mut manual = Vec::new();
        manual.extend_from_slice(b"quantum-shield/v2/kem:X25519+ML-KEM-1024\0");
        manual.extend_from_slice(&ss_mlkem);
        manual.extend_from_slice(&ss_x25519);
        manual.extend_from_slice(&ct_mlkem);
        manual.extend_from_slice(&epk);
        manual.extend_from_slice(
            &kp.public_keys().to_bytes()[HEADER_LEN + X25519_PK_LEN..][..MLKEM1024_EK_LEN],
        );
        manual.extend_from_slice(kp.public_keys().x25519.as_bytes());
        let expected: [u8; 32] = Sha3_256::digest(&manual).into();

        assert_eq!(*got, expected);
    }
}
