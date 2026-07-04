//! Hybrid signatures: Ed25519 + ML-DSA-87, both mandatory.
//!
//! Both algorithms sign the same *framed* message in pure (non-prehashed)
//! mode:
//!
//! ```text
//! M' = label || u8(context.len()) || context || message
//! ```
//!
//! The label provides domain separation from any other use of the same keys;
//! the length-prefixed application context (0–255 bytes, mirroring the
//! FIPS 204 context-string limit) makes the (context, message) encoding
//! injective. Verification requires **both** signatures to be valid, so a
//! future break of either algorithm alone does not enable forgery.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::keys::{KeyPair, PublicKeyBundle};
use crate::types::HybridSignature;
use alloc::boxed::Box;
use alloc::vec::Vec;
use ed25519_dalek::Signer as _;
use ml_dsa::signature::{Signer as _, Verifier as _};
use ml_dsa::MlDsa87;

/// Build the framed message `M'`. Fails if `context` exceeds 255 bytes.
fn frame(message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(Error::ContextTooLong);
    }
    let mut framed = Vec::with_capacity(SIG_DOMAIN_LABEL.len() + 1 + context.len() + message.len());
    framed.extend_from_slice(SIG_DOMAIN_LABEL);
    framed.push(context.len() as u8);
    framed.extend_from_slice(context);
    framed.extend_from_slice(message);
    Ok(framed)
}

/// Sign `message` under `context` with both algorithms.
pub(crate) fn sign(keypair: &KeyPair, message: &[u8], context: &[u8]) -> Result<HybridSignature> {
    let framed = frame(message, context)?;

    let ed_sig = keypair.ed25519_sk.sign(&framed);
    let pq_sig: ml_dsa::Signature<MlDsa87> = keypair.mldsa_sk.sign(&framed);

    Ok(HybridSignature {
        ed25519: ed_sig.to_bytes(),
        mldsa: Box::new(pq_sig.encode().into()),
    })
}

/// Verify a [`HybridSignature`]. Both components must be valid.
pub(crate) fn verify(
    message: &[u8],
    context: &[u8],
    signature: &HybridSignature,
    signer: &PublicKeyBundle,
) -> Result<()> {
    let framed = frame(message, context)?;

    // Evaluate both components unconditionally (no short-circuit), then
    // combine, so the two layers are always enforced symmetrically.
    let ed_sig = ed25519_dalek::Signature::from_bytes(&signature.ed25519);
    let ed_ok = signer.ed25519.verify_strict(&framed, &ed_sig).is_ok();

    let pq_ok = match ml_dsa::Signature::<MlDsa87>::decode(signature.mldsa.as_ref().into()) {
        Some(pq_sig) => signer.mldsa.verify(&framed, &pq_sig).is_ok(),
        None => false,
    };

    if ed_ok & pq_ok {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let sig = sign(&kp, b"message", b"ctx").unwrap();
        verify(b"message", b"ctx", &sig, kp.public_keys()).unwrap();
    }

    #[test]
    fn tampered_message_fails() {
        let kp = KeyPair::generate().unwrap();
        let sig = sign(&kp, b"message", b"").unwrap();
        assert_eq!(
            verify(b"messagE", b"", &sig, kp.public_keys()).unwrap_err(),
            Error::VerificationFailed
        );
    }

    #[test]
    fn context_mismatch_fails() {
        let kp = KeyPair::generate().unwrap();
        let sig = sign(&kp, b"message", b"context-a").unwrap();
        assert_eq!(
            verify(b"message", b"context-b", &sig, kp.public_keys()).unwrap_err(),
            Error::VerificationFailed
        );
    }

    #[test]
    fn context_message_boundary_is_unambiguous() {
        let kp = KeyPair::generate().unwrap();
        // Same concatenation, different (ctx, msg) split: must not cross-verify.
        let sig = sign(&kp, b"bc", b"a").unwrap();
        assert!(verify(b"c", b"ab", &sig, kp.public_keys()).is_err());
        assert!(verify(b"abc", b"", &sig, kp.public_keys()).is_err());
    }

    #[test]
    fn tampering_either_component_fails() {
        let kp = KeyPair::generate().unwrap();
        let sig = sign(&kp, b"message", b"").unwrap();

        // Corrupt only the Ed25519 half.
        let mut bad_ed = sig.clone();
        bad_ed.ed25519[0] ^= 1;
        assert!(verify(b"message", b"", &bad_ed, kp.public_keys()).is_err());

        // Corrupt only the ML-DSA half.
        let mut bad_pq = sig.clone();
        bad_pq.mldsa[0] ^= 1;
        assert!(verify(b"message", b"", &bad_pq, kp.public_keys()).is_err());

        // Zero out the ML-DSA half entirely (the v1 "stripping" attack shape).
        let mut stripped = sig.clone();
        stripped.mldsa.fill(0);
        assert!(verify(b"message", b"", &stripped, kp.public_keys()).is_err());
    }

    #[test]
    fn wrong_signer_fails() {
        let alice = KeyPair::generate().unwrap();
        let mallory = KeyPair::generate().unwrap();
        let sig = sign(&alice, b"message", b"").unwrap();
        assert!(verify(b"message", b"", &sig, mallory.public_keys()).is_err());
    }

    #[test]
    fn long_context_rejected() {
        let kp = KeyPair::generate().unwrap();
        let ctx = [0u8; MAX_CONTEXT_LEN + 1];
        assert_eq!(sign(&kp, b"m", &ctx).unwrap_err(), Error::ContextTooLong);
    }

    #[test]
    fn max_context_accepted() {
        let kp = KeyPair::generate().unwrap();
        let ctx = [7u8; MAX_CONTEXT_LEN];
        let sig = sign(&kp, b"m", &ctx).unwrap();
        verify(b"m", &ctx, &sig, kp.public_keys()).unwrap();
    }
}
