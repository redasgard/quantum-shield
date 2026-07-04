//! Compile-only proof that `quantum-shield` builds for a bare-metal
//! `no_std` + `alloc` target (`thumbv7em-none-eabi`) with a user-supplied
//! randomness backend and no operating system.
//!
//! This is not run; `cargo check` for the configured target is the gate.

#![no_std]

extern crate alloc;

use getrandom::Error;
use quantum_shield::{seal, verify, Envelope, HybridCrypto, HybridSignature, PublicKeyBundle};

/// getrandom's custom backend hook. On a real device this would read a TRNG;
/// here it only needs to link. `getrandom_backend="custom"` (set in
/// `.cargo/config.toml`) routes all randomness through this function.
///
/// # Safety
/// `dest` points to `len` writable bytes; we fully initialize them.
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), Error> {
    // Deterministic filler — sufficient to compile and link; NOT secure.
    let mut i = 0usize;
    while i < len {
        *dest.add(i) = (i as u8) ^ 0xA5;
        i += 1;
    }
    Ok(())
}

/// Reference every public entry point so the whole crate is type-checked and
/// monomorphized for the bare-metal target.
pub fn exercise_api() -> Result<(), quantum_shield::Error> {
    let alice = HybridCrypto::generate()?;
    let bob = HybridCrypto::generate()?;

    let envelope = seal(b"no_std", bob.public_keys())?;
    let wire = envelope.to_bytes();
    let parsed = Envelope::from_bytes(&wire)?;
    let _plaintext = bob.open(&parsed)?;

    let sig = alice.sign(b"msg", b"ctx")?;
    let sig_bytes = sig.to_bytes();
    let sig2 = HybridSignature::from_bytes(&sig_bytes)?;
    verify(b"msg", b"ctx", &sig2, alice.public_keys())?;

    let pub_bytes = alice.public_keys().to_bytes();
    let _pk = PublicKeyBundle::from_bytes(&pub_bytes)?;

    let secret = alice.to_secret_bytes();
    let _restored = HybridCrypto::from_secret_bytes(&secret)?;
    Ok(())
}
