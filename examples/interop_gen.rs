//! Emit one of every quantum-shield v2 artifact into a directory, for the
//! independent Python implementation in `ci/interop/cleanroom.py`.
//!
//! `cargo run --example interop_gen -- <out-dir>`
use quantum_shield::{seal_multi, HybridCrypto, StreamSealer};
fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: interop_gen <out-dir>");
    let alice = HybridCrypto::generate().unwrap();
    let bob = HybridCrypto::generate().unwrap();
    let pt = b"independent interop check: the quick brown fox".to_vec();
    let env = alice.seal_for(&pt, bob.public_keys()).unwrap().to_bytes();
    let sig = alice
        .sign(b"signed message body", b"ctx-123")
        .unwrap()
        .to_bytes();
    let w = |n: &str, b: &[u8]| std::fs::write(format!("{out}/{n}"), b).unwrap();
    w("bob.qsk", &bob.to_secret_bytes());
    w("alice.qsk", &alice.to_secret_bytes());
    w("bob.qsp", &bob.public_keys().to_bytes());
    w("alice.qsp", &alice.public_keys().to_bytes());
    w("envelope.qse", &env);
    w("plaintext", &pt);
    w("sig.qss", &sig);
    // QSM2: carol, bob, dave — bob in the middle so trial-decryption must skip a wrap
    let carol = HybridCrypto::generate().unwrap();
    let dave = HybridCrypto::generate().unwrap();
    let m = seal_multi(
        b"multi-recipient payload",
        &[carol.public_keys(), bob.public_keys(), dave.public_keys()],
    )
    .unwrap();
    w("multi.qsm", &m.to_bytes());
    // QST2: three chunks of unequal size
    let (mut s, hdr) = StreamSealer::new(bob.public_keys()).unwrap();
    let mut frames = Vec::new();
    for (i, c) in [&b"chunk-zero "[..], b"chunk-one-is-longer ", b"last"]
        .iter()
        .enumerate()
    {
        frames.extend(s.seal_chunk(c, i == 2).unwrap());
    }
    w("stream.hdr", &hdr);
    w("stream.frames", &frames);
    // QSR2: alice attests bob as successor at epoch 7
    w(
        "rotation.qsr",
        &alice
            .attest_rotation(bob.public_keys(), 7)
            .unwrap()
            .to_bytes(),
    );
}
