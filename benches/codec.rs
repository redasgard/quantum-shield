//! Wire-format serialization/parsing benchmarks.

use criterion::{criterion_group, criterion_main, Criterion};
use quantum_shield::{seal, Envelope, HybridCrypto, HybridSignature, PublicKeyBundle};

fn bench_codec(c: &mut Criterion) {
    let kp = HybridCrypto::generate().unwrap();

    let envelope = seal(b"codec benchmark payload", kp.public_keys()).unwrap();
    let env_bytes = envelope.to_bytes();
    c.bench_function("envelope_to_bytes", |b| b.iter(|| envelope.to_bytes()));
    c.bench_function("envelope_from_bytes", |b| {
        b.iter(|| Envelope::from_bytes(&env_bytes).unwrap());
    });

    let sig = kp.sign(b"msg", b"").unwrap();
    let sig_bytes = sig.to_bytes();
    c.bench_function("signature_to_bytes", |b| b.iter(|| sig.to_bytes()));
    c.bench_function("signature_from_bytes", |b| {
        b.iter(|| HybridSignature::from_bytes(&sig_bytes).unwrap());
    });

    let pub_bytes = kp.public_keys().to_bytes();
    c.bench_function("public_bundle_to_bytes", |b| {
        b.iter(|| kp.public_keys().to_bytes());
    });
    c.bench_function("public_bundle_from_bytes", |b| {
        b.iter(|| PublicKeyBundle::from_bytes(&pub_bytes).unwrap());
    });

    let secret = kp.to_secret_bytes();
    c.bench_function("secret_from_bytes", |b| {
        b.iter(|| HybridCrypto::from_secret_bytes(&secret).unwrap());
    });
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
