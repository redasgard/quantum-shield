//! Cryptographic operation benchmarks.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quantum_shield::{seal, verify, HybridCrypto};

fn bench_generate(c: &mut Criterion) {
    c.bench_function("generate_keypair", |b| {
        b.iter(HybridCrypto::generate);
    });
}

fn bench_seal_open(c: &mut Criterion) {
    let recipient = HybridCrypto::generate().unwrap();
    let mut group = c.benchmark_group("seal_open");
    for size in [1024usize, 1024 * 1024, 16 * 1024 * 1024] {
        let msg = vec![0x5Au8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("seal", size), &msg, |b, msg| {
            b.iter(|| seal(msg, recipient.public_keys()).unwrap());
        });
        let envelope = seal(&msg, recipient.public_keys()).unwrap();
        group.bench_with_input(BenchmarkId::new("open", size), &envelope, |b, env| {
            b.iter(|| recipient.open(env).unwrap());
        });
    }
    group.finish();
}

fn bench_sign_verify(c: &mut Criterion) {
    let signer = HybridCrypto::generate().unwrap();
    let msg = b"benchmark message for hybrid signing";
    c.bench_function("sign", |b| {
        b.iter(|| signer.sign(msg, b"bench").unwrap());
    });
    let sig = signer.sign(msg, b"bench").unwrap();
    c.bench_function("verify", |b| {
        b.iter(|| verify(msg, b"bench", &sig, signer.public_keys()).unwrap());
    });
}

criterion_group!(benches, bench_generate, bench_seal_open, bench_sign_verify);
criterion_main!(benches);
