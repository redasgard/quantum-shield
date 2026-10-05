//! NIST ACVP known-answer tests for the post-quantum components, using the
//! official ACVP-Server vectors (subset in `tests/data/acvp/`, source URL in
//! each file). Unlike `kat_mlkem.rs`/`kat_mldsa.rs`, which pin this crate's own
//! output, these are external vectors a wrong implementation cannot pass.
//!
//! Besides exercising the upstream `ml-kem`/`ml-dsa` versions this crate
//! locks, `qsk2_seed_import_matches_nist_keygen` feeds NIST's keyGen seeds
//! through quantum-shield's own `QSK2` importer, so the crate's seed layout and
//! key derivation are checked end to end.
//!
//! The vector files are excluded from the published package (2.4 MiB); this
//! test runs from the repository.
#![allow(deprecated)] // expanded-key APIs are deprecated upstream but are what ACVP uses

use ml_dsa::{
    ExpandedSigningKey, KeyExport as _, Keypair as _, MlDsa87, Signature, SigningKey, VerifyingKey,
};
use ml_kem::kem::Decapsulate as _;
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, ExpandedKeyEncoding as _, Seed, B32};
use quantum_shield::{KeyPair, PublicKeyBundle, HEADER_LEN, MLKEM1024_EK_LEN, X25519_PK_LEN};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/tests/data/acvp/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn hx(tc: &Value, field: &str) -> Vec<u8> {
    hex::decode(tc[field].as_str().unwrap()).unwrap()
}
/// All test cases of the groups matching `pred`, with their group.
fn cases(v: &Value, pred: impl Fn(&Value) -> bool) -> Vec<(Value, Value)> {
    let mut out = vec![];
    for g in v["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| pred(g))
    {
        for tc in g["tests"].as_array().unwrap() {
            out.push((g.clone(), tc.clone()));
        }
    }
    assert!(!out.is_empty(), "no ACVP cases selected");
    out
}

#[test]
fn mlkem1024_keygen() {
    for (_, tc) in cases(&load("ML-KEM-keyGen-FIPS203"), |_| true) {
        let seed = [hx(&tc, "d"), hx(&tc, "z")].concat();
        let dk = DecapsulationKey1024::from_seed(Seed::try_from(&seed[..]).unwrap());
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            hx(&tc, "ek"),
            "tcId {}",
            tc["tcId"]
        );
        assert_eq!(
            dk.to_expanded_bytes().as_slice(),
            hx(&tc, "dk"),
            "tcId {}",
            tc["tcId"]
        );
    }
}

#[test]
fn mlkem1024_encap_decap_and_key_checks() {
    let template = KeyPair::generate().unwrap().public_keys().to_bytes();
    let ek_at = HEADER_LEN + X25519_PK_LEN;
    for (g, tc) in cases(&load("ML-KEM-encapDecap-FIPS203"), |_| true) {
        let id = &tc["tcId"];
        match g["function"].as_str().unwrap() {
            "encapsulation" => {
                // The exact upstream call quantum-shield makes, with NIST's `m`.
                let ek = EncapsulationKey1024::new(hx(&tc, "ek")[..].try_into().unwrap()).unwrap();
                let (c, k) =
                    ek.encapsulate_deterministic(&B32::try_from(&hx(&tc, "m")[..]).unwrap());
                assert_eq!(c.as_slice(), hx(&tc, "c"), "tcId {id}");
                assert_eq!(k.as_slice(), hx(&tc, "k"), "tcId {id}");
            }
            "decapsulation" => {
                // Includes modified ciphertexts: checks implicit rejection.
                let dk = DecapsulationKey1024::from_expanded(hx(&tc, "dk")[..].try_into().unwrap())
                    .unwrap();
                let k = dk.decapsulate(hx(&tc, "c")[..].try_into().unwrap());
                assert_eq!(k.as_slice(), hx(&tc, "k"), "tcId {id}");
            }
            "encapsulationKeyCheck" => {
                // FIPS 203 §7.2: quantum-shield's bundle parser must agree.
                let expected = tc["testPassed"].as_bool().unwrap();
                let ek = hx(&tc, "ek");
                let accepted = ek.len() == MLKEM1024_EK_LEN && {
                    let mut b = template.clone();
                    b[ek_at..ek_at + MLKEM1024_EK_LEN].copy_from_slice(&ek);
                    PublicKeyBundle::from_bytes(&b).is_ok()
                };
                assert_eq!(accepted, expected, "tcId {id}");
            }
            "decapsulationKeyCheck" => {
                let expected = tc["testPassed"].as_bool().unwrap();
                let dk = hx(&tc, "dk");
                let accepted = dk.len() == 3168
                    && DecapsulationKey1024::from_expanded(dk[..].try_into().unwrap()).is_ok();
                assert_eq!(accepted, expected, "tcId {id}");
            }
            other => panic!("unexpected ACVP function {other}"),
        }
    }
}

#[test]
fn mldsa87_keygen() {
    for (_, tc) in cases(&load("ML-DSA-keyGen-FIPS204"), |_| true) {
        let sk = SigningKey::<MlDsa87>::from_seed(&B32::try_from(&hx(&tc, "seed")[..]).unwrap());
        assert_eq!(
            sk.verifying_key().encode().as_slice(),
            hx(&tc, "pk"),
            "tcId {}",
            tc["tcId"]
        );
        assert_eq!(
            sk.expanded_key().to_expanded().as_slice(),
            hx(&tc, "sk"),
            "tcId {}",
            tc["tcId"]
        );
    }
}

#[test]
fn mldsa87_siggen_pure() {
    for (g, tc) in cases(&load("ML-DSA-sigGen-FIPS204"), |_| true) {
        let esk =
            ExpandedSigningKey::<MlDsa87>::from_expanded(hx(&tc, "sk")[..].try_into().unwrap());
        let (msg, ctx) = (hx(&tc, "message"), hx(&tc, "context"));
        let sig = if g["deterministic"].as_bool().unwrap() {
            esk.sign_deterministic(&msg, &ctx).unwrap()
        } else {
            // FIPS 204 Algorithm 2 with caller-supplied rnd: M' = 0 || |ctx| || ctx || M.
            let rnd = B32::try_from(&hx(&tc, "rnd")[..]).unwrap();
            esk.sign_internal(&[&[0, ctx.len() as u8], &ctx, &msg], &rnd)
        };
        assert_eq!(
            sig.encode().as_slice(),
            hx(&tc, "signature"),
            "tcId {}",
            tc["tcId"]
        );
    }
}

#[test]
fn mldsa87_sigver_pure() {
    for (_, tc) in cases(&load("ML-DSA-sigVer-FIPS204"), |_| true) {
        let vk = VerifyingKey::<MlDsa87>::decode(hx(&tc, "pk")[..].try_into().unwrap());
        let ok = Signature::<MlDsa87>::try_from(&hx(&tc, "signature")[..])
            .map(|sig| vk.verify_with_context(&hx(&tc, "message"), &hx(&tc, "context"), &sig))
            .unwrap_or(false);
        assert_eq!(
            ok,
            tc["testPassed"].as_bool().unwrap(),
            "tcId {}",
            tc["tcId"]
        );
    }
}

#[test]
fn qsk2_seed_import_matches_nist_keygen() {
    let kem = cases(&load("ML-KEM-keyGen-FIPS203"), |_| true);
    let dsa = cases(&load("ML-DSA-keyGen-FIPS204"), |_| true);
    let vk_at = HEADER_LEN + X25519_PK_LEN + MLKEM1024_EK_LEN + 32;
    for ((_, k), (_, d)) in kem.iter().zip(&dsa) {
        // QSK2 = header || x25519_sk || d || z || ed25519_seed || xi
        let mut qsk = b"QSK2\x02\x01".to_vec();
        qsk.extend([0x11; 32]);
        qsk.extend(hx(k, "d"));
        qsk.extend(hx(k, "z"));
        qsk.extend([0x22; 32]);
        qsk.extend(hx(d, "seed"));
        let public = KeyPair::from_secret_bytes(&qsk)
            .unwrap()
            .public_keys()
            .to_bytes();
        let ek_at = HEADER_LEN + X25519_PK_LEN;
        assert_eq!(
            &public[ek_at..ek_at + MLKEM1024_EK_LEN],
            &hx(k, "ek")[..],
            "ML-KEM tcId {}",
            k["tcId"]
        );
        assert_eq!(
            &public[vk_at..],
            &hx(d, "pk")[..],
            "ML-DSA tcId {}",
            d["tcId"]
        );
    }
}
