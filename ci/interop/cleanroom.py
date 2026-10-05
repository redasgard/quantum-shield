"""Independent implementation of the quantum-shield v2 formats, written from
docs/design.md only. It shares no code with the crate: X25519, Ed25519 and
AES-256-GCM come from pyca/cryptography (OpenSSL), SHA3 from hashlib, and
ML-KEM / ML-DSA from the pure-Python FIPS 203/204 references kyber-py and
dilithium-py.

Usage: cargo run --example interop_gen -- DIR && python cleanroom.py DIR
Exits non-zero if any check fails.
"""
import hashlib, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kyber_py.ml_kem import ML_KEM_1024
from dilithium_py.ml_dsa import ML_DSA_87
A = sys.argv[1]; rd = lambda n: open(f"{A}/{n}", "rb").read()
raw = lambda k: k.public_bytes(Encoding.Raw, PublicFormat.Raw)
results = []
def check(name, ok): results.append((name, ok)); print(("PASS " if ok else "FAIL ") + name)

def header(b, magic):
    check(f"{magic} header = magic||0x02||0x01", b[:6] == magic.encode() + b"\x02\x01"); return b[6:]

# QSK2: header || x25519_sk[32] || mlkem_seed[64] || ed25519_seed[32] || mldsa_seed[32]
qsk = rd("bob.qsk"); check("QSK2 length 166", len(qsk) == 166)
b = header(qsk, "QSK2"); xsk, mseed, eseed, dseed = b[:32], b[32:96], b[96:128], b[128:160]
ek, dk = ML_KEM_1024._keygen_internal(mseed[:32], mseed[32:])      # FIPS 203 (d,z)
vk, _ = ML_DSA_87.key_derive(dseed)                                  # FIPS 204 xi
x_pk = raw(X25519PrivateKey.from_private_bytes(xsk).public_key())
e_pk = raw(Ed25519PrivateKey.from_private_bytes(eseed).public_key())
# QSP2: header || x25519_pk[32] || mlkem_ek[1568] || ed25519_pk[32] || mldsa_vk[2592]
check("QSP2 re-derived independently from QSK2 == crate's bundle (4230 B)",
      b"QSP2\x02\x01" + x_pk + ek + e_pk + vk == rd("bob.qsp"))

# QSE2: header || epk[32] || ct_mlkem[1568] || nonce[12] || aead_ct
env = rd("envelope.qse"); b = header(env, "QSE2")
epk, ct, nonce, aead = b[:32], b[32:1600], b[1600:1612], b[1612:]
ss_x = X25519PrivateKey.from_private_bytes(xsk).exchange(X25519PublicKey.from_public_bytes(epk))
ss_m = ML_KEM_1024.decaps(dk, ct)
label = b"quantum-shield/v2/kem:X25519+ML-KEM-1024\0"
ss = hashlib.sha3_256(label + ss_m + ss_x + ct + epk + ek + x_pk).digest()
try:
    pt = AESGCM(ss).decrypt(nonce, aead, env[:1618])            # aad = full 1618-byte prefix
    check("QSE2 envelope decrypts with documented combiner + AAD", pt == rd("plaintext"))
except Exception as e:
    check(f"QSE2 envelope decrypts with documented combiner + AAD ({type(e).__name__})", False)

# QSS2: header || ed25519_sig[64] || mldsa_sig[4627]; M' = label || u8(len ctx) || ctx || msg
sig = rd("sig.qss"); check("QSS2 length 4697", len(sig) == 4697); b = header(sig, "QSS2")
ctx, msg = b"ctx-123", b"signed message body"
Mp = b"quantum-shield/v2/sig:Ed25519+ML-DSA-87\0" + bytes([len(ctx)]) + ctx + msg
a = rd("alice.qsp")[6:]; a_ed, a_vk = a[1600:1632], a[1632:]
try: Ed25519PublicKey.from_public_bytes(a_ed).verify(b[:64], Mp); ed_ok = True
except Exception: ed_ok = False
check("QSS2 Ed25519 component verifies over documented M'", ed_ok)
check("QSS2 ML-DSA-87 component verifies over documented M' with empty FIPS ctx",
      ML_DSA_87.verify(a_vk, Mp, b[64:], ctx=b""))
# FIPS 204 determinism claim: an independent signer must reproduce the crate's ML-DSA bytes
qa = rd("alice.qsk")[6:]
_, a_sk = ML_DSA_87.key_derive(qa[128:160])
check("ML-DSA-87 'deterministic' claim: independent re-sign is byte-identical",
      ML_DSA_87.sign(a_sk, Mp, ctx=b"", deterministic=True) == b[64:])

def kem_ss(epk, ct):
    sx = X25519PrivateKey.from_private_bytes(xsk).exchange(X25519PublicKey.from_public_bytes(epk))
    sm = ML_KEM_1024.decaps(dk, ct)
    return hashlib.sha3_256(label + sm + sx + ct + epk + ek + x_pk).digest()
def gcm(key, nonce, ct, aad):
    try: return AESGCM(key).decrypt(nonce, ct, aad)
    except Exception: return None

# QSM2: header || count u16_be || commitment[32] || wraps || payload_nonce[12] || payload_ct
m = rd("multi.qsm"); b = header(m, "QSM2"); n = int.from_bytes(b[:2], "big")
commit = b[2:34]; off = 34; cek = None; matched = []
for i in range(n):
    w = b[off:off+1660]; off += 1660
    ss_i = kem_ss(w[:32], w[32:1600])
    c = gcm(ss_i, w[1600:1612], w[1612:1660], m[:8])            # aad = header || count
    if c is not None: cek = c; matched.append(i)
check("QSM2: exactly bob's wrap (index 1 of 3) opens", matched == [1])
check("QSM2: CEK matches documented commitment",
      cek is not None and hashlib.sha3_256(b"quantum-shield/v2/multi:cek-commit\0" + cek).digest() == commit)
pn = b[off:off+12]; pt = gcm(cek, pn, b[off+12:], m[:6+off+12])  # aad = whole prefix
check("QSM2: payload decrypts with whole-prefix AAD", pt == b"multi-recipient payload")

# QST2: header || epk || ct || nonce_prefix[7]; frame = last u8 || len u32_be || ct
hdr = rd("stream.hdr"); hb = header(hdr, "QST2"); check("QST2 header 1613 B", len(hdr) == 1613)
key = kem_ss(hb[:32], hb[32:1600]); prefix = hb[1600:1607]
fr = rd("stream.frames"); off = 0; i = 0; out = b""; ok = True; saw_last = False
while off < len(fr):
    last = fr[off]; ln = int.from_bytes(fr[off+1:off+5], "big"); c = fr[off+5:off+5+ln]; off += 5 + ln
    idx = i.to_bytes(4, "big")
    chunk = gcm(key, prefix + idx + bytes([last]), c, hdr + idx + bytes([last]))
    if chunk is None: ok = False; break
    out += chunk; saw_last = bool(last); i += 1
check("QST2: 3 chunks decrypt with documented nonce/AAD, last flag on final",
      ok and saw_last and i == 3 and out == b"chunk-zero chunk-one-is-longer last")

# QSR2: header || epoch u64_be || new_public[4230] || sig[4697]
r = rd("rotation.qsr"); check("QSR2 length 8941", len(r) == 8941); rb = header(r, "QSR2")
epoch = int.from_bytes(rb[:8], "big"); newp = rb[8:4238]; rs = rb[4238+6:]
check("QSR2: epoch=7 and embedded successor == bob's QSP2", epoch == 7 and newp == rd("bob.qsp"))
old_id = hashlib.sha3_256(rd("alice.qsp")).digest()[:16]
rctx = b"quantum-shield/v2/rotate\0"
RM = b"quantum-shield/v2/sig:Ed25519+ML-DSA-87\0" + bytes([len(rctx)]) + rctx + old_id + rb[:8] + newp
try: Ed25519PublicKey.from_public_bytes(a_ed).verify(rs[:64], RM); e2 = True
except Exception: e2 = False
check("QSR2: Ed25519 verifies over documented rotation message", e2)
check("QSR2: ML-DSA-87 verifies over documented rotation message", ML_DSA_87.verify(a_vk, RM, rs[64:], ctx=b""))
passed = sum(1 for _, o in results if o)
print(f"{passed}/{len(results)} passed")
sys.exit(0 if passed == len(results) else 1)
