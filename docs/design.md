# quantum-shield v2 design and wire format

This document is the normative specification of the quantum-shield v2
formats. An independent implementation following this document interoperates
with this crate. All multi-byte fields are raw bytes (no endianness
concerns); all sizes are fixed by the suite.

## Suite

Every wire object carries `version = 2` and `suite = 1`. Suite 1 means
exactly:

| Role | Algorithm |
|---|---|
| Classical KEM | X25519 (RFC 7748) |
| Post-quantum KEM | ML-KEM-1024 (FIPS 203) |
| KDF / combiner | SHA3-256 (FIPS 202) |
| Payload AEAD | AES-256-GCM, 96-bit nonce, 128-bit tag |
| Classical signature | Ed25519 (RFC 8032), `verify_strict` semantics |
| Post-quantum signature | ML-DSA-87 (FIPS 204), pure mode, deterministic |

There is no negotiation. A different algorithm set would be a new suite id,
and implementations must reject unknown versions and suites.

## Common header

Every serialized object begins with:

```text
magic[4] || version: u8 (= 2) || suite: u8 (= 1)
```

Magics: `QSE2` envelope, `QSS2` signature, `QSP2` public key bundle,
`QSK2` secret key bundle. Inputs beginning with `{` (0x7B) are quantum-shield
0.1.x JSON artifacts and must be rejected with a dedicated error.

## Hybrid KEM

Encapsulation to a recipient with X25519 public key `pk_x25519` and ML-KEM
encapsulation key `ek_mlkem`:

1. Generate an ephemeral X25519 keypair `(esk, epk_x25519)`;
   compute `ss_x25519 = X25519(esk, pk_x25519)`.
2. Run ML-KEM-1024 encapsulation: `(ct_mlkem, ss_mlkem) = Encaps(ek_mlkem)`.
3. Derive the 32-byte shared secret:

```text
ss = SHA3-256( "quantum-shield/v2/kem:X25519+ML-KEM-1024\0"
               || ss_mlkem   (32 B)
               || ss_x25519  (32 B)
               || ct_mlkem   (1568 B)
               || epk_x25519 (32 B)
               || ek_mlkem   (1568 B)
               || pk_x25519  (32 B) )
```

The label includes a trailing NUL byte. Every field is fixed-size, so the
concatenation is injective without length framing.

This is the X-Wing combiner (draft-connolly-cfrg-xwing-kem) ported to
ML-KEM-1024 with a distinct label, hardened by hashing the full transcript
(both ciphertext components and both recipient public keys, in the style of
Chempat), so the derivation does not depend on ML-KEM-specific binding
properties. `ss` is used directly as the AES-256-GCM key.

Decapsulation recomputes `ss_x25519` from the recipient's static secret and
`epk_x25519`, decapsulates `ct_mlkem` (ML-KEM implicit rejection applies:
tampered ciphertexts yield a random secret, never an error), and applies the
same combiner. No X25519 contributory check is performed; the ML-KEM secret
and the hashed transcript make low-order inputs harmless.

## Envelope (`QSE2`)

```text
header[6] || epk_x25519[32] || ct_mlkem[1568] || nonce[12] || aead_ct[..]
```

- `nonce` is 12 random bytes from the OS RNG. The AEAD key is single-use
  (fresh KEM per envelope), so nonce collisions across envelopes are
  irrelevant; randomness is defense in depth.
- `aead_ct = AES-256-GCM-Encrypt(key = ss, nonce, plaintext, aad)` where
  **`aad` is the entire 1618-byte prefix** (header through nonce). Any
  header modification therefore fails authentication.
- `aead_ct` is plaintext length + 16 bytes of tag; total envelope overhead
  is 1634 bytes.
- Encrypting implementations must reject plaintexts over 64 MiB
  (`MAX_PLAINTEXT_LEN`); parsers must reject envelopes whose `aead_ct` is
  shorter than 16 bytes.
- Decryption failures must be reported uniformly, with no distinction
  between parse-stage and AEAD-stage failures beyond what parsing itself
  reveals.

## Hybrid signature (`QSS2`, fixed 4697 bytes)

```text
header[6] || ed25519_sig[64] || mldsa_sig[4627]
```

Both signatures are computed over the framed message

```text
M' = "quantum-shield/v2/sig:Ed25519+ML-DSA-87\0"
     || u8(len(context)) || context || message
```

with `context` limited to 255 bytes (mirroring the FIPS 204 context-string
limit; the FIPS 204 external `ctx` parameter itself is empty). ML-DSA-87
signing uses the deterministic variant. Ed25519 verification uses strict
semantics (reject small-order and non-canonical components).

**Verification requires both components to pass.** Implementations should
evaluate both before deciding, and must not provide any mode that accepts
one signature alone.

## Public key bundle (`QSP2`, fixed 4230 bytes)

```text
header[6] || x25519_pk[32] || mlkem_ek[1568] || ed25519_pk[32] || mldsa_vk[2592]
```

Parsers must validate components: ML-KEM encapsulation keys re-encode
canonically (modulus check), Ed25519 points decompress. A bundle that fails
any component check is invalid as a whole.

## Secret key bundle (`QSK2`, fixed 166 bytes)

```text
header[6] || x25519_sk[32] || mlkem_seed[64] || ed25519_seed[32] || mldsa_seed[32]
```

Private keys are stored in seed form only (FIPS 203 `(d,z)` seed, FIPS 204
`xi` seed); all working keys are re-derived on import. Implementations must
zeroize seed material on drop and treat the bundle as highly sensitive.

## Stability

The formats above are covered by known-answer tests (`tests/golden.rs` and
the KAT in `src/hybrid_kem.rs`). Any change to them requires a new format
version, not an update to the pinned vectors.
