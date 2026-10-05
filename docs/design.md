# quantum-shield v2 design and wire format

This document is the normative specification of the quantum-shield v2
formats. An independent implementation following this document interoperates
with this crate: `ci/interop/cleanroom.py` is one, written from this document
alone, and CI checks that it opens and verifies every format this crate
produces. Integer fields (counts, lengths, indices, epochs) are big-endian;
keys, ciphertexts, nonces and signatures are raw fixed-size byte strings.

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
`QSK2` secret key bundle, `QSM2` multi-recipient envelope, `QST2` stream
header, `QSR2` rotation attestation. Inputs beginning with `{` (0x7B) are quantum-shield
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

This is **not** X-Wing (draft-connolly-cfrg-xwing-kem), which uses
ML-KEM-768, places its label last, and does not hash the ML-KEM ciphertext or
encapsulation key. This combiner hashes the full transcript (both ciphertext
components and both recipient public keys), in the style of Chempat and the
CFRG hybrid-KEM "universal combiner", so the derivation does not depend on
ML-KEM-specific binding properties. It has no dedicated published security
proof. `ss` is used directly as the AES-256-GCM key.

Decapsulation recomputes `ss_x25519` from the recipient's static secret and
`epk_x25519`, decapsulates `ct_mlkem` (ML-KEM implicit rejection applies:
tampered ciphertexts yield a random secret, never an error), and applies the
same combiner. Recipient X25519 keys are checked for low order when a
`QSP2` bundle is parsed (see below). The sender's ephemeral key is not
checked on decapsulation: a low-order `epk_x25519` only makes `ss_x25519`
predictable, and the ML-KEM secret still randomizes `ss`.

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

Parsers must validate components:

- X25519: reject low-order points (including all-zero), i.e. any key for
  which Diffie-Hellman is non-contributory. Otherwise the hybrid KEM would
  silently degrade to ML-KEM alone for that recipient.
- ML-KEM-1024: the FIPS 203 §7.2 encapsulation-key (modulus) check.
- Ed25519: the point must decompress, be canonically encoded (`y < p`), and
  not have small order.
- ML-DSA-87: length only (every bit pattern decodes to a valid `t1`).

A bundle that fails any component check is invalid as a whole.

## Secret key bundle (`QSK2`, fixed 166 bytes)

```text
header[6] || x25519_sk[32] || mlkem_seed[64] || ed25519_seed[32] || mldsa_seed[32]
```

Private keys are stored in seed form only (FIPS 203 `(d,z)` seed, FIPS 204
`xi` seed); all working keys are re-derived on import. Implementations must
zeroize seed material on drop and treat the bundle as highly sensitive.

## Multi-recipient envelope (`QSM2`)

Encrypts one payload to N recipients (1 ≤ N ≤ 1024).

```text
header[6] || recipient_count: u16_be || cek_commitment[32]
          || wrap[0..N] || payload_nonce[12] || payload_ct[..]
wrap = epk_x25519[32] || ct_mlkem[1568] || wrap_nonce[12] || wrapped_cek[48]
```

Construction:

1. Draw a random 32-byte content-encryption key (CEK).
2. Compute `cek_commitment = SHA3-256("quantum-shield/v2/multi:cek-commit\0" || CEK)`.
3. For each recipient, run the hybrid KEM (as above) to a shared secret `ss_i`,
   then AES-256-GCM-encrypt the CEK under `ss_i` with `wrap_nonce` and
   `aad = header || recipient_count`. The 48-byte result is `wrapped_cek`
   (32-byte CEK + 16-byte tag).
4. AES-256-GCM-encrypt the payload under the CEK with `payload_nonce` and
   `aad = the entire prefix` (header, count, commitment, **all** wrap records,
   and `payload_nonce`).

The payload AAD binds the full recipient set, so adding, removing, reordering,
or duplicating any wrap fails authentication. Decryption trial-decrypts every
wrap — there is **no** per-recipient identifier on the wire — and, after
recovering a CEK, **must** check `SHA3-256(label || CEK) == cek_commitment`
(constant-time) before using it; a mismatch is a uniform failure. Implementations
must reject `recipient_count == 0`, `recipient_count > 1024`, and a byte length
inconsistent with the count.

Security notes: this is KEM-DEM, not the v0.1.x OR-flaw — every wrap is a full
hybrid KEM and the CEK is random, so no single broken key reveals the payload.
The commitment closes an equivocation gap: because AES-GCM is not key-committing,
without it a malicious sender could wrap *different* CEKs to different recipients
and craft one payload that decrypts to different plaintexts for each. Requiring
every recipient to match the single committed CEK prevents that.

DoS note: because there is no recipient identifier, `open` trial-decrypts every
wrap, so an unauthenticated attacker can force up to `recipient_count` hybrid
decapsulations per message. `MAX_RECIPIENTS = 1024` bounds this; callers who
process untrusted envelopes should rate-limit accordingly.

## Streaming envelope (`QST2`)

For payloads too large for a single-shot envelope. One hybrid KEM run keys the
whole stream; the payload is chunked.

Header (once):

```text
header[6] || epk_x25519[32] || ct_mlkem[1568] || nonce_prefix[7]
```

Each chunk frame:

```text
last: u8 (0|1) || chunk_ct_len: u32_be || chunk_ct[..]
```

For chunk index `i` (0-based, `u32`):

- nonce = `nonce_prefix (7) || i as u32_be (4) || last (1)`
- `aad = stream_header || i as u32_be || last`
- `chunk_ct = AES-256-GCM(key = ss, nonce, plaintext_chunk, aad)`

The sender chooses each chunk's plaintext length (at most 2^32 − 17 bytes, so
that `chunk_ct_len` fits a `u32`); 64 KiB (`STREAM_CHUNK_SIZE`) is the
recommended size. The final chunk sets `last = 1`;
a stream with no `last = 1` chunk is a truncation and must be rejected at
finalization. Binding the index and last-flag into both the nonce and the AAD
makes reordering, duplication, dropping, and truncation fail. Implementations
must reject a `u32` counter overflow (2^32 chunks).

## Rotation attestation (`QSR2`, fixed 8941 bytes)

```text
header[6] || epoch: u64_be || new_public (QSP2, 4230) || signature (QSS2, 4697)
```

`key_id(bundle) = SHA3-256(bundle_QSP2_bytes)[..16]`. An attestation is the
**old** keypair's hybrid signature over

```text
old_key_id (16) || epoch (8) || new_public_QSP2 (4230)
```

under the signing context `"quantum-shield/v2/rotate\0"`. The old bundle is
not on the wire: a verifier supplies the trusted old key, recomputes the
message, and checks the signature (both Ed25519 and ML-DSA-87). Success proves
the trusted old key authorized `new_public` at `epoch`.

Rollback: attestations do not expire, so a verifier that trusts `old` must
remember the highest `epoch` it has accepted for `old` and reject any
attestation whose epoch does not strictly advance; otherwise a captured,
superseded attestation could roll it back to an old successor. The library is
stateless and cannot enforce this — it only binds and exposes the epoch.

## Stability

`QSE2`, `QSS2`, `QSP2`/`QSK2` key derivation, `key_id`, and `QSR2` are pinned
by golden vectors (`tests/golden.rs`, and the combiner vector in
`src/hybrid_kem.rs`). Those are regression pins of this crate's own output,
not external known-answer tests; the external checks are the NIST ACVP
vectors in `tests/acvp.rs` and the independent implementation in
`ci/interop/`, which covers all seven formats. Any change to a format
requires a new format version, not an update to the pinned vectors.
