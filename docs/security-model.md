# Security model

This is an honest statement of what quantum-shield v2 does and does not
protect against. If a claim isn't here, don't assume it.

## Audit status

**Neither this library nor the underlying `ml-kem`/`ml-dsa` crates have been
independently audited.** The library implements FIPS 203/204 algorithms; it
is not FIPS-validated. Do not deploy it where certification is required.

## What the hybrid construction buys

Both primitives protect every operation, AND-composed:

- **Confidentiality**: the AEAD key is `SHA3-256(ss_mlkem || ss_x25519 ||
  transcript)`. Recovering it requires both the X25519 shared secret
  (classical hardness: CDH on Curve25519) and the ML-KEM-1024 shared secret
  (post-quantum hardness: MLWE). A quantum attacker running Shor's algorithm
  gets `ss_x25519` but not `ss_mlkem`; a lattice cryptanalysis breakthrough
  gets `ss_mlkem` but not `ss_x25519`.
- **Authenticity**: verification requires a valid Ed25519 *and* a valid
  ML-DSA-87 signature over the same framed message. Forgery requires
  breaking both.

Consequences: "harvest now, decrypt later" traffic recorded today stays
confidential against a future quantum computer, as long as ML-KEM-1024
holds.

## Threats addressed

- **Ciphertext tampering / malleability**: every envelope byte is either
  AEAD-encrypted or bound as associated data; the KDF additionally binds the
  full KEM transcript. Component swapping between envelopes fails.
- **Downgrade**: version and suite bytes are authenticated; unknown values
  are rejected; v1 artifacts are rejected outright. There is no negotiation
  to attack.
- **Signature stripping**: both signature fields are fixed-size and
  mandatory; there is no wire encoding without the post-quantum component
  (the 0.1.x vulnerability).
- **Cross-protocol / cross-context reuse**: KEM and signature inputs are
  domain-separated by labels; signatures additionally separate application
  contexts via the length-framed `context` parameter.
- **Decryption oracles**: ML-KEM implicit rejection plus a single uniform
  `DecryptionFailed` error; error values carry no algorithm detail.
- **Key-material hygiene**: private keys exist as seeds, zeroized on drop
  (`zeroize`), never printed by `Debug`. Randomness comes from the OS CSPRNG
  (`getrandom`) only.

## Threats NOT addressed

- **Side channels beyond best effort**: the underlying crates are written to
  be constant-time (dalek, RustCrypto `ml-kem`/`ml-dsa`), but no formal
  side-channel evaluation has been done on this composition. No claims about
  fault injection, electromagnetic leakage, or speculative-execution
  attacks.
- **Sender authentication of envelopes**: `seal` is anonymous (like
  `crypto_box_seal`). An envelope proves nothing about who sent it — sign
  the message if you need that.
- **Replay**: a valid envelope or signature can be replayed; deduplication
  and freshness are application concerns (put a nonce/timestamp in the
  message or context).
- **Key distribution and trust**: binding a `PublicKeyBundle` to an identity
  (PKI, TOFU, out-of-band verification) is out of scope.
- **Forward secrecy for the recipient**: the recipient's KEM keys are
  static. Compromise of a recipient's secret bundle decrypts all past
  envelopes addressed to it. Rotate keys if you need bounded exposure.
- **Denial of service**: parsing enforces sizes, but callers must still
  bound how many envelopes/signatures they process. Note that opening a
  multi-recipient envelope trial-decrypts every wrap (no recipient identifier
  is on the wire, for privacy), so an attacker can force up to
  `MAX_RECIPIENTS` (1024) hybrid decapsulations per message — rate-limit
  untrusted multi-recipient input.
- **Multi-recipient equivocation** is *addressed*: `QSM2` binds `SHA3-256(CEK)`
  as a commitment and every recipient checks it, so a malicious sender cannot
  deliver different plaintexts to different recipients (AES-GCM alone is not
  key-committing).
- **Rotation rollback**: a `RotationAttestation` never expires. It binds a
  caller-supplied monotonic `epoch`, but the library is stateless — a verifier
  **must** track the highest epoch accepted per signer and reject non-advancing
  ones, or a captured superseded attestation can roll it back.
- **Stream truncation** is only caught if the reader calls
  `StreamOpener::finish()`; a reader that drops the opener without finishing
  will accept a truncated stream.

## Operational guidance

- Rotate keys on personnel or system compromise, and consider periodic
  rotation to bound the forward-secrecy exposure above.
- Treat `to_secret_bytes()` output like any other long-term private key:
  KMS/HSM-backed storage, at-rest encryption, least privilege.
- Report vulnerabilities per [SECURITY.md](../SECURITY.md).
