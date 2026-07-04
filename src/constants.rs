//! Sizes, labels, and limits for the quantum-shield v2 wire format.
//!
//! All sizes are fixed by the algorithm suite (suite id 1): X25519 +
//! ML-KEM-1024 for key establishment, AES-256-GCM for payload encryption,
//! and Ed25519 + ML-DSA-87 for signatures.

/// Wire format version produced and accepted by this crate.
pub const WIRE_VERSION: u8 = 2;

/// Cipher suite id 1: X25519 + ML-KEM-1024, AES-256-GCM, Ed25519 + ML-DSA-87.
pub const SUITE_ID: u8 = 1;

/// Length of the common wire header: magic (4) + version (1) + suite (1).
pub const HEADER_LEN: usize = 6;

/// Magic prefix of a serialized [`Envelope`](crate::Envelope).
pub const MAGIC_ENVELOPE: [u8; 4] = *b"QSE2";

/// Magic prefix of a serialized [`HybridSignature`](crate::HybridSignature).
pub const MAGIC_SIGNATURE: [u8; 4] = *b"QSS2";

/// Magic prefix of a serialized [`PublicKeyBundle`](crate::PublicKeyBundle).
pub const MAGIC_PUBLIC_BUNDLE: [u8; 4] = *b"QSP2";

/// Magic prefix of a serialized secret-key bundle.
pub const MAGIC_SECRET_BUNDLE: [u8; 4] = *b"QSK2";

/// X25519 public key length in bytes.
pub const X25519_PK_LEN: usize = 32;

/// X25519 secret key length in bytes.
pub const X25519_SK_LEN: usize = 32;

/// ML-KEM-1024 encapsulation (public) key length in bytes.
pub const MLKEM1024_EK_LEN: usize = 1568;

/// ML-KEM-1024 ciphertext length in bytes.
pub const MLKEM1024_CT_LEN: usize = 1568;

/// ML-KEM (d,z) seed length in bytes (FIPS 203 private key seed form).
pub const MLKEM_SEED_LEN: usize = 64;

/// Ed25519 public key length in bytes.
pub const ED25519_PK_LEN: usize = 32;

/// Ed25519 private key seed length in bytes.
pub const ED25519_SEED_LEN: usize = 32;

/// Ed25519 signature length in bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// ML-DSA-87 verifying (public) key length in bytes.
pub const MLDSA87_VK_LEN: usize = 2592;

/// ML-DSA-87 signature length in bytes.
pub const MLDSA87_SIG_LEN: usize = 4627;

/// ML-DSA private key seed (xi) length in bytes (FIPS 204 Algorithm 6).
pub const MLDSA_SEED_LEN: usize = 32;

/// AES-256-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Length of the authenticated envelope header (everything before the AEAD
/// ciphertext): header + ephemeral X25519 key + ML-KEM ciphertext + nonce.
/// This entire prefix is bound into the AEAD tag as associated data.
pub const ENVELOPE_AAD_LEN: usize = HEADER_LEN + X25519_PK_LEN + MLKEM1024_CT_LEN + NONCE_LEN;

/// Total envelope overhead on top of the plaintext length.
pub const ENVELOPE_OVERHEAD: usize = ENVELOPE_AAD_LEN + TAG_LEN;

/// Serialized [`HybridSignature`](crate::HybridSignature) length in bytes.
pub const SIGNATURE_LEN: usize = HEADER_LEN + ED25519_SIG_LEN + MLDSA87_SIG_LEN;

/// Serialized [`PublicKeyBundle`](crate::PublicKeyBundle) length in bytes.
pub const PUBLIC_BUNDLE_LEN: usize =
    HEADER_LEN + X25519_PK_LEN + MLKEM1024_EK_LEN + ED25519_PK_LEN + MLDSA87_VK_LEN;

/// Serialized secret-key bundle length in bytes (seeds only).
pub const SECRET_BUNDLE_LEN: usize =
    HEADER_LEN + X25519_SK_LEN + MLKEM_SEED_LEN + ED25519_SEED_LEN + MLDSA_SEED_LEN;

/// Maximum plaintext length accepted by [`seal`](crate::seal) (64 MiB).
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;

/// Maximum signing/verification context length in bytes (mirrors the FIPS 204
/// context-string limit).
pub const MAX_CONTEXT_LEN: usize = 255;

/// Domain-separation label for the hybrid KEM shared-secret combiner.
pub(crate) const KEM_COMBINER_LABEL: &[u8] = b"quantum-shield/v2/kem:X25519+ML-KEM-1024\0";

/// Domain-separation label prepended to every signed message.
pub(crate) const SIG_DOMAIN_LABEL: &[u8] = b"quantum-shield/v2/sig:Ed25519+ML-DSA-87\0";
