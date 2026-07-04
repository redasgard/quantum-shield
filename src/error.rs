//! Error types for quantum-shield.
//!
//! Decryption and verification failures are deliberately opaque: they carry
//! no algorithm-specific detail, so callers cannot accidentally build a
//! padding/format oracle out of the error messages.

/// Result type alias for quantum-shield operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The wire object declares a format version this crate does not support.
    #[error("unsupported wire format version {0}")]
    UnsupportedVersion(u8),

    /// The wire object declares a cipher suite this crate does not support.
    #[error("unsupported cipher suite {0}")]
    UnsupportedSuite(u8),

    /// The input is a quantum-shield 0.1.x JSON artifact. The v1 format is
    /// cryptographically broken and unsupported by design.
    #[error(
        "quantum-shield v1 (0.1.x) artifacts are not supported; \
         decrypt with a 0.1.x build and re-encrypt with v2"
    )]
    LegacyV1Artifact,

    /// Key material failed to parse or validate.
    #[error("invalid key material")]
    InvalidKey,

    /// An envelope failed to parse (wrong magic, truncated, or malformed).
    #[error("invalid envelope encoding")]
    InvalidEnvelope,

    /// A signature failed to parse (wrong magic, truncated, or malformed).
    #[error("invalid signature encoding")]
    InvalidSignature,

    /// Decryption failed. No further detail is provided by design.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Signature verification failed. No further detail is provided by design.
    #[error("signature verification failed")]
    VerificationFailed,

    /// The plaintext exceeds [`MAX_PLAINTEXT_LEN`](crate::MAX_PLAINTEXT_LEN).
    #[error("message too large: {len} bytes exceeds the {max}-byte limit")]
    MessageTooLarge {
        /// Length of the rejected message in bytes.
        len: usize,
        /// The enforced limit in bytes.
        max: usize,
    },

    /// The signing context exceeds [`MAX_CONTEXT_LEN`](crate::MAX_CONTEXT_LEN).
    #[error("context longer than 255 bytes")]
    ContextTooLong,

    /// The operating system's secure random number generator failed.
    #[error("operating system randomness unavailable")]
    RandomnessUnavailable,

    /// A multi-recipient envelope was requested with no recipients.
    #[error("no recipients")]
    NoRecipients,

    /// A multi-recipient envelope exceeds [`MAX_RECIPIENTS`](crate::MAX_RECIPIENTS).
    #[error("too many recipients: {count} exceeds the {max} limit")]
    TooManyRecipients {
        /// The rejected recipient count.
        count: usize,
        /// The enforced limit.
        max: usize,
    },

    /// A streaming chunk was submitted after the final chunk.
    #[error("stream already finished")]
    StreamFinished,

    /// A stream ended without a final chunk (possible truncation).
    #[error("stream truncated")]
    StreamTruncated,
}
