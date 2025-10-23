//! Constants for quantum-shield cryptography

// Algorithm specifications
pub const RSA_KEY_SIZE: usize = 4096;
pub const KYBER_KEY_SIZE: usize = 1024;
pub const DILITHIUM_KEY_SIZE: usize = 5;

// NIST security levels
pub const NIST_LEVEL_5: u8 = 5;

// Buffer sizes
pub const KYBER1024_CIPHERTEXT_BYTES: usize = 1568;
pub const NONCE_BYTES: usize = 12;
pub const ENTROPY_BUFFER_SIZE: usize = 32;
pub const HASH_OUTPUT_SIZE: usize = 32;

// Timing and entropy thresholds
pub const DEFAULT_ENTROPY_THRESHOLD: u64 = 256;
pub const MIN_ENTROPY_TIME_SECONDS: u64 = 1;
pub const MAX_TIMING_JITTER_MICROS: u64 = 1000;

// Memory protection
pub const MEMORY_SCRUB_ROUNDS: usize = 3;
pub const SECURE_ALLOCATION_SIZE: usize = 4096;

// Algorithm agility
pub const MAX_ALGORITHM_VERSIONS: usize = 10;
pub const DEFAULT_CRYPTO_VERSION: u8 = 1;

// Security limits
pub const MAX_ENCRYPTION_SIZE: usize = 1024 * 1024; // 1MB
pub const MAX_SIGNATURE_SIZE: usize = 1024 * 1024; // 1MB
pub const MAX_KEY_SIZE: usize = 8192; // 8KB

// Performance thresholds
pub const SLOW_OPERATION_THRESHOLD_MS: u64 = 1000;
pub const MEMORY_USAGE_THRESHOLD_MB: u64 = 100;
