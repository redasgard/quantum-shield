# User Guide

Comprehensive guide for using Quantum Shield in your applications.

## Basic Usage

### 1. Initialize Quantum Shield

```rust
use quantum_shield::{QuantumShield, Config, Algorithm};

// Create configuration
let config = Config::new()
    .with_algorithm(Algorithm::Kyber1024)
    .with_signature_algorithm(Algorithm::Dilithium5)
    .with_hybrid_mode(true);

// Initialize shield
let shield = QuantumShield::new(config)?;
```

### 2. Generate Key Pairs

```rust
// Generate quantum-resistant key pair
let (public_key, private_key) = shield.generate_keypair()?;

println!("Public key: {}", public_key.to_hex());
println!("Private key: {}", private_key.to_hex());
```

### 3. Encrypt Data

```rust
use quantum_shield::CryptoData;

// Prepare data for encryption
let plaintext = b"Secret quantum-resistant message";
let data = CryptoData::from_bytes(plaintext);

// Encrypt with public key
let encrypted = shield.encrypt(&public_key, &data)?;

println!("Encrypted data: {} bytes", encrypted.len());
```

### 4. Decrypt Data

```rust
// Decrypt with private key
let decrypted = shield.decrypt(&private_key, &encrypted)?;
let plaintext = decrypted.to_bytes();

assert_eq!(plaintext, b"Secret quantum-resistant message");
```

## Advanced Usage

### Hybrid Cryptography

```rust
use quantum_shield::{Config, Algorithm, HybridMode};

// Configure hybrid mode (quantum + classical)
let config = Config::new()
    .with_hybrid_mode(true)
    .with_classical_algorithm(Algorithm::RSA4096)
    .with_quantum_algorithm(Algorithm::Kyber1024)
    .with_signature_algorithm(Algorithm::Dilithium5);

let shield = QuantumShield::new(config)?;

// Hybrid encryption (both quantum and classical)
let encrypted = shield.encrypt_hybrid(&public_key, &data)?;
```

### Digital Signatures

```rust
// Sign data
let signature = shield.sign(&private_key, &data)?;

// Verify signature
let is_valid = shield.verify(&public_key, &data, &signature)?;

if is_valid {
    println!("Signature is valid!");
}
```

### Key Exchange

```rust
// Generate ephemeral key pair for key exchange
let (alice_public, alice_private) = shield.generate_keypair()?;
let (bob_public, bob_private) = shield.generate_keypair()?;

// Perform key exchange
let shared_secret_alice = shield.key_exchange(&alice_private, &bob_public)?;
let shared_secret_bob = shield.key_exchange(&bob_private, &alice_public)?;

// Both parties now have the same shared secret
assert_eq!(shared_secret_alice, shared_secret_bob);
```

## Configuration Options

### Algorithm Selection

```rust
use quantum_shield::{Config, Algorithm};

// Kyber for encryption
let kyber_config = Config::new()
    .with_algorithm(Algorithm::Kyber1024);

// Dilithium for signatures
let dilithium_config = Config::new()
    .with_signature_algorithm(Algorithm::Dilithium5);

// SPHINCS+ for stateless signatures
let sphincs_config = Config::new()
    .with_signature_algorithm(Algorithm::SphincsPlus);
```

### Performance Tuning

```rust
use quantum_shield::{Config, PerformanceMode};

// Optimize for speed
let fast_config = Config::new()
    .with_performance_mode(PerformanceMode::Speed)
    .with_algorithm(Algorithm::Kyber768);  // Smaller key size

// Optimize for security
let secure_config = Config::new()
    .with_performance_mode(PerformanceMode::Security)
    .with_algorithm(Algorithm::Kyber1024);  // Larger key size
```

### Memory Management

```rust
use quantum_shield::{Config, MemoryMode};

// Low memory usage
let low_mem_config = Config::new()
    .with_memory_mode(MemoryMode::Low)
    .with_algorithm(Algorithm::Kyber768);

// High memory for better performance
let high_mem_config = Config::new()
    .with_memory_mode(MemoryMode::High)
    .with_algorithm(Algorithm::Kyber1024);
```

## Error Handling

### Comprehensive Error Handling

```rust
use quantum_shield::{QuantumShield, Error};

fn secure_operation() -> Result<(), Box<dyn std::error::Error>> {
    let shield = QuantumShield::new(Config::default())?;
    
    match shield.encrypt(&public_key, &data) {
        Ok(encrypted) => {
            println!("Encryption successful");
            Ok(())
        }
        Err(Error::InvalidKey) => {
            eprintln!("Invalid key provided");
            Err("Invalid key".into())
        }
        Err(Error::EncryptionFailed) => {
            eprintln!("Encryption failed");
            Err("Encryption failed".into())
        }
        Err(e) => {
            eprintln!("Unexpected error: {}", e);
            Err(e.into())
        }
    }
}
```

### Retry Logic

```rust
use quantum_shield::{QuantumShield, Error};
use std::time::Duration;

fn encrypt_with_retry(shield: &QuantumShield, key: &PublicKey, data: &CryptoData) -> Result<EncryptedData, Error> {
    let mut attempts = 0;
    let max_attempts = 3;
    
    loop {
        match shield.encrypt(key, data) {
            Ok(encrypted) => return Ok(encrypted),
            Err(Error::TemporaryFailure) if attempts < max_attempts => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(100 * attempts));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}
```

## Integration Patterns

### Web Application Integration

```rust
use quantum_shield::{QuantumShield, Config};
use axum::{extract::State, response::Json};

// Global shield instance
struct AppState {
    shield: QuantumShield,
}

async fn encrypt_endpoint(
    State(state): State<AppState>,
    Json(request): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, String> {
    let encrypted = state.shield
        .encrypt(&request.public_key, &request.data)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    Ok(Json(EncryptResponse {
        encrypted_data: encrypted.to_hex(),
    }))
}
```

### Database Integration

```rust
use quantum_shield::{QuantumShield, EncryptedData};
use sqlx::PgPool;

struct SecureStorage {
    shield: QuantumShield,
    pool: PgPool,
}

impl SecureStorage {
    async fn store_encrypted(&self, key_id: &str, data: &[u8]) -> Result<(), sqlx::Error> {
        // Encrypt data
        let encrypted = self.shield.encrypt(&self.get_public_key(key_id)?, &data.into())?;
        
        // Store in database
        sqlx::query!(
            "INSERT INTO encrypted_data (key_id, data) VALUES ($1, $2)",
            key_id,
            encrypted.to_bytes()
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
}
```

### File System Integration

```rust
use quantum_shield::{QuantumShield, CryptoData};
use std::fs;

struct SecureFileSystem {
    shield: QuantumShield,
}

impl SecureFileSystem {
    fn encrypt_file(&self, input_path: &str, output_path: &str, public_key: &PublicKey) -> Result<(), Box<dyn std::error::Error>> {
        // Read file
        let file_data = fs::read(input_path)?;
        let crypto_data = CryptoData::from_bytes(&file_data);
        
        // Encrypt
        let encrypted = self.shield.encrypt(public_key, &crypto_data)?;
        
        // Write encrypted file
        fs::write(output_path, encrypted.to_bytes())?;
        
        Ok(())
    }
}
```

## Performance Optimization

### Batch Operations

```rust
use quantum_shield::{QuantumShield, BatchEncrypt};

// Encrypt multiple items at once
let items = vec![
    ("item1", data1),
    ("item2", data2),
    ("item3", data3),
];

let batch_encrypted = shield.batch_encrypt(&public_key, &items)?;

for (id, encrypted) in batch_encrypted {
    println!("Encrypted {}: {} bytes", id, encrypted.len());
}
```

### Async Operations

```rust
use quantum_shield::{QuantumShield, AsyncShield};
use tokio::task;

async fn async_encryption(shield: AsyncShield, data: Vec<CryptoData>) -> Result<Vec<EncryptedData>, Error> {
    let tasks: Vec<_> = data.into_iter()
        .map(|d| {
            let shield = shield.clone();
            task::spawn(async move {
                shield.encrypt(&public_key, &d).await
            })
        })
        .collect();
    
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await??);
    }
    
    Ok(results)
}
```

### Memory Pool

```rust
use quantum_shield::{QuantumShield, MemoryPool};

// Use memory pool for better performance
let pool = MemoryPool::new(10);  // 10 pre-allocated buffers
let shield = QuantumShield::new_with_pool(config, pool)?;

// Operations will reuse memory buffers
let encrypted = shield.encrypt(&public_key, &data)?;
```

## Security Best Practices

### Key Management

```rust
use quantum_shield::{QuantumShield, KeyManager};

// Use key manager for secure key handling
let key_manager = KeyManager::new()
    .with_secure_storage()
    .with_key_rotation()
    .with_backup_enabled();

let shield = QuantumShield::new_with_key_manager(config, key_manager)?;
```

### Secure Random Generation

```rust
use quantum_shield::{QuantumShield, SecureRandom};

// Use cryptographically secure random
let secure_rng = SecureRandom::new()
    .with_entropy_source(EntropySource::Hardware)
    .with_entropy_validation();

let shield = QuantumShield::new_with_rng(config, secure_rng)?;
```

### Input Validation

```rust
use quantum_shield::{QuantumShield, Validation};

// Validate inputs before encryption
fn secure_encrypt(shield: &QuantumShield, key: &PublicKey, data: &[u8]) -> Result<EncryptedData, Error> {
    // Validate key
    if !key.is_valid() {
        return Err(Error::InvalidKey);
    }
    
    // Validate data size
    if data.len() > MAX_DATA_SIZE {
        return Err(Error::DataTooLarge);
    }
    
    // Validate data content
    if !Validation::is_safe_data(data) {
        return Err(Error::UnsafeData);
    }
    
    shield.encrypt(key, &data.into())
}
```

## Monitoring and Logging

### Performance Monitoring

```rust
use quantum_shield::{QuantumShield, Metrics};

let metrics = Metrics::new()
    .with_encryption_timing()
    .with_memory_usage()
    .with_error_tracking();

let shield = QuantumShield::new_with_metrics(config, metrics)?;

// Monitor performance
let start = std::time::Instant::now();
let encrypted = shield.encrypt(&public_key, &data)?;
let duration = start.elapsed();

println!("Encryption took: {:?}", duration);
println!("Memory used: {} bytes", metrics.memory_usage());
```

### Security Logging

```rust
use quantum_shield::{QuantumShield, SecurityLogger};

let logger = SecurityLogger::new()
    .with_audit_trail()
    .with_threat_detection()
    .with_compliance_logging();

let shield = QuantumShield::new_with_logger(config, logger)?;

// All operations are logged for security audit
let encrypted = shield.encrypt(&public_key, &data)?;
```

## Troubleshooting

### Common Issues

**1. Invalid Key Error**
```rust
// Check key format
if !public_key.is_valid_format() {
    eprintln!("Invalid key format");
}

// Check key size
if public_key.size() != expected_size {
    eprintln!("Unexpected key size: {}", public_key.size());
}
```

**2. Encryption Failure**
```rust
// Check data size
if data.len() > MAX_ENCRYPTION_SIZE {
    eprintln!("Data too large for encryption");
}

// Check memory availability
if !has_sufficient_memory() {
    eprintln!("Insufficient memory for operation");
}
```

**3. Performance Issues**
```rust
// Use smaller algorithm for better performance
let fast_config = Config::new()
    .with_algorithm(Algorithm::Kyber768)  // Instead of Kyber1024
    .with_performance_mode(PerformanceMode::Speed);
```

## Next Steps

- Review [API Reference](./api-reference.md) for complete API documentation
- Check [Security Model](./security-model.md) for security considerations
- See [Performance](./performance.md) for optimization tips
- Read [Migration Guide](./migration-guide.md) for upgrading from classical crypto

## Getting Help

- **Documentation**: See `/docs/` directory
- **Examples**: Check `examples/` directory
- **Issues**: https://github.com/redasgard/quantum-shield/issues
- **Email**: hello@redasgard.com
