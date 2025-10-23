# Getting Started

## Installation

Add Quantum Shield to your `Cargo.toml`:

```toml
[dependencies]
quantum-shield = "0.1"
```

## First Steps

### 1. Generate Key Pairs

Every user needs a key pair containing both classical and post-quantum keys:

```rust
use quantum_shield::HybridCrypto;

fn main() -> quantum_shield::Result<()> {
    // Generate keypair for Alice
    let alice = HybridCrypto::generate_keypair()?;
    
    // Generate keypair for Bob
    let bob = HybridCrypto::generate_keypair()?;
    
    println!("Key pairs generated successfully!");
    Ok(())
}
```

**Note:** Key generation takes ~100ms due to RSA. Generate once and reuse.

### 2. Encrypt a Message

Alice wants to send Bob a secret message:

```rust
use quantum_shield::HybridCrypto;

fn main() -> quantum_shield::Result<()> {
    let alice = HybridCrypto::generate_keypair()?;
    let bob = HybridCrypto::generate_keypair()?;
    
    // Alice encrypts message for Bob using his public keys
    let message = b"Meet me at the secret location";
    let encrypted = alice.encrypt(message, &bob.public_keys())?;
    
    println!("Message encrypted!");
    println!("Ciphertext size: {} bytes", encrypted.ciphertext.len());
    
    Ok(())
}
```

### 3. Decrypt a Message

Bob receives the encrypted message and decrypts it:

```rust
use quantum_shield::HybridCrypto;

fn main() -> quantum_shield::Result<()> {
    let alice = HybridCrypto::generate_keypair()?;
    let bob = HybridCrypto::generate_keypair()?;
    
    // Alice encrypts
    let message = b"Meet me at the secret location";
    let encrypted = alice.encrypt(message, &bob.public_keys())?;
    
    // Bob decrypts using his private keys
    let decrypted = bob.decrypt(&encrypted)?;
    
    assert_eq!(message, &decrypted[..]);
    println!("Message: {}", String::from_utf8_lossy(&decrypted));
    
    Ok(())
}
```

### 4. Sign a Message

Alice signs a document to prove authent icity:

```rust
use quantum_shield::HybridCrypto;

fn main() -> quantum_shield::Result<()> {
    let alice = HybridCrypto::generate_keypair()?;
    
    // Alice signs the document
    let document = b"I agree to the terms and conditions";
    let signature = alice.sign(document)?;
    
    println!("Document signed!");
    println!("Signature size: {} bytes", 
             signature.rsa_signature.len() + signature.dilithium_signature.len());
    
    Ok(())
}
```

### 5. Verify a Signature

Anyone can verify Alice's signature using her public keys:

```rust
use quantum_shield::HybridCrypto;

fn main() -> quantum_shield::Result<()> {
    let alice = HybridCrypto::generate_keypair()?;
    
    // Alice signs
    let document = b"I agree to the terms and conditions";
    let signature = alice.sign(document)?;
    
    // Anyone verifies using Alice's public keys
    let is_valid = HybridCrypto::verify(
        document,
        &signature,
        &alice.public_keys()
    )?;
    
    println!("Signature valid: {}", is_valid);
    
    Ok(())
}
```

## Complete Example

Here's a complete example showing encryption and signatures:

```rust
use quantum_shield::{HybridCrypto, Result};

fn main() -> Result<()> {
    // Setup: Generate keys for Alice and Bob
    println!("Generating keys...");
    let alice = HybridCrypto::generate_keypair()?;
    let bob = HybridCrypto::generate_keypair()?;
    
    // Step 1: Alice encrypts a message for Bob
    println!("\n1. Alice encrypts message for Bob");
    let message = b"Secret quantum-resistant message";
    let encrypted = alice.encrypt(message, &bob.public_keys())?;
    println!("   ✓ Message encrypted");
    
    // Step 2: Bob decrypts the message
    println!("\n2. Bob decrypts the message");
    let decrypted = bob.decrypt(&encrypted)?;
    assert_eq!(message, &decrypted[..]);
    println!("   ✓ Message: {}", String::from_utf8_lossy(&decrypted));
    
    // Step 3: Alice signs a document
    println!("\n3. Alice signs a document");
    let document = b"I agree to transfer ownership";
    let signature = alice.sign(document)?;
    println!("   ✓ Document signed");
    
    // Step 4: Bob verifies Alice's signature
    println!("\n4. Bob verifies the signature");
    let is_valid = HybridCrypto::verify(
        document,
        &signature,
        &alice.public_keys()
    )?;
    println!("   ✓ Signature valid: {}", is_valid);
    
    // Step 5: Try to verify with wrong document (should fail)
    println!("\n5. Try to verify tampered document");
    let tampered = b"I agree to transfer everything";
    let is_valid = HybridCrypto::verify(
        tampered,
        &signature,
        &alice.public_keys()
    )?;
    println!("   ✓ Tampered signature valid: {} (should be false)", is_valid);
    
    println!("\n✅ All operations completed successfully!");
    Ok(())
}
```

## Key Management

### Storing Keys

Keys should be stored securely. Here's a basic example:

```rust
use quantum_shield::{HybridCrypto, PublicKeys};
use std::fs;

fn save_public_keys(keys: &PublicKeys, path: &str) -> quantum_shield::Result<()> {
    let json = keys.to_json()?;
    fs::write(path, json)?;
    Ok(())
}

fn load_public_keys(path: &str) -> quantum_shield::Result<PublicKeys> {
    let json = fs::read_to_string(path)?;
    PublicKeys::from_json(&json)
}

fn main() -> quantum_shield::Result<()> {
    let alice = HybridCrypto::generate_keypair()?;
    
    // Save public keys
    save_public_keys(&alice.public_keys(), "alice_public.json")?;
    
    // Load public keys
    let loaded_keys = load_public_keys("alice_public.json")?;
    
    println!("Keys saved and loaded successfully!");
    Ok(())
}
```

**Security Warning:** Private keys should be encrypted before storage. Never commit keys to version control.

### Key Distribution

Public keys can be shared openly:

```rust
use quantum_shield::{HybridCrypto, PublicKeys};

// Alice shares her public keys
fn share_public_keys(alice: &HybridCrypto) -> PublicKeys {
    alice.public_keys()
}

// Bob receives and uses Alice's public keys
fn use_public_keys(bob: &HybridCrypto, alice_public: &PublicKeys) -> quantum_shield::Result<()> {
    let message = b"Secret message";
    let encrypted = bob.encrypt(message, alice_public)?;
    // Send encrypted to Alice...
    Ok(())
}
```

## Common Patterns

### Server-Client Encryption

```rust
use quantum_shield::HybridCrypto;

// Server setup
fn server_setup() -> HybridCrypto {
    HybridCrypto::generate_keypair().expect("Key generation failed")
}

// Client sends encrypted data to server
fn client_send(server_public_keys: &quantum_shield::PublicKeys, data: &[u8]) 
    -> quantum_shield::Result<quantum_shield::HybridCiphertext> 
{
    let client = HybridCrypto::generate_keypair()?;
    client.encrypt(data, server_public_keys)
}

// Server decrypts client data
fn server_receive(server: &HybridCrypto, encrypted: &quantum_shield::HybridCiphertext) 
    -> quantum_shield::Result<Vec<u8>> 
{
    server.decrypt(encrypted)
}
```

### Digital Contract Signing

```rust
use quantum_shield::{HybridCrypto, HybridSignature};

struct Contract {
    content: Vec<u8>,
    signature: Option<HybridSignature>,
}

impl Contract {
    fn new(content: Vec<u8>) -> Self {
        Self { content, signature: None }
    }
    
    fn sign(&mut self, signer: &HybridCrypto) -> quantum_shield::Result<()> {
        self.signature = Some(signer.sign(&self.content)?);
        Ok(())
    }
    
    fn verify(&self, public_keys: &quantum_shield::PublicKeys) -> quantum_shield::Result<bool> {
        if let Some(ref sig) = self.signature {
            HybridCrypto::verify(&self.content, sig, public_keys)
        } else {
            Ok(false)
        }
    }
}
```

## Error Handling

All operations return `Result<T, Error>`:

```rust
use quantum_shield::{HybridCrypto, Error};

fn handle_errors() {
    let alice = HybridCrypto::generate_keypair().expect("Key generation failed");
    let bob = HybridCrypto::generate_keypair().expect("Key generation failed");
    
    let message = b"Secret";
    let encrypted = alice.encrypt(message, &bob.public_keys())
        .expect("Encryption failed");
    
    match bob.decrypt(&encrypted) {
        Ok(decrypted) => println!("Success: {:?}", decrypted),
        Err(Error::DecryptionFailed) => eprintln!("Decryption failed"),
        Err(Error::InvalidCiphertext) => eprintln!("Invalid ciphertext"),
        Err(e) => eprintln!("Other error: {}", e),
    }
}
```

## Next Steps

- Read [User Guide](./user-guide.md) for advanced usage patterns
- Review [API Reference](./api-reference.md) for detailed documentation
- Check [Security Model](./security-model.md) to understand guarantees
- See [Use Cases](./use-cases.md) for real-world applications

## Troubleshooting

### Slow Key Generation

Key generation takes ~100ms due to RSA-4096. This is normal. Generate once and cache keys.

### Large Signatures

Signatures are ~4.5KB due to Dilithium5. This is expected for NIST Level 5 security.

### Decryption Failures

If decryption fails, verify:
1. Correct recipient's private keys are used
2. Ciphertext hasn't been corrupted
3. Same version of the library is used

## Getting Help

- **Documentation**: See other guides in `/docs/`
- **Examples**: Check `examples/` directory
- **Issues**: https://github.com/redasgard/quantum-shield/issues
- **Email**: hello@redasgard.com

