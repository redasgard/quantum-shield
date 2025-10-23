//! Basic usage example for Quantum Shield

use quantum_shield::{HybridCrypto, Result};

fn main() -> Result<()> {
    println!("Quantum Shield - Basic Usage Example\n");

    // Step 1: Generate keypairs for Alice and Bob
    println!("1. Generating keypairs...");
    let alice = HybridCrypto::generate_keypair()?;
    let bob = HybridCrypto::generate_keypair()?;
    println!("   ✓ Alice and Bob have their keys\n");

    // Step 2: Alice encrypts a message for Bob
    println!("2. Alice encrypts a message for Bob...");
    let secret_message = b"The package will arrive at midnight";
    
    let encrypted = alice.encrypt(secret_message, &bob.public_keys())?;
    println!("   ✓ Message encrypted");
    println!("   Algorithm: {}", encrypted.algorithm);
    println!("   Ciphertext size: {} bytes\n", encrypted.ciphertext.len());

    // Step 3: Bob decrypts the message
    println!("3. Bob decrypts the message...");
    let decrypted = bob.decrypt(&encrypted)?;
    println!("   ✓ Message decrypted");
    println!("   Decrypted: {}\n", String::from_utf8_lossy(&decrypted));

    // Step 4: Alice signs a document
    println!("4. Alice signs a document...");
    let document = b"I agree to the terms and conditions";
    
    let signature = alice.sign(document)?;
    println!("   ✓ Document signed");
    println!("   Quantum-resistant: {}\n", signature.is_quantum_resistant());

    // Step 5: Bob verifies Alice's signature
    println!("5. Bob verifies Alice's signature...");
    let valid = HybridCrypto::verify(document, &signature, &alice.public_keys())?;
    println!("   ✓ Signature verified: {}\n", valid);

    // Step 6: Export public keys for sharing
    println!("6. Exporting public keys...");
    let alice_pubkeys_json = alice.public_keys().to_json()?;
    println!("   ✓ Public keys exported ({} bytes)", alice_pubkeys_json.len());
    
    println!("\nDemo complete!");
    println!("\nSecurity: NIST Level 5");
    println!("   - Resistant to quantum attacks");
    println!("   - Maintains classical security");
    println!("   - Automatic failover on decryption");

    Ok(())
}

