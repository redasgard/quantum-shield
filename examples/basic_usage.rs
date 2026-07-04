//! Basic usage example for Quantum Shield.

use quantum_shield::{verify, HybridCrypto, Result};

fn main() -> Result<()> {
    println!("Quantum Shield - Basic Usage Example\n");

    // Step 1: Generate keypairs for Alice and Bob.
    println!("1. Generating keypairs (X25519 + ML-KEM-1024 + Ed25519 + ML-DSA-87)...");
    let alice = HybridCrypto::generate()?;
    let bob = HybridCrypto::generate()?;
    println!("   ✓ Alice and Bob have their keys\n");

    // Step 2: Alice encrypts a message for Bob.
    println!("2. Alice encrypts a message for Bob...");
    let secret_message = b"The package will arrive at midnight";
    let envelope = alice.seal_for(secret_message, bob.public_keys())?;
    let wire = envelope.to_bytes();
    println!("   ✓ Message encrypted");
    println!("   Envelope size: {} bytes\n", wire.len());

    // Step 3: Bob decrypts the message.
    println!("3. Bob decrypts the message...");
    let received = quantum_shield::Envelope::from_bytes(&wire)?;
    let decrypted = bob.open(&received)?;
    println!("   ✓ Message decrypted");
    println!("   Decrypted: {}\n", String::from_utf8_lossy(&decrypted));

    // Step 4: Alice signs a document under a context.
    println!("4. Alice signs a document...");
    let document = b"I agree to the terms and conditions";
    let signature = alice.sign(document, b"contract-signing")?;
    println!(
        "   ✓ Document signed ({} bytes)\n",
        signature.to_bytes().len()
    );

    // Step 5: Bob verifies Alice's signature.
    println!("5. Bob verifies Alice's signature...");
    verify(
        document,
        b"contract-signing",
        &signature,
        alice.public_keys(),
    )?;
    println!("   ✓ Signature verified (Ed25519 AND ML-DSA-87)\n");

    // Step 6: Export public keys for sharing.
    println!("6. Exporting public keys...");
    let alice_pub = alice.public_keys().to_bytes();
    println!(
        "   ✓ Public key bundle exported ({} bytes)",
        alice_pub.len()
    );

    println!("\nDemo complete!");
    Ok(())
}
