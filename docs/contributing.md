# Contributing

Thank you for your interest in contributing to Quantum Shield!

## Quick Links

- **GitHub**: https://github.com/redasgard/quantum-shield
- **Issues**: https://github.com/redasgard/quantum-shield/issues
- **Email**: hello@redasgard.com

## Ways to Contribute

### 1. Report Bugs

Found a bug? Please report it:

**Security Bugs:** Email security@redasgard.com (private disclosure)

**Regular Bugs:** Open GitHub issue with:
- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Rust version)
- Code sample if applicable

### 2. Suggest Features

Have an idea? Open an issue with:
- Feature description
- Use case / motivation
- Proposed API (if applicable)
- Willingness to implement

### 3. Improve Documentation

Documentation improvements always welcome:
- Fix typos
- Add examples
- Clarify confusing sections
- Add missing information

### 4. Write Code

Code contributions welcome! See guidelines below.

## Development Setup

### Prerequisites

- Rust 1.70+ (stable)
- Git
- A text editor / IDE

### Clone Repository

```bash
git clone https://github.com/redasgard/quantum-shield.git
cd quantum-shield
```

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Run Examples

```bash
cargo run --example basic_usage
```

## Contribution Guidelines

### Code Style

Follow Rust conventions:
- Use `rustfmt` for formatting
- Use `clippy` for linting
- Follow standard Rust naming conventions

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy -- -D warnings
```

### Commit Messages

Write clear commit messages:

```
Add support for key rotation

- Implement KeyRotation trait
- Add rotate_key() method to HybridCrypto
- Update tests
- Document new API

Fixes #123
```

### Pull Request Process

1. **Fork** the repository
2. **Create** a branch (`git checkout -b feature/my-feature`)
3. **Make** your changes
4. **Test** thoroughly
5. **Commit** with clear messages
6. **Push** to your fork
7. **Open** a pull request

### Pull Request Template

```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes
- List of changes
- Another change

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Code formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] All tests pass (`cargo test`)
```

## Code Guidelines

### Testing

All new code must include tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_feature() {
        let crypto = HybridCrypto::generate_keypair().unwrap();
        // Test code
        assert!(result.is_ok());
    }
}
```

### Documentation

All public APIs must be documented:

```rust
/// Encrypts data using hybrid encryption.
///
/// # Arguments
///
/// * `data` - Data to encrypt
/// * `recipient_keys` - Recipient's public keys
///
/// # Returns
///
/// `Result<HybridCiphertext>` - Encrypted data
///
/// # Example
///
/// ```
/// let encrypted = crypto.encrypt(b"secret", &keys)?;
/// ```
pub fn encrypt(&self, data: &[u8], recipient_keys: &PublicKeys) -> Result<HybridCiphertext> {
    // Implementation
}
```

### Error Handling

Use proper error types:

```rust
// Good
fn my_function() -> Result<T> {
    operation().context("Failed to perform operation")?;
    Ok(result)
}

// Bad
fn my_function() -> T {
    operation().unwrap()
}
```

### Performance

Consider performance implications:
- Minimize allocations
- Avoid unnecessary copies
- Use references where possible
- Profile before optimizing

### Security

Security-critical code requires:
- Clear documentation of security properties
- References to standards/papers
- Constant-time operations where needed
- Input validation

## Architecture

### Module Structure

```
src/
├── lib.rs        # Public API
├── crypto.rs     # HybridCrypto implementation
├── keys.rs       # Key types
├── types.rs      # Ciphertext, Signature types
└── error.rs      # Error types
```

### Adding New Features

1. Discuss in issue first (for major features)
2. Maintain backward compatibility
3. Update documentation
4. Add tests
5. Update CHANGELOG.md

## Testing

### Unit Tests

Test individual functions:

```rust
#[test]
fn test_encryption() {
    let crypto = HybridCrypto::generate_keypair().unwrap();
    let data = b"test";
    let encrypted = crypto.encrypt(data, &crypto.public_keys()).unwrap();
    assert!(encrypted.ciphertext.len() > 0);
}
```

### Integration Tests

Test full workflows:

```rust
#[test]
fn test_full_workflow() {
    let alice = HybridCrypto::generate_keypair().unwrap();
    let bob = HybridCrypto::generate_keypair().unwrap();
    
    let message = b"secret";
    let encrypted = alice.encrypt(message, &bob.public_keys()).unwrap();
    let decrypted = bob.decrypt(&encrypted).unwrap();
    
    assert_eq!(message, &decrypted[..]);
}
```

### Property-Based Tests

Consider using proptest:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_roundtrip(data: Vec<u8>) {
        let crypto = HybridCrypto::generate_keypair()?;
        let encrypted = crypto.encrypt(&data, &crypto.public_keys())?;
        let decrypted = crypto.decrypt(&encrypted)?;
        prop_assert_eq!(data, decrypted);
    }
}
```

## Documentation

### API Documentation

Use rustdoc conventions:

```rust
/// Short description.
///
/// Longer description with details.
///
/// # Arguments
///
/// * `arg1` - Description
///
/// # Returns
///
/// Description of return value
///
/// # Errors
///
/// Description of errors
///
/// # Example
///
/// ```
/// // Example code
/// ```
///
/// # Panics
///
/// When this function panics (if applicable)
///
/// # Safety
///
/// Safety requirements (for unsafe functions)
pub fn my_function(arg1: T) -> Result<U> {
    // Implementation
}
```

### User Documentation

Update `/docs/` when adding features:
- Update relevant guides
- Add new examples
- Update FAQ if needed

## Release Process

Maintainers only:

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Run all tests
4. Create git tag
5. Publish to crates.io
6. Create GitHub release

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all.

### Our Standards

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or insulting comments
- Public or private harassment
- Publishing others' private information

### Enforcement

Violations may result in:
- Warning
- Temporary ban
- Permanent ban

Report violations to: hello@redasgard.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open an issue for questions
- Email hello@redasgard.com
- Check existing documentation

Thank you for contributing to Quantum Shield!

