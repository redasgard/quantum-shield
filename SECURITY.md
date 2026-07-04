# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | ✅ |
| 0.1.x   | ❌ — cryptographically broken by design, upgrade immediately (see [docs/migration-v1-to-v2.md](docs/migration-v1-to-v2.md)) |

## Known limitations

- This library and the underlying `ml-kem`/`ml-dsa` crates have **not been
  independently audited**.
- The library implements FIPS 203/204 algorithms but is **not
  FIPS-validated**.
- The threat model, including explicitly unaddressed threats (side channels
  beyond best-effort constant time, replay, forward secrecy for static
  recipient keys), is documented in
  [docs/security-model.md](docs/security-model.md).

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub
issues.** Email:

**security@redasgard.com**

Include a description, reproduction steps, impact assessment, environment
(OS, Rust version), and a proof of concept if possible.

### What to expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Fix development in private**, coordinated disclosure with the reporter,
  and credit in the advisory if desired
- Advisories are published via
  [GitHub Security Advisories](https://github.com/redasgard/quantum-shield/security/advisories)
  and RustSec where applicable

### Scope

In scope: the hybrid constructions and wire formats specified in
[docs/design.md](docs/design.md), key handling/zeroization, parsing of
attacker-controlled input, decryption/verification oracles, resource
exhaustion in this crate's code.

Out of scope: vulnerabilities in dependencies (report upstream — we will
still ship version bumps), attacks on the underlying algorithms themselves,
issues in applications using this library, social engineering, physical
attacks.

By reporting in good faith you agree to coordinated disclosure; we will not
pursue legal action against good-faith research.
