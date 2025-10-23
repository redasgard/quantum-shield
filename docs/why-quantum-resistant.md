# Why Quantum-Resistant Cryptography?

## The Quantum Threat

### Current State (2025)

Classical cryptography (RSA, ECC) is secure against conventional computers but vulnerable to quantum computers:

- **RSA**: Broken by Shor's algorithm on quantum computers
- **ECC**: Also broken by Shor's algorithm
- **AES**: Weakened by Grover's algorithm (but still secure with larger keys)
- **SHA**: Weakened by Grover's algorithm

### Timeline

| Year | Event | Impact |
|------|-------|--------|
| 1994 | Shor's algorithm published | Theoretical break of RSA/ECC |
| 2016 | NIST PQC competition starts | Standardization begins |
| 2022 | NIST selects winners | Kyber, Dilithium chosen |
| 2024 | FIPS standards published | Official standards released |
| 2030s | Large quantum computers? | Projected timeline |

### Store Now, Decrypt Later

**The Real Threat:** Adversaries are collecting encrypted data today to decrypt when quantum computers become available.

```
Today                          Future (5-10 years)
─────                          ───────────────────
Intercept encrypted data  →    Quantum computer available
Store encrypted data      →    Decrypt with Shor's algorithm
                               Access sensitive information
```

**Impact:** Any data encrypted with RSA/ECC today could be vulnerable in 5-10 years.

## Why Hybrid Cryptography?

### Defense in Depth

Quantum Shield uses **both** classical and post-quantum algorithms:

```
Security = MAX(Classical Security, Post-Quantum Security)
```

**Advantage:**
- ✅ If quantum computers are delayed → Classical crypto provides security
- ✅ If quantum computers arrive early → Post-quantum crypto provides security
- ✅ If PQ algorithms have weaknesses → Classical crypto provides security
- ✅ Best of both worlds → Maximum security guarantee

### Real-World Analogy

Think of it like having two locks on your door:

- **Lock 1 (Classical):** Standard lock, proven for decades, widely trusted
- **Lock 2 (Post-Quantum):** New quantum-resistant lock, future-proof

An attacker must break BOTH locks to gain access. If one lock fails, the other still protects you.

## Why Not Just Post-Quantum?

### Reasons for Hybrid Approach

1. **Maturity**
   - Classical crypto: 40+ years of analysis
   - Post-quantum crypto: < 10 years of analysis

2. **Unknown Weaknesses**
   - New algorithms may have undiscovered vulnerabilities
   - Hybrid approach hedges against this risk

3. **Performance**
   - Classical crypto is still faster for some operations
   - Hybrid balances security and performance

4. **Compatibility**
   - Gradual transition path
   - Works with existing infrastructure

5. **Standards Compliance**
   - Meets both current and future requirements
   - Complies with emerging regulations

## Threat Scenarios

### Scenario 1: Quantum Computer in 2030

**Without Quantum Shield:**
- All RSA/ECC encrypted data from 2025 is vulnerable
- Medical records, financial data, government secrets compromised

**With Quantum Shield:**
- Data protected by Kyber-1024 (quantum-resistant)
- No security breach even with quantum computers

### Scenario 2: PQ Algorithm Weakness Discovered

**Without Classical Layer:**
- All data encrypted with weak PQ algorithm is vulnerable
- Need to re-encrypt everything immediately

**With Quantum Shield:**
- Data still protected by RSA-4096
- Time to transition to new PQ algorithm
- No immediate security breach

### Scenario 3: Both Algorithms Under Attack

**Probability:** Extremely low
- Attacker needs quantum computer AND classical attack
- Must break both layers simultaneously
- Defense in depth provides maximum resilience

## Use Cases Requiring Quantum Resistance

### 1. Long-Term Data Protection

**Examples:**
- Medical records (30+ year retention)
- Financial records (7+ year retention)
- Government archives (permanent retention)
- Legal documents (long-term validity)

**Why:** Data must remain secure beyond quantum computer availability.

### 2. High-Value Targets

**Examples:**
- Military communications
- Trade secrets
- Intellectual property
- Cryptocurrency private keys

**Why:** High-value targets justify "store now, decrypt later" attacks.

### 3. Forward-Thinking Organizations

**Examples:**
- Financial institutions
- Healthcare providers
- Government agencies
- Technology companies

**Why:** Proactive security posture, regulatory compliance, competitive advantage.

### 4. Blockchain and Web3

**Examples:**
- Cryptocurrency wallets
- Smart contract platforms
- Decentralized identity
- NFT authentication

**Why:** Immutable data requires permanent security guarantees.

## Cost of Inaction

### What Happens If You Wait?

1. **Data Exposure**
   - Past encrypted data becomes vulnerable
   - No way to retroactively protect it

2. **Rushed Migration**
   - Forced to migrate quickly when quantum threat is imminent
   - Higher risk of errors and vulnerabilities

3. **Competitive Disadvantage**
   - Late adopters face customer trust issues
   - Regulatory penalties for non-compliance

4. **Higher Costs**
   - Emergency migrations are expensive
   - Data breaches are more expensive

### What Happens If You Act Now?

1. **Future-Proof Security**
   - Data protected against both current and future threats
   - Peace of mind for long-term data retention

2. **Gradual Migration**
   - Time to properly test and deploy
   - Lower risk of implementation issues

3. **Competitive Advantage**
   - Early adopter benefits
   - Customer trust and confidence

4. **Lower Costs**
   - Planned migrations are cheaper
   - Avoid breach costs and penalties

## Industry Adoption

### Who's Already Using PQC?

- **NIST**: Standardized Kyber and Dilithium (2024)
- **Google**: Experimenting with hybrid TLS
- **Cloudflare**: Deployed post-quantum tunnels
- **Apple**: Added PQC to iMessage (2024)
- **Signal**: Implementing PQXDH protocol
- **AWS**: Offering PQC in KMS

### Regulatory Landscape

- **NIST**: Recommends migration by 2030
- **NSA**: CNSA 2.0 requires PQC by 2030 for NSS
- **EU**: Quantum-safe cryptography in cybersecurity strategy
- **ENISA**: Published PQC guidelines

## Migration Path

### Timeline for Adoption

```
Phase 1 (Now - 2026): Early Adoption
├─ High-value data encryption
├─ New systems with PQC
└─ Pilot deployments

Phase 2 (2026 - 2028): Mainstream Adoption
├─ Industry-wide migration begins
├─ Standards mature
└─ Tooling improves

Phase 3 (2028 - 2030): Complete Migration
├─ Legacy system upgrades
├─ Compliance requirements
└─ Universal PQC adoption

Phase 4 (2030+): Post-Quantum Era
├─ Pure PQC systems
├─ Quantum computers available
└─ Classical crypto deprecated
```

### Where You Should Start

1. **Identify Critical Data**
   - What needs long-term protection?
   - What's high-value to attackers?

2. **Assess Current Cryptography**
   - Where do you use RSA/ECC?
   - What's the migration effort?

3. **Plan Migration**
   - Start with new systems
   - Gradually upgrade existing systems
   - Use hybrid approach for transition

4. **Deploy Quantum Shield**
   - Protect new data immediately
   - Migrate existing encrypted data
   - Maintain both layers during transition

## Technical Advantages

### Kyber-1024 (Key Encapsulation)

- **Security Level:** NIST Level 5 (AES-256 equivalent)
- **Based On:** Module-lattice problems (hard for quantum computers)
- **Status:** NIST standardized (FIPS 203)
- **Speed:** Faster than RSA for encryption
- **Key Size:** 1568 bytes public key

### Dilithium5 (Digital Signatures)

- **Security Level:** NIST Level 5 (AES-256 equivalent)
- **Based On:** Module-lattice problems
- **Status:** NIST standardized (FIPS 204)
- **Speed:** Faster than RSA for signing/verification
- **Signature Size:** ~4KB

### Why NIST Level 5?

- **Maximum Security:** Equivalent to AES-256
- **Future-Proof:** Highest security level available
- **Critical Data:** Appropriate for long-term protection
- **Quantum Resistance:** Secure even against large quantum computers

## Conclusion

Quantum-resistant cryptography is not about *if* but *when*. The cost of proactive adoption is far lower than reactive migration under pressure. Quantum Shield provides:

- **Immediate Protection:** Against current and future threats
- **Gradual Migration:** Hybrid approach eases transition
- **Maximum Security:** NIST Level 5, dual-layer protection
- **Future-Proof:** Ready for the post-quantum era

**Start protecting your data today, before quantum computers make it too late.**

## Further Reading

- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Quantum Threat Timeline](https://globalriskinstitute.org/publications/quantum-threat-timeline/)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS_.PDF)
- [Quantum-Shield Architecture](./architecture.md)

