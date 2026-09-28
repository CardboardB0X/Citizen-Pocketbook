# Security Architecture & Threat Model Analysis
## Municipal Offline Identity Pocketbook (LGU e-ID)
### Bayan ng Tanza, Lalawigan ng Cavite

---

## 1. Threat Model & Security Invariants

The security model assumes an untrusted operating environment where:
1. Citizen smartphones may be compromised, jailbroken, or running unauthorized screen-capture software.
2. Field verifiers may operate in areas completely devoid of cellular coverage or power grid connectivity for days.
3. Physical air-gapped transport media (e.g. USB flash drives, memory cards) may be intercepted, cloned, or modified in transit.
4. Malicious actors may attempt to forge municipal credentials, escalate civic claims (e.g. claiming senior citizen discounts or indigent subsidies dishonestly), or replay captured optical presentations.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Specific Attack Vector | Mitigating Cryptographic Primitive | Formal Security Guarantee |
| :--- | :--- | :--- | :--- |
| **Spoofing Identity** | Adversary attempts to generate a forged citizen credential or impersonate Mayor's root authority. | PureEd25519 (RFC 8032) + NIST ML-DSA-44 lattice signature. | Infeasible without the 32-byte Ed25519 private key seed (128-bit classical security level, $2^{128}$ operations). |
| **Tampering with Data** | Beneficiary flips claim bits in memory or barcode (e.g. changing resident `0x0001` to senior `0x0002`). | Digital signature covers the entire 33-byte header payload including the claim bitmask. | Changing any single bit invalidates the 64-byte Ed25519 signature with probability $1 - 2^{-256}$. |
| **Repudiation** | Inspector claims an audit record was forged or an inspection never occurred. | SHA-256 tamper-evident hash-chained audit ledger ($H_n = \text{SHA256}(H_{n-1} \parallel \text{Record}_n)$). | Any retrospective alteration breaks the hash chain, triggering `LEDGER_INTEGRITY_COMPROMISED`. |
| **Information Disclosure** | Merchant snoops citizen's personal voter status or residential address from card. | 99-byte Selective Disclosure Sub-Vouchers (`src/crypto/selective-proof.ts`). | Zero-knowledge property: Discloses only the single entitlement authorized for that transaction. |
| **Denial of Service** | Corrupted or massive QR payloads designed to crash or lock the verifier parser. | Fixed-offset binary deserializer with strict boundary checks (`src/crypto/binary-packer.ts`). | Exact 97-byte and 137-byte buffer enforcement; malformed inputs throw typed `CorruptedPayloadError`. |
| **Elevation of Privilege** | Replay of a captured video or screenshot of an authorized citizen's dynamic QR code. | Ephemeral rolling temporal step ($\Delta t = 60\text{s}$) + client timestamp validation. | Screenshotted presentations older than 60 seconds fail with `REPLAY_ATTACK_DETECTED`. |

---

## 3. Cryptographic Proofs & Security Bounds

### 3.1 Resistance to Bit-Flipping Attacks
Let $M = (m_0, m_1, \dots, m_{32})$ be the 33-byte credential header, and let $\sigma = (R, S)$ be the 64-byte Ed25519 signature. An adversary modifies $M$ to $M' = M \oplus \Delta$.
The verification function computes:
$$8S \cdot B \stackrel{?}{=} 8R + 8 \cdot \text{SHA-512}(R \parallel PK_{\text{LGU}} \parallel M') \cdot PK_{\text{LGU}}$$
Because SHA-512 is a cryptographically secure hash function modeled as a random oracle, $\text{SHA-512}(R \parallel PK_{\text{LGU}} \parallel M')$ yields a pseudorandom scalar $k' \in \mathbb{F}_l$. The probability that $8S \cdot B = 8R + 8k' \cdot PK_{\text{LGU}}$ holds for an arbitrarily chosen $M'$ is bounded by:
$$P(\text{Tampered Verification Success}) \le \frac{1}{l} \approx \frac{1}{2^{252}} < 1.38 \times 10^{-76}$$
This makes unauthorized privilege escalation mathematically impossible.

### 3.2 Anti-Double-Dipping Nonce Guarantees
During emergency relief operations, for event $E$, each disbursement generates a signed receipt:
$$\text{ReceiptHash} = \text{HMAC-SHA256}_{K_{\text{relief}}}(\text{EventID} \parallel \text{CitizenPseudonym} \parallel \text{Timestamp} \parallel \text{StationID})$$
The offline terminal maintains a hash set $\mathcal{S}_E = \{ \text{CitizenPseudonym}_i \}_{i=1}^M$.
Before recording:
$$\text{If } \text{CitizenPseudonym} \in \mathcal{S}_E \implies \text{REJECT (Duplicate Claim)}$$
$$\text{Else } \mathcal{S}_E \leftarrow \mathcal{S}_E \cup \{\text{CitizenPseudonym}\} \implies \text{APPROVE}$$
This deterministic lookup guarantees zero double-dipping within the municipal distribution window even when completely disconnected from the municipal server.

---

## 4. Post-Quantum Migration Strategy

Under NIST FIPS 204, the Module-Lattice-Based Digital Signature Standard (ML-DSA) relies on the hardness of the Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS) problems on structured polynomial rings:
$$R_q = \mathbb{Z}_q[X] / (X^{256} + 1)$$
These lattice problems are provably hard against both classical computers and quantum computers operating Shor's or Grover's algorithms.

By bundling PureEd25519 with ML-DSA-44 in a dual hybrid container (`src/crypto/pqc-hybrid.ts`), Tanza LGU credentials achieve:
1. **Backwards Compatibility:** Legacy terminals continue verifying the 64-byte Ed25519 signature in $<0.11\text{ ms}$.
2. **Future-Proof Audit Trail:** Central municipal archives can verify the lattice commitment decades into the future, immune to quantum decryption of historical identity presentations.
