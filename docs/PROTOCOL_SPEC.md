# Binary Protocol & Wire Specification
## Municipal Offline Identity Pocketbook (LGU e-ID)
### Bayan ng Tanza, Lalawigan ng Cavite (PSGC: `042120000`)

---

## 1. Canonical Static Credential (Exact 97 Bytes)

The static municipal identity credential is encoded in strict Big-Endian (Network Byte Order) binary format. Total binary payload length is invariant at **97 Bytes**.

```
+--------+--------+--------+--------------------+--------------------+--------------------+
| Offset | Length | Type   | Field Name         | Value / Format     | Description        |
+--------+--------+--------+--------------------+--------------------+--------------------+
| 0x00   | 2      | UInt16 | Magic Header       | 0x4C47 (ASCII "LG")| Protocol Identifier|
| 0x02   | 1      | UInt8  | Protocol Version   | 0x01               | Schema Version     |
| 0x03   | 4      | UInt32 | Issuer LGU Code    | 0x0282B400         | Tanza PSGC Code    |
| 0x07   | 16     | Bytes  | Citizen Pseudonym  | 16 raw bytes       | Anonymous UUID     |
| 0x17   | 4      | UInt32 | Issued Timestamp   | Unix Epoch Seconds | Issuance Date      |
| 0x1B   | 4      | UInt32 | Expiry Timestamp   | Unix Epoch Seconds | Expiration Date    |
| 0x1F   | 2      | UInt16 | Entitlement Claims | 16-bit Bitmask     | Civic Privileges   |
+--------+--------+--------+--------------------+--------------------+--------------------+
| 0x21   | 64     | Bytes  | Ed25519 Signature  | 64 raw bytes (R, S)| LGU Authority Sig  |
+--------+--------+--------+--------------------+--------------------+--------------------+
Total Length: 33 Bytes (Header Payload) + 64 Bytes (Digital Signature) = 97 Bytes
```

### Claim Bitmask Flags (`UInt16`)

Entitlements are encoded as bit flags within offsets `0x1F..0x20`:

| Bit Position | Hex Value | Decimal | Entitlement Meaning |
| :--- | :--- | :--- | :--- |
| **Bit 0** | `0x0001` | 1 | **Bonafide Resident** (Barangay Registry Verified) |
| **Bit 1** | `0x0002` | 2 | **Senior Citizen** (OSCA 20% Privilege & Social Pension) |
| **Bit 2** | `0x0004` | 4 | **Indigent / 4Ps Beneficiary** (DSWD Pantawid Pamilya) |
| **Bit 3** | `0x0008` | 8 | **Business Permit Holder** (Local Taxpayer / Merchant) |
| **Bit 4** | `0x0010` | 16 | **Person with Disability (PWD)** (Mandated 20% Privilege) |
| **Bit 5** | `0x0020` | 32 | **Solo Parent** (RA 8972 Registered Beneficiary) |
| **Bit 6** | `0x0040` | 64 | **Active Registered Voter** (Local COMELEC Registry) |
| **Bit 7** | `0x0080` | 128 | **Emergency First Responder** (Accredited MDRRMO / Tanod) |
| **Bits 8-15**| - | - | *Reserved for Future Expansion* |

---

## 2. Dynamic Ephemeral QR Envelope (Exact 137 Bytes)

The dynamic presentation extends the static 97-byte credential with anti-replay and device binding fields:

```
+--------+--------+--------+--------------------+--------------------+--------------------+
| Offset | Length | Type   | Field Name         | Value / Format     | Description        |
+--------+--------+--------+--------------------+--------------------+--------------------+
| 0x00   | 97     | Bytes  | Static Credential  | Raw 97-byte buffer | Canonical ID       |
| 0x61   | 4      | UInt32 | Client Timestamp   | Unix Epoch Seconds | Anti-Replay Clock  |
| 0x65   | 4      | UInt32 | Temporal Step      | floor(time / 60)   | 60-Second Window   |
| 0x69   | 32     | Bytes  | Device Auth Tag    | HMAC-SHA256        | Enclave Binding    |
+--------+--------+--------+--------------------+--------------------+--------------------+
Total Length: 97 Bytes (Static) + 40 Bytes (Dynamic Envelope) = 137 Bytes
Base64URL Length: 183 Characters
```

---

## 3. Privacy-Preserving Selective Disclosure Voucher (Exact 99 Bytes)

Sub-credentials generated for specific merchants, pharmacies, or relief centers disclose only the relevant entitlement while suppressing all other data:

```
+--------+--------+--------+--------------------+--------------------+--------------------+
| Offset | Length | Type   | Field Name         | Value / Format     | Description        |
+--------+--------+--------+--------------------+--------------------+--------------------+
| 0x00   | 2      | UInt16 | Voucher Magic      | 0x5456 (ASCII "TV")| Tanza Voucher      |
| 0x02   | 1      | UInt8  | Version            | 0x01               | Sub-schema Version |
| 0x03   | 4      | UInt32 | Issuer LGU Code    | 0x0282B400         | Tanza PSGC         |
| 0x07   | 16     | Bytes  | Citizen Pseudonym  | 16 raw bytes       | Anonymous Subject  |
| 0x17   | 4      | UInt32 | Expiry Timestamp   | Unix Epoch Seconds | 1-Hour Ephemeral   |
| 0x1B   | 2      | UInt16 | Disclosed Claims   | Filtered Bitmask   | Single Claim Mask  |
| 0x1D   | 2      | UInt16 | Purpose Code       | Purpose Enum       | Authorized Context |
| 0x1F   | 4      | UInt32 | Nonce              | Random uint32      | Replay Prevention  |
+--------+--------+--------+--------------------+--------------------+--------------------+
| 0x23   | 64     | Bytes  | Ed25519 Signature  | 64 raw bytes       | Authority Sub-Sig  |
+--------+--------+--------+--------------------+--------------------+--------------------+
Total Length: 35 Bytes (Header) + 64 Bytes (Signature) = 99 Bytes
Base64URL Length: 132 Characters
```

### Voucher Purpose Codes

| Code (`UInt16`) | Identifier | Intended Context | Disclosed Claim |
| :--- | :--- | :--- | :--- |
| `0x0001` | `SENIOR_MEDICINE` | OSCA Pharmacy 20% Discount | Senior Citizen (`0x0002`) |
| `0x0002` | `RICE_AYUDA` | MSWDO Calamity Food Distribution | Indigent 4Ps (`0x0004`) |
| `0x0003` | `CALAMITY_RELIEF` | Lingap Tanza Health Emergency | Bonafide Resident (`0x0001`) |
| `0x0004` | `BURIAL_ASSISTANCE` | Civil Welfare Support | Resident / 4Ps |
| `0x0005` | `EDUCATIONAL_AID` | Municipal Scholarship Grant | Voter / Resident |

---

## 4. Optical Mesh Relay Frame Format (Variable Length, $\le 154$ Bytes)

Chunked framing for zero-cable camera streaming:

```
+--------+--------+--------+--------------------+--------------------+--------------------+
| Offset | Length | Type   | Field Name         | Value / Format     | Description        |
+--------+--------+--------+--------------------+--------------------+--------------------+
| 0x00   | 2      | UInt16 | Relay Magic        | 0x5152 (ASCII "QR")| Optical Frame      |
| 0x02   | 4      | UInt32 | Session Nonce      | Random uint32      | Transmission ID    |
| 0x06   | 2      | UInt16 | Sequence Index     | 0 to N-1           | Chunk Position     |
| 0x08   | 2      | UInt16 | Total Chunks       | N                  | Frame Count        |
| 0x0A   | 4      | UInt32 | Chunk CRC-32       | IEEE 802.3 CRC-32  | Integrity Check    |
+--------+--------+--------+--------------------+--------------------+--------------------+
| 0x0E   | $\le 140$| Bytes  | Chunk Data Slice   | Raw Payload Bytes  | Sliced Data        |
+--------+--------+--------+--------------------+--------------------+--------------------+
Header Size: 14 Bytes | Max Total Frame: 154 Bytes
```
