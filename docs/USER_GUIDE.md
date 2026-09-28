# Operator & User Manual
## Municipal Offline Identity Pocketbook (LGU e-ID)
### Bayan ng Tanza, Lalawigan ng Cavite

---

## 1. Citizen User Guide: Mobile Pocketbook (`/client`)

### 1.1 First Launch & Unlocking
1. Open `http://localhost:3000/client` on any modern smartphone browser (Chrome, Safari, Edge, Firefox).
2. To install as a native offline app, tap **"Add to Home Screen"** or the browser's install prompt. The Cache-First Service Worker allows the app to launch even when the phone is in Airplane Mode.
3. **Unlocking Your Identity:**
   * **Biometric Passkey (Fastest):** Tap **"Unlock with Biometrics (Passkey)"**. Touch your fingerprint scanner, Face ID, or Windows Hello.
   * **PIN Fallback:** Enter your 6-digit Municipal PIN (default demo PIN: `123456`).

### 1.2 Using Your Digital e-ID
* **3D Interactive Card:** Tap the card to flip it and view your cryptographic credentials, issuing authority, and cryptographic signature hash.
* **Rolling Dynamic QR:** The dynamic QR code in the center refreshes automatically.
  * The countdown bar displays the seconds remaining in the current 60-second window.
  * The outer halo ring pulses with the active **Chrono-Color** (e.g., `#006C4C` Emerald, `#D97706` Amber).
* **Fullscreen Optical Mode:** Tap **"Present Fullscreen QR"** to enlarge the QR code for handheld readers in direct sunlight.

### 1.3 Generating Privacy-Preserving Selective Vouchers
When presenting your ID at a private drugstore or calamity tent, you can hide your personal address and voter status:
1. Tap the **"Benefits"** tab in the bottom dock.
2. Select your entitlement:
   * **Senior Citizen Medicine:** Generates an OSCA 20% discount sub-voucher.
   * **DSWD 4Ps Rice Subsidy:** Discloses indigent benefit status for food aid.
   * **Lingap Tanza Health:** Discloses bonafide residency for municipal clinic privileges.
3. Present the resulting sub-voucher QR to the merchant.

---

## 2. Municipal Administrator Guide: Civil Registrar Portal (`/admin`)

### 2.1 Citizen Registration & Card Issuance
1. Open `http://localhost:3000/admin` on an authorized municipal workstation.
2. Select **"Enroll Citizen"** from the left navigation rail.
3. Fill in the citizen's legal details:
   * **Full Legal Name** (Last, First, Middle)
   * **Date of Birth**
   * **Barangay** (Choose from Tanza's 41 official barangays: Daang Amaya, Amaya, Julugan, Biwas, Bucal, etc.)
4. Toggle the applicable **Civic Entitlements & Privileges** chips (Senior, 4Ps, PWD, Solo Parent, Active Voter).
5. Click **"Issue Cryptographic Credential"**. The system generates a 97-byte PureEd25519 signed credential and computes an anonymous 16-byte citizen pseudonym.

### 2.2 Generating Printable Physical PVC / Paper e-IDs
For elderly citizens or residents without smartphones:
1. Select **"Printable e-ID"** in the sidebar.
2. Verify the preview card displays the official Tanza municipal crest, security guilloche pattern, and high-density 97-byte static QR.
3. Click **"Print Official e-ID Card"** to send the layout directly to the municipal PVC card printer or laminator.

### 2.3 Revoking a Lost, Stolen, or Ineligible Card
1. Navigate to **"Revocation Registry"**.
2. Search for the citizen's name or registry index.
3. Click **"Revoke"**. The system instantly sets the revocation bit in the 122KB municipal bitmap, exports a new signed delta manifest, and pushes it to local verifier caches.

---

## 3. Field Inspector & Checkpoint Operator Guide (`/terminal`)

### 3.1 Operating the Handheld Terminal
1. Open `http://localhost:3000/terminal` on a rugged handheld scanner, tablet, or smartphone.
2. **Camera Viewfinder:** Tap **"Open Camera"** to enable real-time WebRTC optical barcode detection. Point the crosshairs at the citizen's QR code.
3. **Instant Demo Scan:** Click **"Instant Scan"** to simulate reading the active citizen pocketbook payload in $< 0.12\text{ ms}$.

### 3.2 Interpreting Verification Verdicts
* **Green Panel (`✓ VERIFIED`):** Credential is mathematically authentic, unexpired, and active in the revocation registry.
* **Audio Voice Output:** When voice synthesis is enabled, the terminal speaks:
  * English: *"Tanza Verified Resident: Senior Citizen privilege approved."*
  * Tagalog: *"Beripikadong Mamamayan ng Tanza: Pribilehiyo para sa Senior Citizen ay aprubado."*
* **Chrono-Color Synchronization:** Confirm that the color displayed on the terminal HUD matches the colored halo ring on the citizen's smartphone.
* **Red Panel (`✗ REJECTED`):**
  * `REPLAY_ATTACK_DETECTED`: Screenshot or expired QR presentation.
  * `REVOKED_CREDENTIAL`: Card reported lost or cancelled in municipal registry.
  * `SIGNATURE_MISMATCH`: Forged or tampered claim bitmask.

---

## 4. Disaster Relief & Ayuda Teams Guide (Lingap Tanza Mode)

1. On the inspector terminal, tap **"Ayuda Mode: OFF"** to toggle it to **"Ayuda Mode: ACTIVE"**.
2. The terminal switches into the **Emergency Relief & Subsidy Distribution** workflow.
3. When scanning each evacuee:
   * **First-Time Legitimate Claim:** Displays a gold voucher badge, logs the disbursement to the audit trail, prints a unique receipt ID (e.g. `RCPT-7F2A`), and announces: *"Relief approved: 25kg Rice Pack disbursed."*
   * **Duplicate Attempt ("Double-Dipping"):** Rejects immediately with a loud red alert and voice warning: *"Alert: Relief package already claimed by this citizen."*
4. All claims are stored in the tamper-evident offline ledger for evening reconciliation.

---

## 5. Air-Gapped Station Operator Guide (`/sync`)

### 5.1 End-of-Day USB Synchronization
1. At the checkpoint, connect an authorized municipal USB flash drive.
2. Open `http://localhost:3000/sync`.
3. Click **"Download tanza_audit_2026.enc"** to export all local scan and aid receipts encrypted with AES-256-GCM.
4. Deliver the USB flash drive to Tanza Municipal Hall for central database ingestion.

### 5.2 Zero-Cable Optical Mesh Sync (Camera Beaming)
When synchronizing outposts without USB drives:
1. On the supervisor's tablet, click **"Start Optical QR Beam"**.
2. The screen displays an animated stream of QR frames cycling at ~3 FPS.
3. Field inspectors point their terminal cameras at the supervisor's screen.
4. The terminal automatically ingests the frames, reconstructs the signed delta manifest, and updates the local revocation list with zero cables and zero Wi-Fi!
