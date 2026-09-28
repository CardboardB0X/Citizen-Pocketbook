import * as crypto from "node:crypto";
import { MunicipalAuthority } from "./issuer/authority.js";
import { CitizenPocketbookEngine } from "./pocketbook/pocketbook-engine.js";
import { OfflineVerifierEngine } from "./verifier/verifier-engine.js";
import { CLAIM_FLAGS } from "./common/types.js";
import { applySignedRevocationManifest } from "./revocation/delta-manifest.js";

// Export all modules for library usage
export * from "./common/types.js";
export * from "./common/errors.js";
export * from "./crypto/binary-packer.js";
export * from "./crypto/ed25519.js";
export * from "./crypto/dynamic-qr.js";
export * from "./revocation/bitmap-registry.js";
export * from "./revocation/delta-manifest.js";
export * from "./pocketbook/encrypted-vault.js";
export * from "./pocketbook/pocketbook-engine.js";
export * from "./verifier/audit-log.js";
export * from "./verifier/verifier-engine.js";
export * from "./issuer/authority.js";
export * from "./issuer/batch-issuer.js";
export * from "./crypto/selective-proof.js";
export * from "./crypto/biometric-template.js";
export * from "./crypto/pqc-hybrid.js";
export * from "./sync/sync-package.js";
export * from "./sync/qr-mesh-relay.js";
export * from "./verifier/ayuda-tracker.js";

/**
 * End-to-end demonstration when executed directly.
 */
function runDemo(): void {
  console.log("========================================================================");
  console.log("  MUNICIPAL OFFLINE IDENTITY POCKETBOOK (LGU e-ID) - END-TO-END DEMO");
  console.log("========================================================================\n");

  // 1. Initialize Municipal Authority (Tanza, Cavite, PSGC: 042120000)
  const TANZA_LGU_CODE = 42120000;
  const tanzaAuthority = new MunicipalAuthority(TANZA_LGU_CODE, "Municipality of Tanza, Cavite");
  console.log(`[1] Initialized Root Authority for: ${tanzaAuthority.municipalityName} (Code: ${TANZA_LGU_CODE})`);
  console.log(`    Authority Ed25519 Public Key: ${tanzaAuthority.getRawPublicKey().toString("hex").substring(0, 32)}...`);

  // 2. Provision Citizen Identity Credential
  const citizenUuid = "e04b82d7a22f4b7da3c59a0f7e812d44";
  const citizenClaims =
    CLAIM_FLAGS.RESIDENT |
    CLAIM_FLAGS.SENIOR_CITIZEN |
    CLAIM_FLAGS.INDIGENT_4PS |
    CLAIM_FLAGS.VOTER_ACTIVE;

  const issued = tanzaAuthority.issueCredential(citizenUuid, citizenClaims);
  console.log(`\n[2] Credential Issued for Citizen: ${issued.citizenPseudonym}`);
  console.log(`    Binary Raw Size: ${issued.rawBuffer.length} Bytes`);
  console.log(`    Base64URL Representation: ${issued.base64Url}`);
  console.log(`    Citizen Revocation Index: #${issued.citizenIndex}`);

  // 3. Setup Citizen Mobile Pocketbook
  const pocketbook = new CitizenPocketbookEngine();
  const deviceSecretHex = crypto.randomBytes(32).toString("hex");
  const citizenPin = "749201";

  pocketbook.provision(
    {
      masterCredentialRaw: issued.base64Url,
      deviceSecretHex,
      profileMetadata: {
        fullName: "Juan Dela Cruz",
        birthDate: "1958-06-12",
        photoHashSha256: crypto.createHash("sha256").update("citizen_photo").digest("hex"),
        registeredAddress: "Barangay Daang Amaya II, Tanza, Cavite",
      },
    },
    citizenPin
  );
  console.log("\n[3] Citizen Mobile Pocketbook Provisioned & Encrypted (AES-256-GCM)");

  // Unlock and generate dynamic QR
  pocketbook.unlock(citizenPin);
  const presentation = pocketbook.generateDynamicQr();
  console.log(`    Dynamic QR Payload: ${presentation.qrString}`);
  console.log(`    QR Length: ${presentation.qrString.length} chars (Target <= 300)`);
  console.log(`    Dynamic Chrono-Color: ${presentation.chronoColor}`);
  console.log(`    Time Left in Epoch Window: ${presentation.secondsRemainingInWindow}s`);

  // 4. Initialize Field Verifier Terminal (100% Offline)
  const verifier = new OfflineVerifierEngine();
  verifier.registerTrustedLgu(TANZA_LGU_CODE, tanzaAuthority.getPublicKey());
  console.log("\n[4] Offline Verifier Terminal Initialized with Tanza Trust Anchor");

  // Verify dynamic QR
  const result = verifier.verify(presentation.qrString);
  console.log("\n[5] Offline Verification Result:");
  console.log(`    Status: ${result.valid ? "VERIFIED (AUTHENTIC)" : "REJECTED"}`);
  console.log(`    Citizen Pseudonym: ${result.citizenPseudonym}`);
  console.log(`    Eligibility Claims:`, result.claims);
  console.log(`    Chrono-Color Match: ${result.chronoColor === presentation.chronoColor ? "MATCHED" : "MISMATCH"}`);
  console.log(`    Audit Record Hash: ${result.auditRecordHash.substring(0, 32)}...`);

  // 5. Test Revocation Flow
  console.log("\n[6] Testing Offline Revocation Workflow:");
  tanzaAuthority.revokeCredential(issued.citizenIndex);
  console.log(`    Authority marked Citizen Index #${issued.citizenIndex} as REVOKED.`);

  // Export and import signed revocation manifest
  const manifestBuffer = tanzaAuthority.exportSignedRevocationManifest();
  console.log(`    Exported Signed Revocation Delta Manifest: ${manifestBuffer.length} Bytes`);

  const manifestMeta = applySignedRevocationManifest(
    manifestBuffer,
    new Map([[TANZA_LGU_CODE, tanzaAuthority.getPublicKey()]]),
    verifier.getRevocationRegistry(TANZA_LGU_CODE)!
  );
  console.log(`    Applied to Verifier Cache. Total Revoked Entries in Registry: ${manifestMeta.revokedEntriesCount}`);

  // Re-verify: must fail with REVOKED_CREDENTIAL
  try {
    verifier.verify(presentation.qrString);
    console.error("    FAIL: Revoked credential was accepted!");
  } catch (err: any) {
    console.log(`    PASS: Verification successfully rejected -> ${err.message}`);
  }

  // 6. Verify Tamper-Evident Audit Ledger Integrity
  console.log("\n[7] Verifying Audit Ledger Cryptographic Integrity:");
  console.log(`    Total Audit Log Records: ${verifier.auditLedger.size()}`);
  const isLedgerIntact = verifier.auditLedger.verifyLedgerIntegrity();
  console.log(`    Ledger Hash Chain Verification: ${isLedgerIntact ? "PASSED (100% INTACT)" : "FAILED"}`);

  console.log("\n========================================================================");
  console.log("  ALL DEMO VERIFICATION STEPS EXECUTED SUCCESSFULLY");
  console.log("========================================================================");
}

import { pathToFileURL } from "node:url";
import * as path from "node:path";

// Auto-run when file is executed directly
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  runDemo();
}

