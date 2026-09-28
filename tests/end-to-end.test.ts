import { test, describe } from "node:test";
import * as assert from "node:assert";
import * as crypto from "node:crypto";
import { MunicipalAuthority } from "../src/issuer/authority.js";
import { issueBatchCredentials } from "../src/issuer/batch-issuer.js";
import { CitizenPocketbookEngine } from "../src/pocketbook/pocketbook-engine.js";
import { OfflineVerifierEngine } from "../src/verifier/verifier-engine.js";
import { CLAIM_FLAGS } from "../src/common/types.js";
import { applySignedRevocationManifest } from "../src/revocation/delta-manifest.js";
import {
  VaultAuthError,
  ReplayAttackError,
  SignatureMismatchError,
  RevokedCredentialError,
  LedgerIntegrityError,
} from "../src/common/errors.js";

describe("End-to-End System & Adversarial Attack Simulation", () => {
  const PASIG_LGU_CODE = 137403000;
  const authority = new MunicipalAuthority(PASIG_LGU_CODE, "City of Pasig");

  test("Happy Path: Issuance -> Vault -> Dynamic QR -> Offline Verification", () => {
    // 1. Issue Credential
    const citizenUuid = "0123456789abcdef0123456789abcdef";
    const claims = CLAIM_FLAGS.RESIDENT | CLAIM_FLAGS.SENIOR_CITIZEN | CLAIM_FLAGS.INDIGENT_4PS;
    const cred = authority.issueCredential(citizenUuid, claims);

    // 2. Setup Pocketbook Vault
    const pocketbook = new CitizenPocketbookEngine();
    const pin = "839102";
    const deviceSecret = crypto.randomBytes(32).toString("hex");

    pocketbook.provision(
      {
        masterCredentialRaw: cred.base64Url,
        deviceSecretHex: deviceSecret,
        profileMetadata: {
          fullName: "Maria Clara Santos",
          birthDate: "1960-03-15",
          photoHashSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          registeredAddress: "Pasig Green Park, Pasig City",
        },
      },
      pin
    );

    // 3. Unlock & Generate Dynamic QR
    pocketbook.unlock(pin);
    const presentation = pocketbook.generateDynamicQr();
    assert.ok(presentation.qrString.length <= 185);

    // 4. Verifier Validates Offline
    const verifier = new OfflineVerifierEngine();
    verifier.registerTrustedLgu(PASIG_LGU_CODE, authority.getPublicKey());

    const result = verifier.verify(presentation.qrString);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.citizenPseudonym, citizenUuid);
    assert.strictEqual(result.claims.isResident, true);
    assert.strictEqual(result.claims.isSeniorCitizen, true);
    assert.strictEqual(result.claims.isIndigent4Ps, true);
    assert.strictEqual(result.claims.hasBusinessPermit, false);
    assert.strictEqual(result.chronoColor, presentation.chronoColor);

    // 5. Audit ledger is intact
    assert.strictEqual(verifier.auditLedger.verifyLedgerIntegrity(), true);
  });

  test("Security Vector 1: Vault Brute-Force / Wrong PIN Protection", () => {
    const cred = authority.issueCredential("11112222333344445555666677778888", CLAIM_FLAGS.RESIDENT);
    const pocketbook = new CitizenPocketbookEngine();
    pocketbook.provision(
      {
        masterCredentialRaw: cred.base64Url,
        deviceSecretHex: crypto.randomBytes(32).toString("hex"),
        profileMetadata: {
          fullName: "Test Citizen",
          birthDate: "1990-01-01",
          photoHashSha256: "abc",
          registeredAddress: "Test City",
        },
      },
      "correct-pin-1234"
    );

    assert.throws(() => {
      pocketbook.unlock("wrong-pin-9999");
    }, VaultAuthError);
  });

  test("Security Vector 2: Replay Attack / Screenshot Expiration", () => {
    const cred = authority.issueCredential("22223333444455556666777788889999", CLAIM_FLAGS.RESIDENT);
    const pocketbook = new CitizenPocketbookEngine();
    pocketbook.provision(
      {
        masterCredentialRaw: cred.base64Url,
        deviceSecretHex: crypto.randomBytes(32).toString("hex"),
        profileMetadata: {
          fullName: "Test Citizen",
          birthDate: "1990-01-01",
          photoHashSha256: "abc",
          registeredAddress: "Test City",
        },
      },
      "1234"
    );
    pocketbook.unlock("1234");

    const staleTime = 1700000000;
    const stalePresentation = pocketbook.generateDynamicQr(staleTime);

    const verifier = new OfflineVerifierEngine();
    verifier.registerTrustedLgu(PASIG_LGU_CODE, authority.getPublicKey());

    // Verifier scans 90 seconds after screenshot was taken
    const verifierScanTime = staleTime + 90;
    assert.throws(() => {
      verifier.verify(stalePresentation.qrString, verifierScanTime);
    }, ReplayAttackError);
  });

  test("Security Vector 3: Payload Tampering (Privilege Escalation)", () => {
    const cred = authority.issueCredential("3333444455556666777788889999aaaa", CLAIM_FLAGS.RESIDENT);
    const pocketbook = new CitizenPocketbookEngine();
    pocketbook.provision(
      {
        masterCredentialRaw: cred.base64Url,
        deviceSecretHex: crypto.randomBytes(32).toString("hex"),
        profileMetadata: {
          fullName: "Test Citizen",
          birthDate: "1990-01-01",
          photoHashSha256: "abc",
          registeredAddress: "Test City",
        },
      },
      "1234"
    );
    pocketbook.unlock("1234");
    const presentation = pocketbook.generateDynamicQr();

    // Attacker modifies bytes in the static credential portion of the dynamic QR
    const rawQr = Buffer.from(presentation.qrString, "base64url");
    rawQr[32] |= CLAIM_FLAGS.BUSINESS_PERMIT; // Attempt to illegally grant business permit
    const tamperedQrString = rawQr.toString("base64url");

    const verifier = new OfflineVerifierEngine();
    verifier.registerTrustedLgu(PASIG_LGU_CODE, authority.getPublicKey());

    assert.throws(() => {
      verifier.verify(tamperedQrString);
    }, SignatureMismatchError);
  });

  test("Security Vector 4: Offline Revocation Interception", () => {
    const cred = authority.issueCredential("444455556666777788889999aaaabbbb", CLAIM_FLAGS.RESIDENT);
    const pocketbook = new CitizenPocketbookEngine();
    pocketbook.provision(
      {
        masterCredentialRaw: cred.base64Url,
        deviceSecretHex: crypto.randomBytes(32).toString("hex"),
        profileMetadata: {
          fullName: "Revoked Citizen",
          birthDate: "1985-05-20",
          photoHashSha256: "abc",
          registeredAddress: "Pasig",
        },
      },
      "1234"
    );
    pocketbook.unlock("1234");
    const presentation = pocketbook.generateDynamicQr();

    const verifier = new OfflineVerifierEngine();
    verifier.registerTrustedLgu(PASIG_LGU_CODE, authority.getPublicKey());

    // Authority revokes this citizen
    authority.revokeCredential(cred.citizenIndex);

    // Verifier terminal syncs manifest
    const manifest = authority.exportSignedRevocationManifest();
    applySignedRevocationManifest(
      manifest,
      new Map([[PASIG_LGU_CODE, authority.getPublicKey()]]),
      verifier.getRevocationRegistry(PASIG_LGU_CODE)!
    );

    // Verification must now fail
    assert.throws(() => {
      verifier.verify(presentation.qrString);
    }, RevokedCredentialError);
  });

  test("Security Vector 5: Tamper-Evident Audit Chain Invalidation", () => {
    const verifier = new OfflineVerifierEngine();
    verifier.registerTrustedLgu(PASIG_LGU_CODE, authority.getPublicKey());

    const cred = authority.issueCredential("55556666777788889999aaaabbbbcccc", CLAIM_FLAGS.RESIDENT);
    const pocketbook = new CitizenPocketbookEngine();
    pocketbook.provision(
      {
        masterCredentialRaw: cred.base64Url,
        deviceSecretHex: crypto.randomBytes(32).toString("hex"),
        profileMetadata: {
          fullName: "Audit Subject",
          birthDate: "1990-01-01",
          photoHashSha256: "abc",
          registeredAddress: "Pasig",
        },
      },
      "1234"
    );
    pocketbook.unlock("1234");
    const presentation = pocketbook.generateDynamicQr();

    // Generate 3 verified events
    verifier.verify(presentation.qrString);
    verifier.verify(presentation.qrString);
    verifier.verify(presentation.qrString);

    assert.strictEqual(verifier.auditLedger.verifyLedgerIntegrity(), true);

    // Corrupt record #2 in ledger directly
    const records = verifier.auditLedger.getRecords() as any[];
    records[1].citizenPseudonym = "hacked-pseudonym";

    assert.throws(() => {
      verifier.auditLedger.verifyLedgerIntegrity();
    }, LedgerIntegrityError);
  });

  test("Batch Issuance Engine: Throughput and Consistency", () => {
    const records = Array.from({ length: 100 }, (_, i) => ({
      nationalIdHash: crypto.randomBytes(16).toString("hex"),
      fullName: `Citizen #${i + 1}`,
      claimsMask: CLAIM_FLAGS.RESIDENT | (i % 2 === 0 ? CLAIM_FLAGS.VOTER_ACTIVE : 0),
    }));

    const result = issueBatchCredentials(authority, records);
    assert.strictEqual(result.totalProcessed, 100);
    assert.strictEqual(result.credentials.length, 100);
    assert.ok(result.durationMs < 500, `Batch took ${result.durationMs}ms; expected <500ms`);
  });
});
