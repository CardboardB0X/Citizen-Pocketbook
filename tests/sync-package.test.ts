import { test, describe } from "node:test";
import * as assert from "node:assert";
import * as crypto from "node:crypto";
import { exportEncryptedAuditLogs, importEncryptedAuditLogs } from "../src/sync/sync-package.js";
import type { AuditRecord } from "../src/common/types.js";
import { CorruptedPayloadError } from "../src/common/errors.js";

describe("Track D: Air-Gapped USB Sync Package Security", () => {
  const syncSecret = crypto.randomBytes(32);
  const sampleRecords: AuditRecord[] = [
    {
      id: "REC-1-test",
      timestamp: 1700000000,
      issuerLguCode: 42120000,
      citizenPseudonym: "e04b82d7a22f4b7da3c59a0f7e812d44",
      claimsMask: 71,
      status: "VERIFIED",
      previousHash: "0000000000000000000000000000000000000000000000000000000000000000",
      recordHash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    },
    {
      id: "REC-2-test",
      timestamp: 1700000060,
      issuerLguCode: 42120000,
      citizenPseudonym: "11112222333344445555666677778888",
      claimsMask: 1,
      status: "REJECTED",
      rejectionReason: "REPLAY_ATTACK_DETECTED",
      previousHash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
      recordHash: "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
    },
  ];

  test("Should export and import encrypted audit packages with zero data loss", () => {
    const pkg = exportEncryptedAuditLogs("TERM-TANZA-001", sampleRecords, syncSecret);
    assert.ok(pkg.length > 92);

    const restored = importEncryptedAuditLogs(pkg, syncSecret);
    assert.strictEqual(restored.length, 2);
    assert.strictEqual(restored[0].id, "REC-1-test");
    assert.strictEqual(restored[1].status, "REJECTED");
    assert.strictEqual(restored[1].rejectionReason, "REPLAY_ATTACK_DETECTED");
  });

  test("Should reject tampered audit package bytes", () => {
    const pkg = exportEncryptedAuditLogs("TERM-TANZA-001", sampleRecords, syncSecret);

    // Tamper with ciphertext byte
    pkg[pkg.length - 5] ^= 0xff;

    assert.throws(() => {
      importEncryptedAuditLogs(pkg, syncSecret);
    }, CorruptedPayloadError);
  });

  test("Should reject package decrypted with wrong municipal sync key", () => {
    const pkg = exportEncryptedAuditLogs("TERM-TANZA-001", sampleRecords, syncSecret);
    const wrongKey = crypto.randomBytes(32);

    assert.throws(() => {
      importEncryptedAuditLogs(pkg, wrongKey);
    }, CorruptedPayloadError);
  });
});
