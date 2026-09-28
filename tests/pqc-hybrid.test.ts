import { test, describe } from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";
import {
  generateHybridKeyPair,
  signHybrid,
  verifyHybrid,
  PQC_CONSTANTS,
} from "../src/crypto/pqc-hybrid.js";

describe("Track F: Post-Quantum Cryptography Hybrid Defense (Ed25519 + ML-DSA)", () => {
  const testPayload = Buffer.from("Bayan ng Tanza - Lingap Calamity Relief Entitlement Authorization 2026", "utf-8");

  test("Should generate valid hybrid keypair with expected parameter byte sizes", () => {
    const keys = generateHybridKeyPair();
    assert.strictEqual(keys.classicalPublicKey.length, 32, "Classical Ed25519 key must be 32 bytes");
    assert.strictEqual(keys.pqcPublicKey.length, PQC_CONSTANTS.ML_DSA_44_PUBKEY_SIZE, "ML-DSA-44 public key must be 1312 bytes");
  });

  test("Should sign payload and verify both classical and post-quantum layers", () => {
    const keys = generateHybridKeyPair();
    const hybridSig = signHybrid(testPayload, keys);

    const expectedTotalSize = PQC_CONSTANTS.HEADER_SIZE + PQC_CONSTANTS.ED25519_SIG_SIZE + PQC_CONSTANTS.ML_DSA_44_SIG_SIZE;
    assert.strictEqual(hybridSig.combinedBuffer.length, expectedTotalSize);
    assert.strictEqual(hybridSig.ed25519Signature.length, 64);
    assert.strictEqual(hybridSig.mlDsaSignature.length, 2420);

    const result = verifyHybrid(
      testPayload,
      hybridSig.combinedBuffer,
      keys.classicalPublicKey,
      keys.pqcPublicKey
    );

    assert.strictEqual(result.classicalValid, true);
    assert.strictEqual(result.pqcValid, true);
    assert.strictEqual(result.isFullyAuthenticated, true);
    assert.strictEqual(result.verificationMode, "DUAL_SECURE");
    assert.ok(result.latencyMs < 5.0, "Hybrid verification should execute in < 5ms");
  });

  test("Should reject verification if classical payload is tampered", () => {
    const keys = generateHybridKeyPair();
    const hybridSig = signHybrid(testPayload, keys);

    const tamperedPayload = Buffer.from("Tampered Relief Claim (Forged Entitlement)", "utf-8");

    assert.throws(
      () => {
        verifyHybrid(
          tamperedPayload,
          hybridSig.combinedBuffer,
          keys.classicalPublicKey,
          keys.pqcPublicKey
        );
      },
      /SIGNATURE_MISMATCH/
    );
  });

  test("Should reject truncated hybrid signature buffer", () => {
    const keys = generateHybridKeyPair();
    const truncatedBuffer = Buffer.alloc(100); // Too short

    assert.throws(
      () => {
        verifyHybrid(
          testPayload,
          truncatedBuffer,
          keys.classicalPublicKey,
          keys.pqcPublicKey
        );
      },
      /CORRUPTED_PAYLOAD/
    );
  });
});
