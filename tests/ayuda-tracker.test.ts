import { test, describe } from "node:test";
import * as assert from "node:assert/strict";
import { AyudaDistributionTracker } from "../src/verifier/ayuda-tracker.js";

describe("Track H: Disaster Ayuda Anti-Double-Dipping Engine", () => {
  const eventId = "TANZA-RICE-AYUDA-2026";
  const citizenA = "e04b82d7a22f4b7da3c59a0f7e812d44";
  const citizenB = "3a91f5e2d14872cbb0924e719aa01823";

  test("Should allow first-time legitimate citizen claim and issue signed receipt", () => {
    const tracker = new AyudaDistributionTracker();
    const check = tracker.checkEligibility(citizenA, eventId);
    assert.strictEqual(check.allowed, true);

    const receipt = tracker.recordClaim(citizenA, 1001, eventId, "TENT-HALAYHAY-02");
    assert.strictEqual(receipt.citizenPseudonym, citizenA);
    assert.ok(receipt.receiptId.startsWith("RCPT-"));
    assert.ok(receipt.receiptSignature.length === 64);
  });

  test("Should reject duplicate claim attempt for the same citizen in the same event", () => {
    const tracker = new AyudaDistributionTracker();
    tracker.recordClaim(citizenA, 1001, eventId, "TENT-DAANG-AMAYA");

    const recheck = tracker.checkEligibility(citizenA, eventId);
    assert.strictEqual(recheck.allowed, false);
    assert.ok(recheck.reason?.includes("DUPLICATE CLAIM"));

    assert.throws(
      () => tracker.recordClaim(citizenA, 1001, eventId, "TENT-DAANG-AMAYA-2"),
      /DUPLICATE CLAIM/
    );
  });

  test("Should allow different citizens to claim independently in same event", () => {
    const tracker = new AyudaDistributionTracker();
    tracker.recordClaim(citizenA, 1001, eventId);

    const checkB = tracker.checkEligibility(citizenB, eventId);
    assert.strictEqual(checkB.allowed, true);

    const receiptB = tracker.recordClaim(citizenB, 1002, eventId);
    assert.strictEqual(receiptB.citizenPseudonym, citizenB);

    assert.strictEqual(tracker.getAllClaims(eventId).length, 2);
  });
});
