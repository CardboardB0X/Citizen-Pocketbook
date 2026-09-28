import { test, describe } from "node:test";
import * as assert from "node:assert";
import { generateAuthorityKeyPair } from "../src/crypto/ed25519.js";
import {
  generateSelectiveVoucher,
  verifySelectiveVoucher,
  VOUCHER_PURPOSES,
} from "../src/crypto/selective-proof.js";
import { CLAIM_FLAGS } from "../src/common/types.js";
import { SignatureMismatchError, ExpiredCredentialError } from "../src/common/errors.js";

describe("Track C: Zero-Knowledge Selective Claim Disclosure", () => {
  const keyPair = generateAuthorityKeyPair();
  const TANZA_LGU_CODE = 42120000;
  const citizenUuid = "0123456789abcdef0123456789abcdef";

  test("Should generate and verify sub-voucher disclosing ONLY Senior Citizen status", () => {
    // Citizen has Senior + 4Ps + Voter, but selectively only reveals Senior for medicine
    const seniorOnlyMask = CLAIM_FLAGS.SENIOR_CITIZEN;

    const voucher = generateSelectiveVoucher(
      TANZA_LGU_CODE,
      citizenUuid,
      seniorOnlyMask,
      VOUCHER_PURPOSES.SENIOR_MEDICINE,
      3600, // 1 hour validity
      keyPair.privateKey
    );

    assert.strictEqual(voucher.rawBuffer.length, 99); // 35B header + 64B sig
    assert.strictEqual(voucher.disclosedClaims.isSeniorCitizen, true);
    assert.strictEqual(voucher.disclosedClaims.isIndigent4Ps, false); // Suppressed!
    assert.strictEqual(voucher.disclosedClaims.isVoterActive, false); // Suppressed!

    // Verify voucher offline
    const verified = verifySelectiveVoucher(voucher.base64Url, keyPair.publicKey);
    assert.strictEqual(verified.citizenPseudonym, citizenUuid);
    assert.strictEqual(verified.purposeCode, VOUCHER_PURPOSES.SENIOR_MEDICINE);
    assert.strictEqual(verified.disclosedClaims.isSeniorCitizen, true);
    assert.strictEqual(verified.disclosedClaims.isIndigent4Ps, false);
  });

  test("Should reject tampered voucher claim escalation", () => {
    const voucher = generateSelectiveVoucher(
      TANZA_LGU_CODE,
      citizenUuid,
      CLAIM_FLAGS.RESIDENT,
      VOUCHER_PURPOSES.RICE_AYUDA,
      3600,
      keyPair.privateKey
    );

    // Tamper with bytes in header
    const raw = Buffer.from(voucher.base64Url, "base64url");
    raw[28] |= CLAIM_FLAGS.SENIOR_CITIZEN; // illegally escalate to senior
    const tamperedBase64 = raw.toString("base64url");

    assert.throws(() => {
      verifySelectiveVoucher(tamperedBase64, keyPair.publicKey);
    }, SignatureMismatchError);
  });

  test("Should reject expired selective voucher", () => {
    const pastVoucher = generateSelectiveVoucher(
      TANZA_LGU_CODE,
      citizenUuid,
      CLAIM_FLAGS.RESIDENT,
      VOUCHER_PURPOSES.CALAMITY_RELIEF,
      -10, // already expired 10 seconds ago
      keyPair.privateKey
    );

    assert.throws(() => {
      verifySelectiveVoucher(pastVoucher.base64Url, keyPair.publicKey);
    }, ExpiredCredentialError);
  });
});
