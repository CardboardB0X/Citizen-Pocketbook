import { test, describe } from "node:test";
import * as assert from "node:assert";
import { PROTOCOL_CONSTANTS, CLAIM_FLAGS } from "../src/common/types.js";
import { packPayloadHeader, packFullCredential, unpackCredential } from "../src/crypto/binary-packer.js";
import {
  generateAuthorityKeyPair,
  signPayload,
  verifySignature,
  importRawPublicKey,
  importRawPrivateKey,
} from "../src/crypto/ed25519.js";
import { SignatureMismatchError, CorruptedPayloadError } from "../src/common/errors.js";

describe("Module 1: Cryptographic Trust Layer & Binary Layout", () => {
  test("Should enforce exact 97-byte static payload constraint", () => {
    assert.strictEqual(PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE, 97);
    assert.strictEqual(PROTOCOL_CONSTANTS.HEADER_PAYLOAD_SIZE, 33);
    assert.strictEqual(PROTOCOL_CONSTANTS.SIGNATURE_SIZE, 64);
  });

  test("Should serialize and unpack canonical 97-byte credential", () => {
    const keyPair = generateAuthorityKeyPair();
    const lguCode = 137403000;
    const citizenUuid = "12345678123456781234567812345678";
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + 86400 * 30;
    const claims = CLAIM_FLAGS.RESIDENT | CLAIM_FLAGS.SENIOR_CITIZEN;

    const header = packPayloadHeader(lguCode, citizenUuid, iat, exp, claims);
    assert.strictEqual(header.length, 33);

    const sig = signPayload(header, keyPair.privateKey);
    assert.strictEqual(sig.length, 64);

    const packed = packFullCredential(header, sig);
    assert.strictEqual(packed.length, 97);

    const unpacked = unpackCredential(packed);
    assert.strictEqual(unpacked.issuerLguCode, lguCode);
    assert.strictEqual(unpacked.citizenPseudonym, citizenUuid);
    assert.strictEqual(unpacked.claims.isResident, true);
    assert.strictEqual(unpacked.claims.isSeniorCitizen, true);
    assert.strictEqual(unpacked.claims.hasBusinessPermit, false);
    assert.strictEqual(unpacked.issuedAt.getTime(), iat * 1000);
    assert.strictEqual(unpacked.expiresAt.getTime(), exp * 1000);

    // Verify signature passes
    assert.doesNotThrow(() => {
      verifySignature(unpacked.rawPayload, unpacked.rawSignature, keyPair.publicKey);
    });
  });

  test("Should reject tampered payload bytes", () => {
    const keyPair = generateAuthorityKeyPair();
    const header = packPayloadHeader(100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1000, 2000, 1);
    const sig = signPayload(header, keyPair.privateKey);
    const packed = packFullCredential(header, sig);

    // Tamper single bit in header
    packed[5] ^= 0x01;

    const unpacked = unpackCredential(packed);
    assert.throws(() => {
      verifySignature(unpacked.rawPayload, unpacked.rawSignature, keyPair.publicKey);
    }, SignatureMismatchError);
  });

  test("Should reject truncated buffer", () => {
    const invalidBuf = Buffer.alloc(50);
    assert.throws(() => {
      unpackCredential(invalidBuf);
    }, CorruptedPayloadError);
  });

  test("Should support zero-loss import/export of raw 32-byte Ed25519 keys", () => {
    const keyPair = generateAuthorityKeyPair();
    assert.strictEqual(keyPair.rawPublicKey.length, 32);
    assert.strictEqual(keyPair.rawPrivateKey.length, 32);

    const importedPub = importRawPublicKey(keyPair.rawPublicKey);
    const importedPriv = importRawPrivateKey(keyPair.rawPrivateKey);

    const testData = Buffer.from("lgu-offline-trust-test");
    const sig = signPayload(testData, importedPriv);
    assert.strictEqual(sig.length, 64);

    assert.doesNotThrow(() => {
      verifySignature(testData, sig, importedPub);
    });
  });
});
