import { test, describe } from "node:test";
import * as assert from "node:assert";
import * as crypto from "node:crypto";
import { PROTOCOL_CONSTANTS } from "../src/common/types.js";
import { packDynamicQrPayload, unpackDynamicQrPayload, getChronoColor } from "../src/crypto/dynamic-qr.js";
import { ReplayAttackError, CorruptedPayloadError } from "../src/common/errors.js";

describe("Anti-Replay & Dynamic QR Protocol", () => {
  const dummyStaticCredential = Buffer.alloc(PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE, 0xaa);
  const deviceSecret = crypto.randomBytes(32);

  test("Should pack dynamic payload into exact 137 bytes", () => {
    const qrString = packDynamicQrPayload(dummyStaticCredential, deviceSecret);
    const decoded = Buffer.from(qrString, "base64url");
    assert.strictEqual(decoded.length, PROTOCOL_CONSTANTS.TOTAL_DYNAMIC_SIZE);
    assert.strictEqual(decoded.length, 137);
    assert.ok(qrString.length <= 185); // 137 bytes * 4 / 3 ≈ 183-184 chars
  });

  test("Should accept fresh QR within temporal freshness window", () => {
    const clientTime = 1700000000;
    const verifierTime = clientTime + 15; // 15 seconds later

    const qrString = packDynamicQrPayload(dummyStaticCredential, deviceSecret, clientTime);
    const result = unpackDynamicQrPayload(qrString, verifierTime, 60);

    assert.strictEqual(result.clientTimestamp, clientTime);
    assert.strictEqual(result.staticPayload.length, PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE);
  });

  test("Should reject stale screenshot exceeding 60-second replay window", () => {
    const clientTime = 1700000000;
    const verifierTime = clientTime + 75; // 75 seconds later (exceeds 60s limit)

    const qrString = packDynamicQrPayload(dummyStaticCredential, deviceSecret, clientTime);

    assert.throws(() => {
      unpackDynamicQrPayload(qrString, verifierTime, 60);
    }, ReplayAttackError);
  });

  test("Should reject futuristic timestamp beyond allowable skew", () => {
    const clientTime = 1700000120; // 120 seconds in future
    const verifierTime = 1700000000;

    const qrString = packDynamicQrPayload(dummyStaticCredential, deviceSecret, clientTime);

    assert.throws(() => {
      unpackDynamicQrPayload(qrString, verifierTime, 60);
    }, ReplayAttackError);
  });

  test("Should reject malformed Base64URL string", () => {
    assert.throws(() => {
      unpackDynamicQrPayload("not-a-valid-size-or-envelope");
    }, CorruptedPayloadError);
  });

  test("Should synchronize chrono-colors based on 10-second epoch step", () => {
    const time1 = 1700000002; // step = 170000000
    const time2 = 1700000008; // same step
    const time3 = 1700000012; // next step

    assert.strictEqual(getChronoColor(time1), getChronoColor(time2));
    assert.notStrictEqual(getChronoColor(time1), getChronoColor(time3));
  });
});
