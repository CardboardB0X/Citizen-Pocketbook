import { test, describe } from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";
import {
  fragmentPayloadForOpticalRelay,
  unpackOpticalFrame,
  OpticalMeshReceiver,
  computeCrc32,
  MESH_CONSTANTS,
} from "../src/sync/qr-mesh-relay.js";

describe("Track G: Optical QR-to-QR Air-Gapped Mesh Relay", () => {
  const originalData = crypto.randomBytes(750); // 750 bytes payload (~6 chunks)

  test("Should accurately compute CRC32 checksums", () => {
    const testBuf = Buffer.from("123456789", "ascii");
    const crc = computeCrc32(testBuf);
    assert.strictEqual(crc, 0xcbf43926); // Standard IEEE 802.3 CRC32 check value
  });

  test("Should fragment large payload into sequenced frames within chunk size", () => {
    const chunkSize = 150;
    const frames = fragmentPayloadForOpticalRelay(originalData, chunkSize, 888123);

    assert.strictEqual(frames.length, 5);
    assert.strictEqual(frames[0].sequenceIndex, 0);
    assert.strictEqual(frames[0].totalChunks, 5);
    assert.strictEqual(frames[0].sessionId, 888123);
    assert.ok(frames[0].rawBuffer.length <= MESH_CONSTANTS.HEADER_SIZE + chunkSize);
  });

  test("Should unpack and validate individual frame correctly", () => {
    const frames = fragmentPayloadForOpticalRelay(originalData, 100);
    const unpacked = unpackOpticalFrame(frames[0].base64Url);

    assert.strictEqual(unpacked.sequenceIndex, 0);
    assert.strictEqual(unpacked.totalChunks, frames.length);
    assert.deepStrictEqual(unpacked.dataChunk, frames[0].dataChunk);
  });

  test("Should assemble frames in arbitrary order and reconstruct exact original buffer", () => {
    const frames = fragmentPayloadForOpticalRelay(originalData, 120);
    const receiver = new OpticalMeshReceiver();

    // Ingest chunks in out-of-order sequence (e.g. 2, 0, 4, 1, 3, etc.)
    const shuffled = [...frames].sort(() => Math.random() - 0.5);

    for (let i = 0; i < shuffled.length; i++) {
      const progress = receiver.ingestFrame(shuffled[i].rawBuffer);
      assert.strictEqual(progress.receivedCount, i + 1);
      if (i < shuffled.length - 1) {
        assert.strictEqual(progress.isComplete, false);
      } else {
        assert.strictEqual(progress.isComplete, true);
        assert.strictEqual(progress.percentComplete, 100);
      }
    }

    const reconstructed = receiver.assemble();
    assert.deepStrictEqual(reconstructed, originalData);
  });

  test("Should reject frame with tampered data slice due to CRC32 mismatch", () => {
    const frames = fragmentPayloadForOpticalRelay(originalData, 100);
    const corruptedRaw = Buffer.from(frames[0].rawBuffer);
    corruptedRaw[corruptedRaw.length - 1] ^= 0xff; // Invert last byte

    assert.throws(
      () => unpackOpticalFrame(corruptedRaw),
      /CRC32 mismatch/
    );
  });
});
