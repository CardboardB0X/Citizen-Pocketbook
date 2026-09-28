import { test, describe } from "node:test";
import * as assert from "node:assert";
import { BitmapRevocationRegistry } from "../src/revocation/bitmap-registry.js";
import {
  createSignedRevocationManifest,
  applySignedRevocationManifest,
} from "../src/revocation/delta-manifest.js";
import { generateAuthorityKeyPair } from "../src/crypto/ed25519.js";
import { UntrustedIssuerError, SignatureMismatchError } from "../src/common/errors.js";

describe("Module 2: Offline Revocation Registry & Delta Manifests", () => {
  test("Should accurately set and query revocation bits in memory", () => {
    const registry = new BitmapRevocationRegistry(100_000);

    assert.strictEqual(registry.isRevoked(42), false);
    assert.strictEqual(registry.isRevoked(99_999), false);

    registry.revoke(42);
    registry.revoke(99_999);

    assert.strictEqual(registry.isRevoked(42), true);
    assert.strictEqual(registry.isRevoked(99_999), true);
    assert.strictEqual(registry.isRevoked(43), false);
    assert.strictEqual(registry.getRevokedCount(), 2);

    registry.unrevoke(42);
    assert.strictEqual(registry.isRevoked(42), false);
    assert.strictEqual(registry.getRevokedCount(), 1);
  });

  test("Should compress and decompress sparse revocation bitmaps without loss", () => {
    const source = new BitmapRevocationRegistry(50_000);
    source.revoke(10);
    source.revoke(500);
    source.revoke(45_000);

    const compressed = source.exportCompressed();
    // Raw uncompressed size: ~6.25 KB. Sparse chunks for 3 items: 8 + 3 * 36 = 116 bytes!
    assert.ok(compressed.length < 500, `Compressed size ${compressed.length} is larger than expected`);

    const target = new BitmapRevocationRegistry(50_000);
    target.importCompressed(compressed);

    assert.strictEqual(target.isRevoked(10), true);
    assert.strictEqual(target.isRevoked(500), true);
    assert.strictEqual(target.isRevoked(45_000), true);
    assert.strictEqual(target.isRevoked(11), false);
    assert.strictEqual(target.getRevokedCount(), 3);
  });

  test("Should generate and verify signed revocation delta manifests", () => {
    const keyPair = generateAuthorityKeyPair();
    const lguCode = 137403000;
    const registry = new BitmapRevocationRegistry(10_000);
    registry.revoke(777);

    const manifestBuffer = createSignedRevocationManifest(lguCode, 1, registry, keyPair.privateKey);

    const verifierRegistry = new BitmapRevocationRegistry(10_000);
    const trustedKeys = new Map([[lguCode, keyPair.publicKey]]);

    const meta = applySignedRevocationManifest(manifestBuffer, trustedKeys, verifierRegistry);

    assert.strictEqual(meta.issuerLguCode, lguCode);
    assert.strictEqual(meta.manifestVersion, 1);
    assert.strictEqual(meta.revokedEntriesCount, 1);
    assert.strictEqual(verifierRegistry.isRevoked(777), true);
    assert.strictEqual(verifierRegistry.isRevoked(778), false);
  });

  test("Should reject manifest from untrusted issuer or with invalid signature", () => {
    const keyPair = generateAuthorityKeyPair();
    const attackerKeyPair = generateAuthorityKeyPair();
    const lguCode = 137403000;
    const registry = new BitmapRevocationRegistry(10_000);

    // Signed by unauthorized key
    const forgedManifest = createSignedRevocationManifest(lguCode, 1, registry, attackerKeyPair.privateKey);

    const verifierRegistry = new BitmapRevocationRegistry(10_000);
    const trustedKeys = new Map([[lguCode, keyPair.publicKey]]);

    assert.throws(() => {
      applySignedRevocationManifest(forgedManifest, trustedKeys, verifierRegistry);
    }, SignatureMismatchError);

    // Manifest with unknown LGU code
    const unknownLguManifest = createSignedRevocationManifest(999999, 1, registry, keyPair.privateKey);
    assert.throws(() => {
      applySignedRevocationManifest(unknownLguManifest, trustedKeys, verifierRegistry);
    }, UntrustedIssuerError);
  });
});
