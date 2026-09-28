import * as crypto from "node:crypto";
import { signPayload, verifySignature } from "../crypto/ed25519.js";
import { BitmapRevocationRegistry } from "./bitmap-registry.js";
import { CorruptedPayloadError, UntrustedIssuerError } from "../common/errors.js";

const REVOCATION_MAGIC = 0x4c52; // ASCII "LR" (LGU Revocation)
const REVOCATION_VERSION = 0x01;
const HEADER_SIZE = 19;
const SIGNATURE_SIZE = 64;

export interface RevocationManifestMeta {
  issuerLguCode: number;
  manifestVersion: number;
  timestamp: Date;
  totalCapacity: number;
  revokedEntriesCount: number;
}

/**
 * Creates and signs a compact revocation delta manifest using the LGU Authority key.
 */
export function createSignedRevocationManifest(
  issuerLguCode: number,
  manifestVersion: number,
  registry: BitmapRevocationRegistry,
  authorityPrivateKey: crypto.KeyObject
): Buffer {
  const compressedBitmap = registry.exportCompressed();

  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt16BE(REVOCATION_MAGIC, 0);
  header.writeUInt8(REVOCATION_VERSION, 2);
  header.writeUInt32BE(issuerLguCode, 3);
  header.writeUInt32BE(manifestVersion, 7);
  header.writeUInt32BE(Math.floor(Date.now() / 1000), 11);
  header.writeUInt32BE(registry.capacity, 15);

  const payloadToSign = Buffer.concat([header, compressedBitmap]);
  const signature = signPayload(payloadToSign, authorityPrivateKey);

  return Buffer.concat([payloadToSign, signature]);
}

/**
 * Verifies and applies an offline signed revocation manifest into a local registry.
 */
export function applySignedRevocationManifest(
  manifestBuffer: Buffer,
  trustedLguPublicKeys: Map<number, crypto.KeyObject>,
  targetRegistry: BitmapRevocationRegistry
): RevocationManifestMeta {
  if (manifestBuffer.length < HEADER_SIZE + 8 + SIGNATURE_SIZE) {
    throw new CorruptedPayloadError("Revocation manifest file is truncated.");
  }

  const magic = manifestBuffer.readUInt16BE(0);
  const version = manifestBuffer.readUInt8(2);

  if (magic !== REVOCATION_MAGIC || version !== REVOCATION_VERSION) {
    throw new CorruptedPayloadError("Unrecognized revocation manifest header format.");
  }

  const issuerLguCode = manifestBuffer.readUInt32BE(3);
  const manifestVersion = manifestBuffer.readUInt32BE(7);
  const timestampEpoch = manifestBuffer.readUInt32BE(11);
  const totalCapacity = manifestBuffer.readUInt32BE(15);

  // Authenticate issuer public key
  const publicKey = trustedLguPublicKeys.get(issuerLguCode);
  if (!publicKey) {
    throw new UntrustedIssuerError(issuerLguCode);
  }

  const signedContentLength = manifestBuffer.length - SIGNATURE_SIZE;
  const signedContent = manifestBuffer.subarray(0, signedContentLength);
  const signature = manifestBuffer.subarray(signedContentLength);

  // Validate Ed25519 signature
  verifySignature(signedContent, signature, publicKey);

  // Unpack and hydrate bitmap
  const compressedBitmap = manifestBuffer.subarray(HEADER_SIZE, signedContentLength);
  targetRegistry.importCompressed(compressedBitmap);

  return {
    issuerLguCode,
    manifestVersion,
    timestamp: new Date(timestampEpoch * 1000),
    totalCapacity,
    revokedEntriesCount: targetRegistry.getRevokedCount(),
  };
}
