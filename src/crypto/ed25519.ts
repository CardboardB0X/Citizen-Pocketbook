import * as crypto from "node:crypto";
import { SignatureMismatchError } from "../common/errors.js";

// Standard ASN.1 prefixes for Ed25519 raw key wrapping
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface Ed25519KeyPair {
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
  rawPublicKey: Buffer;  // 32 bytes
  rawPrivateKey: Buffer; // 32 bytes seed
}

/**
 * Generates an Ed25519 asymmetric keypair with raw byte representations.
 */
export function generateAuthorityKeyPair(): Ed25519KeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  const pkcs8Der = privateKey.export({ type: "pkcs8", format: "der" });

  const rawPublicKey = spkiDer.subarray(ED25519_SPKI_PREFIX.length);
  const rawPrivateKey = pkcs8Der.subarray(ED25519_PKCS8_PREFIX.length);

  return {
    publicKey,
    privateKey,
    rawPublicKey,
    rawPrivateKey,
  };
}

/**
 * Creates an Ed25519 KeyObject from a raw 32-byte public key.
 */
export function importRawPublicKey(raw32Bytes: Buffer): crypto.KeyObject {
  if (raw32Bytes.length !== 32) {
    throw new Error(`Invalid Ed25519 public key size: expected 32 bytes, got ${raw32Bytes.length}`);
  }
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, raw32Bytes]);
  return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}

/**
 * Creates an Ed25519 KeyObject from a raw 32-byte private key seed.
 */
export function importRawPrivateKey(raw32Bytes: Buffer): crypto.KeyObject {
  if (raw32Bytes.length !== 32) {
    throw new Error(`Invalid Ed25519 private key seed size: expected 32 bytes, got ${raw32Bytes.length}`);
  }
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, raw32Bytes]);
  return crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

/**
 * Extracts raw 32-byte public key from an Ed25519 KeyObject.
 */
export function exportRawPublicKey(publicKey: crypto.KeyObject): Buffer {
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  return spkiDer.subarray(ED25519_SPKI_PREFIX.length);
}

/**
 * Signs a payload buffer using PureEd25519 (RFC 8032). Returns 64-byte signature.
 */
export function signPayload(payload: Buffer, privateKey: crypto.KeyObject): Buffer {
  return crypto.sign(null, payload, privateKey);
}

/**
 * Verifies a 64-byte Ed25519 signature over a payload buffer.
 * Throws SignatureMismatchError if invalid.
 */
export function verifySignature(payload: Buffer, signature: Buffer, publicKey: crypto.KeyObject | Buffer): boolean {
  const keyObj = Buffer.isBuffer(publicKey) ? importRawPublicKey(publicKey) : publicKey;
  const isValid = crypto.verify(null, payload, keyObj, signature);
  if (!isValid) {
    throw new SignatureMismatchError();
  }
  return true;
}
