import * as crypto from "node:crypto";
import type { AuditRecord } from "../common/types.js";
import { signPayload, verifySignature } from "../crypto/ed25519.js";
import { CorruptedPayloadError, SignatureMismatchError } from "../common/errors.js";

const SYNC_PACKAGE_MAGIC = 0x5453; // ASCII "TS" (Tanza Sync)
const SYNC_PACKAGE_VERSION = 0x01;

export interface EncryptedAuditPackage {
  packageVersion: number;
  terminalId: string;
  recordCount: number;
  encryptedPayload: Buffer; // AES-256-GCM ciphertext
  iv: Buffer;               // 12 bytes
  tag: Buffer;              // 16 bytes
  checksumSha256: string;
}

/**
 * Packages and encrypts terminal audit logs for air-gapped USB offloading.
 */
export function exportEncryptedAuditLogs(
  terminalId: string,
  records: readonly AuditRecord[],
  municipalSyncSecretKey: Buffer
): Buffer {
  const jsonBytes = Buffer.from(JSON.stringify(records), "utf-8");
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv("aes-256-gcm", municipalSyncSecretKey, iv);
  const ciphertext = Buffer.concat([cipher.update(jsonBytes), cipher.final()]);
  const tag = cipher.getAuthTag();

  const checksum = crypto.createHash("sha256").update(ciphertext).digest();

  const termIdBuf = Buffer.alloc(16);
  termIdBuf.write(terminalId.substring(0, 16), 0, "utf-8");

  const header = Buffer.alloc(32);
  header.writeUInt16BE(SYNC_PACKAGE_MAGIC, 0);
  header.writeUInt8(SYNC_PACKAGE_VERSION, 2);
  header.writeUInt32BE(records.length, 3);
  header.writeUInt32BE(Math.floor(Date.now() / 1000), 7);
  termIdBuf.copy(header, 11, 0, 16);

  // Wire format: [header (32B)] + [iv (12B)] + [tag (16B)] + [checksum (32B)] + [ciphertext]
  return Buffer.concat([header, iv, tag, checksum, ciphertext]);
}

/**
 * Decrypts and ingests air-gapped audit packages at the central Municipal Hall.
 */
export function importEncryptedAuditLogs(
  packageBuffer: Buffer,
  municipalSyncSecretKey: Buffer
): AuditRecord[] {
  if (packageBuffer.length < 32 + 12 + 16 + 32) {
    throw new CorruptedPayloadError("Audit sync package is truncated.");
  }

  const magic = packageBuffer.readUInt16BE(0);
  const version = packageBuffer.readUInt8(2);

  if (magic !== SYNC_PACKAGE_MAGIC || version !== SYNC_PACKAGE_VERSION) {
    throw new CorruptedPayloadError("Unrecognized audit sync package format.");
  }

  const recordCount = packageBuffer.readUInt32BE(3);
  const iv = packageBuffer.subarray(32, 44);
  const tag = packageBuffer.subarray(44, 60);
  const expectedChecksum = packageBuffer.subarray(60, 92);
  const ciphertext = packageBuffer.subarray(92);

  const calculatedChecksum = crypto.createHash("sha256").update(ciphertext).digest();
  if (!crypto.timingSafeEqual(expectedChecksum, calculatedChecksum)) {
    throw new CorruptedPayloadError("Audit package checksum mismatch. File is corrupted or tampered.");
  }

  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", municipalSyncSecretKey, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const records = JSON.parse(decrypted.toString("utf-8")) as AuditRecord[];

    if (records.length !== recordCount) {
      throw new CorruptedPayloadError(`Record count mismatch: expected ${recordCount}, got ${records.length}`);
    }
    return records;
  } catch (err: any) {
    throw new CorruptedPayloadError(`Failed to decrypt audit package: ${err.message}`);
  }
}
