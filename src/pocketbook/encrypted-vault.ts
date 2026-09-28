import * as crypto from "node:crypto";
import { VaultAuthError } from "../common/errors.js";

const PBKDF2_ITERATIONS = 100_000;
const KEY_LENGTH_BYTES = 32; // 256-bit AES key
const SALT_BYTES = 32;
const IV_BYTES = 12; // Standard GCM 96-bit IV
const TAG_BYTES = 16; // GCM 128-bit authentication tag

export interface CitizenVaultData {
  masterCredentialRaw: string; // Base64URL string of the 97-byte credential
  deviceSecretHex: string;     // 32 bytes (64 hex) device HMAC key
  profileMetadata: {
    fullName: string;
    birthDate: string;
    photoHashSha256: string;
    registeredAddress: string;
  };
}

/**
 * Encrypts citizen pocketbook records using AES-256-GCM derived from PIN.
 */
export function encryptVault(data: CitizenVaultData, pinOrPassphrase: string): Buffer {
  const salt = crypto.randomBytes(SALT_BYTES);
  const iv = crypto.randomBytes(IV_BYTES);

  // Derive AES-256 key via PBKDF2-HMAC-SHA256
  const key = crypto.pbkdf2Sync(pinOrPassphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BYTES, "sha256");

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const jsonPayload = Buffer.from(JSON.stringify(data), "utf-8");

  const ciphertext = Buffer.concat([cipher.update(jsonPayload), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Return packed envelope: [salt (32B)] + [iv (12B)] + [tag (16B)] + [ciphertext]
  return Buffer.concat([salt, iv, tag, ciphertext]);
}

/**
 * Decrypts citizen vault envelope. Throws VaultAuthError on wrong PIN or corrupted file.
 */
export function decryptVault(encryptedEnvelope: Buffer, pinOrPassphrase: string): CitizenVaultData {
  if (encryptedEnvelope.length < SALT_BYTES + IV_BYTES + TAG_BYTES + 1) {
    throw new VaultAuthError("Encrypted vault file is corrupted or truncated.");
  }

  const salt = encryptedEnvelope.subarray(0, SALT_BYTES);
  const iv = encryptedEnvelope.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const tag = encryptedEnvelope.subarray(SALT_BYTES + IV_BYTES, SALT_BYTES + IV_BYTES + TAG_BYTES);
  const ciphertext = encryptedEnvelope.subarray(SALT_BYTES + IV_BYTES + TAG_BYTES);

  const key = crypto.pbkdf2Sync(pinOrPassphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BYTES, "sha256");

  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString("utf-8")) as CitizenVaultData;
  } catch {
    throw new VaultAuthError();
  }
}
