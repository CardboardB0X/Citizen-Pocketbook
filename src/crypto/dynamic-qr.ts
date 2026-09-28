import * as crypto from "node:crypto";
import { PROTOCOL_CONSTANTS, type DynamicQrEnvelope } from "../common/types.js";
import { CorruptedPayloadError, ReplayAttackError } from "../common/errors.js";

// 8-color synchronized chrono-palette for visual verification
export const CHRONO_PALETTE = [
  "#2563EB", // Blue
  "#059669", // Emerald Green
  "#D97706", // Amber
  "#DC2626", // Crimson Red
  "#7C3AED", // Violet
  "#0891B2", // Cyan
  "#DB2777", // Pink
  "#4F46E5", // Indigo
] as const;

/**
 * Returns synchronized visual border color derived from the RTC epoch.
 * Changes every 10 seconds.
 */
export function getChronoColor(epochSeconds: number = Math.floor(Date.now() / 1000)): string {
  const step = Math.floor(epochSeconds / 10);
  const index = Math.abs(step) % CHRONO_PALETTE.length;
  return CHRONO_PALETTE[index];
}

/**
 * Packs a 97-byte static credential into a 137-byte anti-replay dynamic QR payload.
 */
export function packDynamicQrPayload(
  staticCredentialBuffer: Buffer,
  deviceSecretKey: Buffer,
  clientTimestampSec: number = Math.floor(Date.now() / 1000)
): string {
  if (staticCredentialBuffer.length !== PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE) {
    throw new CorruptedPayloadError(
      `Static credential must be ${PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE} bytes, got ${staticCredentialBuffer.length}`
    );
  }

  const stepWindow = Math.floor(clientTimestampSec / PROTOCOL_CONSTANTS.EPHEMERAL_WINDOW_SECONDS);
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeUInt32BE(clientTimestampSec, 0);
  timeBuffer.writeUInt32BE(stepWindow, 4);

  // Compute HMAC over static credential + time parameters
  const hmac = crypto.createHmac("sha256", deviceSecretKey);
  hmac.update(staticCredentialBuffer);
  hmac.update(timeBuffer);
  const authTag = hmac.digest(); // 32 bytes

  const dynamicBuffer = Buffer.concat([staticCredentialBuffer, timeBuffer, authTag], PROTOCOL_CONSTANTS.TOTAL_DYNAMIC_SIZE);
  return dynamicBuffer.toString("base64url");
}

/**
 * Unpacks dynamic QR Base64URL string and verifies temporal freshness (anti-replay window).
 */
export function unpackDynamicQrPayload(
  qrStringBase64Url: string,
  verifierTimestampSec: number = Math.floor(Date.now() / 1000),
  maxAllowedAgeSec: number = PROTOCOL_CONSTANTS.EPHEMERAL_WINDOW_SECONDS
): DynamicQrEnvelope {
  let rawBuffer: Buffer;
  try {
    rawBuffer = Buffer.from(qrStringBase64Url, "base64url");
  } catch {
    throw new CorruptedPayloadError("QR payload is not valid Base64URL.");
  }

  if (rawBuffer.length !== PROTOCOL_CONSTANTS.TOTAL_DYNAMIC_SIZE) {
    throw new CorruptedPayloadError(
      `Invalid dynamic QR size: expected ${PROTOCOL_CONSTANTS.TOTAL_DYNAMIC_SIZE} bytes, got ${rawBuffer.length}.`
    );
  }

  const staticPayload = rawBuffer.subarray(0, PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE);
  const clientTimestamp = rawBuffer.readUInt32BE(PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE);
  const stepWindow = rawBuffer.readUInt32BE(PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE + 4);
  const deviceHmac = rawBuffer.subarray(PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE + 8, PROTOCOL_CONSTANTS.TOTAL_DYNAMIC_SIZE);

  // Anti-Replay Check: Reject screenshots older than maxAllowedAgeSec or futuristic timestamps
  const drift = Math.abs(verifierTimestampSec - clientTimestamp);
  if (drift > maxAllowedAgeSec) {
    throw new ReplayAttackError(drift, maxAllowedAgeSec);
  }

  return {
    staticPayload,
    clientTimestamp,
    stepWindow,
    deviceHmac,
  };
}
