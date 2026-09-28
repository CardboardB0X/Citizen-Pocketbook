import { PROTOCOL_CONSTANTS, CLAIM_FLAGS, type UnpackedCredential, type CitizenClaims } from "../common/types.js";
import { CorruptedPayloadError } from "../common/errors.js";

/**
 * Parses integer claim bitmask into descriptive flags.
 */
export function parseClaimsBitmask(mask: number): CitizenClaims {
  return {
    isResident: (mask & CLAIM_FLAGS.RESIDENT) !== 0,
    isSeniorCitizen: (mask & CLAIM_FLAGS.SENIOR_CITIZEN) !== 0,
    isIndigent4Ps: (mask & CLAIM_FLAGS.INDIGENT_4PS) !== 0,
    hasBusinessPermit: (mask & CLAIM_FLAGS.BUSINESS_PERMIT) !== 0,
    isPwd: (mask & CLAIM_FLAGS.PWD) !== 0,
    isSoloParent: (mask & CLAIM_FLAGS.SOLO_PARENT) !== 0,
    isVoterActive: (mask & CLAIM_FLAGS.VOTER_ACTIVE) !== 0,
    isEmergencyFirstResponder: (mask & CLAIM_FLAGS.EMERGENCY_FIRST_RESPONDER) !== 0,
    rawMask: mask,
  };
}

/**
 * Serializes raw fields into the canonical 33-byte payload buffer for signing.
 */
export function packPayloadHeader(
  issuerLguCode: number,
  citizenUuidHex: string,
  iatEpochSec: number,
  expEpochSec: number,
  claimsMask: number
): Buffer {
  const cleanUuid = citizenUuidHex.replace(/-/g, "");
  if (cleanUuid.length !== 32) {
    throw new CorruptedPayloadError("Citizen UUID must be exactly 16 bytes (32 hex characters).");
  }

  const buf = Buffer.alloc(PROTOCOL_CONSTANTS.HEADER_PAYLOAD_SIZE);
  buf.writeUInt16BE(PROTOCOL_CONSTANTS.MAGIC_HEADER, 0);
  buf.writeUInt8(PROTOCOL_CONSTANTS.PROTOCOL_VERSION, 2);
  buf.writeUInt32BE(issuerLguCode, 3);
  Buffer.from(cleanUuid, "hex").copy(buf, 7, 0, 16);
  buf.writeUInt32BE(iatEpochSec, 23);
  buf.writeUInt32BE(expEpochSec, 27);
  buf.writeUInt16BE(claimsMask, 31);
  return buf;
}

/**
 * Combines 33-byte signed header with 64-byte Ed25519 signature into a 97-byte credential.
 */
export function packFullCredential(signedHeader: Buffer, signature: Buffer): Buffer {
  if (signedHeader.length !== PROTOCOL_CONSTANTS.HEADER_PAYLOAD_SIZE) {
    throw new CorruptedPayloadError(
      `Invalid header length: expected ${PROTOCOL_CONSTANTS.HEADER_PAYLOAD_SIZE}, got ${signedHeader.length}`
    );
  }
  if (signature.length !== PROTOCOL_CONSTANTS.SIGNATURE_SIZE) {
    throw new CorruptedPayloadError(
      `Invalid signature length: expected ${PROTOCOL_CONSTANTS.SIGNATURE_SIZE}, got ${signature.length}`
    );
  }
  return Buffer.concat([signedHeader, signature], PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE);
}

/**
 * Unpacks a 97-byte raw binary credential buffer into typed components.
 */
export function unpackCredential(rawBuffer: Buffer): UnpackedCredential {
  if (rawBuffer.length < PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE) {
    throw new CorruptedPayloadError(
      `Invalid credential size: expected at least ${PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE} bytes, got ${rawBuffer.length}.`
    );
  }

  const magic = rawBuffer.readUInt16BE(0);
  const version = rawBuffer.readUInt8(2);

  if (magic !== PROTOCOL_CONSTANTS.MAGIC_HEADER) {
    throw new CorruptedPayloadError(`Invalid magic header 0x${magic.toString(16)}. Not an LGU e-ID.`);
  }

  if (version !== PROTOCOL_CONSTANTS.PROTOCOL_VERSION) {
    throw new CorruptedPayloadError(`Unsupported protocol version: ${version}.`);
  }

  const issuerLguCode = rawBuffer.readUInt32BE(3);
  const subBytes = rawBuffer.subarray(7, 23);
  const citizenPseudonym = subBytes.toString("hex");

  // Derive stable 32-bit revocation index from the lower 4 bytes of the pseudonym
  const citizenIndex = subBytes.readUInt32BE(12);

  const iatSeconds = rawBuffer.readUInt32BE(23);
  const expSeconds = rawBuffer.readUInt32BE(27);
  const claimsMask = rawBuffer.readUInt16BE(31);

  const rawPayload = rawBuffer.subarray(0, PROTOCOL_CONSTANTS.HEADER_PAYLOAD_SIZE);
  const rawSignature = rawBuffer.subarray(
    PROTOCOL_CONSTANTS.HEADER_PAYLOAD_SIZE,
    PROTOCOL_CONSTANTS.TOTAL_STATIC_SIZE
  );

  return {
    version,
    issuerLguCode,
    citizenPseudonym,
    citizenIndex,
    issuedAt: new Date(iatSeconds * 1000),
    expiresAt: new Date(expSeconds * 1000),
    claims: parseClaimsBitmask(claimsMask),
    rawPayload,
    rawSignature,
  };
}
