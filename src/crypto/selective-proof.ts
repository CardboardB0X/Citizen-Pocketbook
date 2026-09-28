import * as crypto from "node:crypto";
import { PROTOCOL_CONSTANTS, type CitizenClaims } from "../common/types.js";
import { parseClaimsBitmask } from "./binary-packer.js";
import { signPayload, verifySignature } from "./ed25519.js";
import { CorruptedPayloadError, SignatureMismatchError, ExpiredCredentialError } from "../common/errors.js";

const VOUCHER_MAGIC = 0x5456; // ASCII "TV" (Tanza Voucher)
const VOUCHER_VERSION = 0x01;
const HEADER_SIZE = 35; // 2B magic + 1B ver + 4B lgu + 16B sub + 4B exp + 2B mask + 2B purpose + 4B nonce
const SIGNATURE_SIZE = 64;
const TOTAL_VOUCHER_SIZE = HEADER_SIZE + SIGNATURE_SIZE; // 99 Bytes

export const VOUCHER_PURPOSES = {
  SENIOR_MEDICINE: 0x0001,
  RICE_AYUDA: 0x0002,
  CALAMITY_RELIEF: 0x0003,
  BURIAL_ASSISTANCE: 0x0004,
  EDUCATIONAL_AID: 0x0005,
} as const;

export type VoucherPurposeKey = keyof typeof VOUCHER_PURPOSES;

export interface SelectiveVoucher {
  version: number;
  issuerLguCode: number;
  citizenPseudonym: string;
  expiresAt: Date;
  disclosedClaims: CitizenClaims;
  purposeCode: number;
  nonce: number;
  rawBuffer: Buffer;
  base64Url: string;
}

/**
 * Derives a privacy-preserving selective disclosure sub-voucher.
 * Only discloses specifically selected entitlement claims while suppressing all others.
 */
export function generateSelectiveVoucher(
  issuerLguCode: number,
  citizenUuidHex: string,
  selectedClaimsMask: number,
  purposeCode: number,
  validityDurationSeconds: number,
  authorityOrCitizenPrivateKey: crypto.KeyObject
): SelectiveVoucher {
  const cleanUuid = citizenUuidHex.replace(/-/g, "");
  if (cleanUuid.length !== 32) {
    throw new CorruptedPayloadError("Invalid citizen UUID: must be 16 bytes.");
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = nowSec + validityDurationSeconds;
  const nonce = crypto.randomInt(1, 0xffffffff);

  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt16BE(VOUCHER_MAGIC, 0);
  header.writeUInt8(VOUCHER_VERSION, 2);
  header.writeUInt32BE(issuerLguCode, 3);
  Buffer.from(cleanUuid, "hex").copy(header, 7, 0, 16);
  header.writeUInt32BE(expSec, 23);
  header.writeUInt16BE(selectedClaimsMask, 27);
  header.writeUInt16BE(purposeCode, 29);
  header.writeUInt32BE(nonce, 31);

  const signature = signPayload(header, authorityOrCitizenPrivateKey);
  const rawBuffer = Buffer.concat([header, signature], TOTAL_VOUCHER_SIZE);

  return {
    version: VOUCHER_VERSION,
    issuerLguCode,
    citizenPseudonym: cleanUuid,
    expiresAt: new Date(expSec * 1000),
    disclosedClaims: parseClaimsBitmask(selectedClaimsMask),
    purposeCode,
    nonce,
    rawBuffer,
    base64Url: rawBuffer.toString("base64url"),
  };
}

/**
 * Validates a selective disclosure sub-voucher offline.
 */
export function verifySelectiveVoucher(
  voucherBase64Url: string,
  trustedLguPublicKey: crypto.KeyObject,
  currentTimeSec: number = Math.floor(Date.now() / 1000)
): SelectiveVoucher {
  let buf: Buffer;
  try {
    buf = Buffer.from(voucherBase64Url, "base64url");
  } catch {
    throw new CorruptedPayloadError("Voucher payload is not valid Base64URL.");
  }

  if (buf.length !== TOTAL_VOUCHER_SIZE) {
    throw new CorruptedPayloadError(`Invalid voucher size: expected ${TOTAL_VOUCHER_SIZE} bytes, got ${buf.length}.`);
  }

  const magic = buf.readUInt16BE(0);
  const version = buf.readUInt8(2);

  if (magic !== VOUCHER_MAGIC || version !== VOUCHER_VERSION) {
    throw new CorruptedPayloadError("Unrecognized voucher header format.");
  }

  const header = buf.subarray(0, HEADER_SIZE);
  const signature = buf.subarray(HEADER_SIZE, TOTAL_VOUCHER_SIZE);

  // Validate Ed25519 signature
  verifySignature(header, signature, trustedLguPublicKey);

  const issuerLguCode = header.readUInt32BE(3);
  const citizenPseudonym = header.subarray(7, 23).toString("hex");
  const expSec = header.readUInt32BE(23);
  const claimsMask = header.readUInt16BE(27);
  const purposeCode = header.readUInt16BE(29);
  const nonce = header.readUInt32BE(31);

  if (currentTimeSec > expSec) {
    throw new ExpiredCredentialError(new Date(expSec * 1000));
  }

  return {
    version,
    issuerLguCode,
    citizenPseudonym,
    expiresAt: new Date(expSec * 1000),
    disclosedClaims: parseClaimsBitmask(claimsMask),
    purposeCode,
    nonce,
    rawBuffer: buf,
    base64Url: voucherBase64Url,
  };
}
