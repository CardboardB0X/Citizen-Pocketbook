import type { KeyObject } from "node:crypto";

/**
 * Standard civic entitlement bitmask flags.
 */
export const CLAIM_FLAGS = {
  RESIDENT: 1 << 0,         // 0x0001: Bonafide LGU Resident
  SENIOR_CITIZEN: 1 << 1,   // 0x0002: Senior Citizen (OSCA registered)
  INDIGENT_4PS: 1 << 2,     // 0x0004: Indigent / DSWD 4Ps Beneficiary
  BUSINESS_PERMIT: 1 << 3,  // 0x0008: Valid Business Owner / Taxpayer
  PWD: 1 << 4,              // 0x0010: Person with Disability
  SOLO_PARENT: 1 << 5,      // 0x0020: Registered Solo Parent
  VOTER_ACTIVE: 1 << 6,     // 0x0040: Active Local Registered Voter
  EMERGENCY_FIRST_RESPONDER: 1 << 7, // 0x0080: Accredited First Responder
} as const;

export type ClaimFlagKey = keyof typeof CLAIM_FLAGS;

/**
 * Parsed citizen entitlements.
 */
export interface CitizenClaims {
  isResident: boolean;
  isSeniorCitizen: boolean;
  isIndigent4Ps: boolean;
  hasBusinessPermit: boolean;
  isPwd: boolean;
  isSoloParent: boolean;
  isVoterActive: boolean;
  isEmergencyFirstResponder: boolean;
  rawMask: number;
}

/**
 * Binary protocol layout constants.
 */
export const PROTOCOL_CONSTANTS = {
  MAGIC_HEADER: 0x4c47, // ASCII "LG"
  PROTOCOL_VERSION: 0x01,
  HEADER_PAYLOAD_SIZE: 33,
  SIGNATURE_SIZE: 64,
  TOTAL_STATIC_SIZE: 97, // 33 + 64 bytes
  DYNAMIC_ENVELOPE_EXTRA_SIZE: 40, // 4B timestamp + 4B step + 32B device auth
  TOTAL_DYNAMIC_SIZE: 137, // 97 + 40 bytes
  DEFAULT_VALIDITY_SECONDS: 86400 * 365, // 1 Year
  EPHEMERAL_WINDOW_SECONDS: 60, // Anti-screenshot freshness limit
} as const;

/**
 * Decoded static credential representation.
 */
export interface UnpackedCredential {
  version: number;
  issuerLguCode: number;
  citizenPseudonym: string; // 32-hex character string (16 bytes)
  citizenIndex: number;     // Extracted or derived 32-bit registry index for revocation
  issuedAt: Date;
  expiresAt: Date;
  claims: CitizenClaims;
  rawSignature: Buffer;
  rawPayload: Buffer;
}

/**
 * Dynamic QR envelope containing anti-replay proofs.
 */
export interface DynamicQrEnvelope {
  staticPayload: Buffer;
  clientTimestamp: number;
  stepWindow: number;
  deviceHmac: Buffer;
}

/**
 * Output of the offline verification pipeline.
 */
export interface VerificationResult {
  valid: boolean;
  issuerLguCode: number;
  citizenPseudonym: string;
  citizenIndex: number;
  claims: CitizenClaims;
  issuedAt: Date;
  expiresAt: Date;
  ephemeralLatencySec: number;
  revocationStatus: "ACTIVE" | "REVOKED";
  chronoColor: string;
  auditRecordHash: string;
}

/**
 * Revocation manifest payload signed by an LGU.
 */
export interface SignedRevocationManifest {
  issuerLguCode: number;
  version: number;
  timestamp: number;
  totalRegistered: number;
  compressedBitmap: Buffer;
  signature: Buffer;
}

/**
 * Audit record stored in verifier's tamper-evident ledger.
 */
export interface AuditRecord {
  id: string;
  timestamp: number;
  issuerLguCode: number;
  citizenPseudonym: string;
  claimsMask: number;
  status: "VERIFIED" | "REJECTED";
  rejectionReason?: string;
  previousHash: string;
  recordHash: string;
}
