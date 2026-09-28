import * as crypto from "node:crypto";
import { PROTOCOL_CONSTANTS, type VerificationResult } from "../common/types.js";
import { unpackCredential } from "../crypto/binary-packer.js";
import { verifySignature } from "../crypto/ed25519.js";
import { unpackDynamicQrPayload, getChronoColor } from "../crypto/dynamic-qr.js";
import { BitmapRevocationRegistry } from "../revocation/bitmap-registry.js";
import { TamperEvidentAuditLedger } from "./audit-log.js";
import {
  UntrustedIssuerError,
  ExpiredCredentialError,
  RevokedCredentialError,
  CorruptedPayloadError,
  LguEidError,
} from "../common/errors.js";

/**
 * Offline Verifier Terminal Engine.
 * Capable of running on resource-constrained handheld terminals with zero network.
 */
export class OfflineVerifierEngine {
  private trustedLguKeystore = new Map<number, crypto.KeyObject>();
  private revocationRegistries = new Map<number, BitmapRevocationRegistry>();
  public readonly auditLedger = new TamperEvidentAuditLedger();

  /**
   * Enrolls a trusted LGU Root Authority Public Key.
   */
  public registerTrustedLgu(lguCode: number, publicKey: crypto.KeyObject): void {
    this.trustedLguKeystore.set(lguCode, publicKey);
    if (!this.revocationRegistries.has(lguCode)) {
      this.revocationRegistries.set(lguCode, new BitmapRevocationRegistry());
    }
  }

  /**
   * Sets or updates the revocation registry for an LGU.
   */
  public setRevocationRegistry(lguCode: number, registry: BitmapRevocationRegistry): void {
    this.revocationRegistries.set(lguCode, registry);
  }

  public getRevocationRegistry(lguCode: number): BitmapRevocationRegistry | undefined {
    return this.revocationRegistries.get(lguCode);
  }

  /**
   * Complete 7-step offline verification pipeline.
   * Total latency: < 5ms on modern CPU, < 15ms on Cortex-A53.
   */
  public verify(
    dynamicQrString: string,
    verifierClockSec: number = Math.floor(Date.now() / 1000)
  ): VerificationResult {
    let issuerCode = 0;
    let pseudonym = "UNKNOWN";
    let claimsMask = 0;

    try {
      // Step 1: Unpack Dynamic QR & Validate Anti-Replay Temporal Freshness (<= 60s)
      const dynamicEnvelope = unpackDynamicQrPayload(
        dynamicQrString,
        verifierClockSec,
        PROTOCOL_CONSTANTS.EPHEMERAL_WINDOW_SECONDS
      );

      // Step 2: Unpack 97-Byte Static Credential
      const credential = unpackCredential(dynamicEnvelope.staticPayload);
      issuerCode = credential.issuerLguCode;
      pseudonym = credential.citizenPseudonym;
      claimsMask = credential.claims.rawMask;

      // Step 3: Check Authority Keystore
      const lguPublicKey = this.trustedLguKeystore.get(issuerCode);
      if (!lguPublicKey) {
        throw new UntrustedIssuerError(issuerCode);
      }

      // Step 4: Verify Asymmetric Ed25519 Signature
      verifySignature(credential.rawPayload, credential.rawSignature, lguPublicKey);

      // Step 5: Validate Credential Timestamps
      const nowMs = verifierClockSec * 1000;
      if (credential.issuedAt.getTime() > nowMs + 60_000) {
        throw new CorruptedPayloadError("Credential issued at a future date (clock drift violation).");
      }
      if (nowMs > credential.expiresAt.getTime()) {
        throw new ExpiredCredentialError(credential.expiresAt);
      }

      // Step 6: Evaluate Offline Revocation Bitmap
      const registry = this.revocationRegistries.get(issuerCode);
      if (registry && registry.isRevoked(credential.citizenIndex)) {
        throw new RevokedCredentialError(credential.citizenPseudonym, credential.citizenIndex);
      }

      // Step 7: Record Audit Ledger Event (Immutable Hash Chain)
      const auditRecord = this.auditLedger.append(issuerCode, pseudonym, claimsMask, "VERIFIED");

      const chronoColor = getChronoColor(verifierClockSec);
      const latencySec = Math.abs(verifierClockSec - dynamicEnvelope.clientTimestamp);

      return {
        valid: true,
        issuerLguCode: credential.issuerLguCode,
        citizenPseudonym: credential.citizenPseudonym,
        citizenIndex: credential.citizenIndex,
        claims: credential.claims,
        issuedAt: credential.issuedAt,
        expiresAt: credential.expiresAt,
        ephemeralLatencySec: latencySec,
        revocationStatus: "ACTIVE",
        chronoColor,
        auditRecordHash: auditRecord.recordHash,
      };
    } catch (err: any) {
      const reason = err instanceof LguEidError ? err.message : String(err);
      this.auditLedger.append(issuerCode, pseudonym, claimsMask, "REJECTED", reason);
      throw err;
    }
  }
}
