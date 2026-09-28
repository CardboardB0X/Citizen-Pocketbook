import * as crypto from "node:crypto";
import type { AuditRecord } from "../common/types.js";
import { LedgerIntegrityError } from "../common/errors.js";

const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Append-only tamper-evident audit ledger using SHA-256 cryptographic hash chaining.
 */
export class TamperEvidentAuditLedger {
  private records: AuditRecord[] = [];

  /**
   * Computes the deterministic SHA-256 digest of an audit block.
   */
  private computeRecordHash(
    previousHash: string,
    id: string,
    timestamp: number,
    issuerLguCode: number,
    citizenPseudonym: string,
    claimsMask: number,
    status: string,
    rejectionReason = ""
  ): string {
    const payload = `${previousHash}:${id}:${timestamp}:${issuerLguCode}:${citizenPseudonym}:${claimsMask}:${status}:${rejectionReason}`;
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  /**
   * Appends a verification event to the immutable chain.
   */
  public append(
    issuerLguCode: number,
    citizenPseudonym: string,
    claimsMask: number,
    status: "VERIFIED" | "REJECTED",
    rejectionReason?: string
  ): AuditRecord {
    const previousHash = this.records.length === 0 ? GENESIS_HASH : this.records[this.records.length - 1].recordHash;
    const id = `REC-${this.records.length + 1}-${crypto.randomBytes(4).toString("hex")}`;
    const timestamp = Math.floor(Date.now() / 1000);

    const recordHash = this.computeRecordHash(
      previousHash,
      id,
      timestamp,
      issuerLguCode,
      citizenPseudonym,
      claimsMask,
      status,
      rejectionReason
    );

    const record: AuditRecord = {
      id,
      timestamp,
      issuerLguCode,
      citizenPseudonym,
      claimsMask,
      status,
      rejectionReason,
      previousHash,
      recordHash,
    };

    this.records.push(record);
    return record;
  }

  /**
   * Cryptographically verifies the entire historical chain.
   * Throws LedgerIntegrityError on any tampering, deletion, or bit-flip.
   */
  public verifyLedgerIntegrity(): boolean {
    for (let i = 0; i < this.records.length; i++) {
      const record = this.records[i];
      const expectedPreviousHash = i === 0 ? GENESIS_HASH : this.records[i - 1].recordHash;

      if (record.previousHash !== expectedPreviousHash) {
        throw new LedgerIntegrityError(record.id, expectedPreviousHash, record.previousHash);
      }

      const recomputedHash = this.computeRecordHash(
        record.previousHash,
        record.id,
        record.timestamp,
        record.issuerLguCode,
        record.citizenPseudonym,
        record.claimsMask,
        record.status,
        record.rejectionReason || ""
      );

      if (recomputedHash !== record.recordHash) {
        throw new LedgerIntegrityError(record.id, record.recordHash, recomputedHash);
      }
    }
    return true;
  }

  public getRecords(): readonly AuditRecord[] {
    return this.records;
  }

  public size(): number {
    return this.records.length;
  }
}
