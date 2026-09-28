import * as crypto from "node:crypto";
import { MunicipalAuthority, type IssuedCredentialOutput } from "./authority.js";

export interface BatchCitizenRecord {
  nationalIdHash: string; // 32-hex
  fullName: string;
  claimsMask: number;
}

export interface BatchIssuanceResult {
  totalProcessed: number;
  credentials: Array<IssuedCredentialOutput & { fullName: string }>;
  durationMs: number;
}

/**
 * High-throughput batch credential generator for municipal mass enrollment.
 */
export function issueBatchCredentials(
  authority: MunicipalAuthority,
  records: BatchCitizenRecord[],
  validityDurationSec?: number
): BatchIssuanceResult {
  const startTime = performance.now();
  const credentials: Array<IssuedCredentialOutput & { fullName: string }> = [];

  for (const record of records) {
    const cred = authority.issueCredential(record.nationalIdHash, record.claimsMask, validityDurationSec);
    credentials.push({
      ...cred,
      fullName: record.fullName,
    });
  }

  const durationMs = performance.now() - startTime;
  return {
    totalProcessed: records.length,
    credentials,
    durationMs,
  };
}
