export type ErrorCode =
  | "CORRUPTED_PAYLOAD"
  | "UNTRUSTED_ISSUER"
  | "EXPIRED_CREDENTIAL"
  | "SIGNATURE_MISMATCH"
  | "REPLAY_ATTACK_DETECTED"
  | "CLOCK_SKEW_DETECTED"
  | "REVOKED_CREDENTIAL"
  | "VAULT_AUTH_FAILED"
  | "INVALID_KEY_FORMAT"
  | "LEDGER_INTEGRITY_COMPROMISED";

export class LguEidError extends Error {
  public readonly code: ErrorCode;
  public readonly timestamp: Date;

  constructor(code: ErrorCode, message: string) {
    super(`[${code}] ${message}`);
    this.name = "LguEidError";
    this.code = code;
    this.timestamp = new Date();
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class CorruptedPayloadError extends LguEidError {
  constructor(message: string) {
    super("CORRUPTED_PAYLOAD", message);
  }
}

export class UntrustedIssuerError extends LguEidError {
  constructor(issuerCode: number) {
    super(
      "UNTRUSTED_ISSUER",
      `LGU identifier 0x${issuerCode.toString(16)} is not registered in the offline trust keystore.`
    );
  }
}

export class ExpiredCredentialError extends LguEidError {
  constructor(expiresAt: Date) {
    super("EXPIRED_CREDENTIAL", `Credential expired on ${expiresAt.toISOString()}.`);
  }
}

export class SignatureMismatchError extends LguEidError {
  constructor() {
    super("SIGNATURE_MISMATCH", "Cryptographic signature validation failed. Payload integrity compromised.");
  }
}

export class ReplayAttackError extends LguEidError {
  constructor(ageSeconds: number, maxAllowed: number) {
    super(
      "REPLAY_ATTACK_DETECTED",
      `Dynamic QR presentation expired. Captured age was ${ageSeconds}s (max permitted: ${maxAllowed}s). Possible screenshot replay.`
    );
  }
}

export class RevokedCredentialError extends LguEidError {
  constructor(citizenPseudonym: string, citizenIndex: number) {
    super(
      "REVOKED_CREDENTIAL",
      `Citizen identity ${citizenPseudonym} (index #${citizenIndex}) is marked REVOKED in the offline registry.`
    );
  }
}

export class VaultAuthError extends LguEidError {
  constructor(message = "Decryption failed. Invalid PIN or passphrase.") {
    super("VAULT_AUTH_FAILED", message);
  }
}

export class LedgerIntegrityError extends LguEidError {
  constructor(recordId: string, expectedHash: string, calculatedHash: string) {
    super(
      "LEDGER_INTEGRITY_COMPROMISED",
      `Audit ledger block verification failed at record ${recordId}. Expected ${expectedHash}, computed ${calculatedHash}.`
    );
  }
}
