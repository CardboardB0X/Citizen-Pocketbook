import * as crypto from "node:crypto";
import { packDynamicQrPayload, getChronoColor } from "../crypto/dynamic-qr.js";
import { encryptVault, decryptVault, type CitizenVaultData } from "./encrypted-vault.js";
import { PROTOCOL_CONSTANTS } from "../common/types.js";
import { VaultAuthError } from "../common/errors.js";

export interface ActiveQrPresentation {
  qrString: string;
  chronoColor: string;
  secondsRemainingInWindow: number;
  timestampEpoch: number;
}

/**
 * Mobile runtime engine for citizen identity pocketbook.
 * Handles encrypted storage, session isolation, and dynamic QR emission.
 */
export class CitizenPocketbookEngine {
  private encryptedVaultBuffer: Buffer | null = null;
  private activeSession: CitizenVaultData | null = null;

  /**
   * Initializes or provisions a new citizen pocketbook.
   */
  public provision(data: CitizenVaultData, initialPin: string): Buffer {
    this.encryptedVaultBuffer = encryptVault(data, initialPin);
    return this.encryptedVaultBuffer;
  }

  /**
   * Loads an existing encrypted vault file.
   */
  public loadVault(vaultBuffer: Buffer): void {
    this.encryptedVaultBuffer = vaultBuffer;
    this.activeSession = null;
  }

  /**
   * Unlocks the vault using the citizen PIN.
   */
  public unlock(pin: string): void {
    if (!this.encryptedVaultBuffer) {
      throw new VaultAuthError("Pocketbook vault has not been provisioned or loaded.");
    }
    this.activeSession = decryptVault(this.encryptedVaultBuffer, pin);
  }

  /**
   * Clears active decrypted credentials from volatile memory.
   */
  public lock(): void {
    this.activeSession = null;
  }

  public isUnlocked(): boolean {
    return this.activeSession !== null;
  }

  /**
   * Generates dynamic anti-replay QR payload with synchronized visual chrono-color.
   */
  public generateDynamicQr(currentTimeSec: number = Math.floor(Date.now() / 1000)): ActiveQrPresentation {
    if (!this.activeSession) {
      throw new VaultAuthError("Pocketbook is locked. Provide PIN to generate QR.");
    }

    const staticBuffer = Buffer.from(this.activeSession.masterCredentialRaw, "base64url");
    const deviceSecret = Buffer.from(this.activeSession.deviceSecretHex, "hex");

    const qrString = packDynamicQrPayload(staticBuffer, deviceSecret, currentTimeSec);
    const chronoColor = getChronoColor(currentTimeSec);

    const windowSeconds = PROTOCOL_CONSTANTS.EPHEMERAL_WINDOW_SECONDS;
    const secondsRemainingInWindow = windowSeconds - (currentTimeSec % windowSeconds);

    return {
      qrString,
      chronoColor,
      secondsRemainingInWindow,
      timestampEpoch: currentTimeSec,
    };
  }

  public getProfile(): CitizenVaultData["profileMetadata"] {
    if (!this.activeSession) {
      throw new VaultAuthError("Pocketbook is locked.");
    }
    return this.activeSession.profileMetadata;
  }
}
