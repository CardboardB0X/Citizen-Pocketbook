import * as crypto from "node:crypto";
import { PROTOCOL_CONSTANTS } from "../common/types.js";
import { packPayloadHeader, packFullCredential } from "../crypto/binary-packer.js";
import { generateAuthorityKeyPair, signPayload, type Ed25519KeyPair } from "../crypto/ed25519.js";
import { BitmapRevocationRegistry } from "../revocation/bitmap-registry.js";
import { createSignedRevocationManifest } from "../revocation/delta-manifest.js";

export interface IssuedCredentialOutput {
  rawBuffer: Buffer;           // 97 bytes
  base64Url: string;           // 130 characters
  citizenPseudonym: string;    // 32-hex
  citizenIndex: number;
  issuedAt: Date;
  expiresAt: Date;
}

/**
 * Municipal Root Authority Service.
 * Acts as the sovereign cryptographic issuer for an LGU.
 */
export class MunicipalAuthority {
  public readonly lguCode: number;
  public readonly municipalityName: string;
  private keyPair: Ed25519KeyPair;
  public readonly revocationRegistry: BitmapRevocationRegistry;
  private manifestVersion = 1;

  constructor(lguCode: number, municipalityName: string, existingKeyPair?: Ed25519KeyPair) {
    this.lguCode = lguCode;
    this.municipalityName = municipalityName;
    this.keyPair = existingKeyPair || generateAuthorityKeyPair();
    this.revocationRegistry = new BitmapRevocationRegistry(1_000_000);
  }

  public getPublicKey(): crypto.KeyObject {
    return this.keyPair.publicKey;
  }

  public getPrivateKey(): crypto.KeyObject {
    return this.keyPair.privateKey;
  }

  public getRawPublicKey(): Buffer {
    return this.keyPair.rawPublicKey;
  }

  /**
   * Issues a signed 97-byte municipal identity credential.
   */
  public issueCredential(
    citizenUuidHex: string,
    claimsMask: number,
    validityDurationSeconds = PROTOCOL_CONSTANTS.DEFAULT_VALIDITY_SECONDS
  ): IssuedCredentialOutput {
    const nowSec = Math.floor(Date.now() / 1000);
    const expSec = nowSec + validityDurationSeconds;

    const payloadHeader = packPayloadHeader(this.lguCode, citizenUuidHex, nowSec, expSec, claimsMask);
    const signature = signPayload(payloadHeader, this.keyPair.privateKey);
    const rawBuffer = packFullCredential(payloadHeader, signature);

    const cleanUuid = citizenUuidHex.replace(/-/g, "");
    const citizenIndex = Buffer.from(cleanUuid, "hex").readUInt32BE(12);

    return {
      rawBuffer,
      base64Url: rawBuffer.toString("base64url"),
      citizenPseudonym: cleanUuid,
      citizenIndex,
      issuedAt: new Date(nowSec * 1000),
      expiresAt: new Date(expSec * 1000),
    };
  }

  /**
   * Marks a citizen identity as revoked.
   */
  public revokeCredential(citizenIndex: number): void {
    this.revocationRegistry.revoke(citizenIndex);
  }

  /**
   * Restores an identity to active status.
   */
  public unrevokeCredential(citizenIndex: number): void {
    this.revocationRegistry.unrevoke(citizenIndex);
  }

  /**
   * Generates an offline-distributable, cryptographically signed revocation manifest.
   */
  public exportSignedRevocationManifest(): Buffer {
    const manifest = createSignedRevocationManifest(
      this.lguCode,
      this.manifestVersion++,
      this.revocationRegistry,
      this.keyPair.privateKey
    );
    return manifest;
  }
}
