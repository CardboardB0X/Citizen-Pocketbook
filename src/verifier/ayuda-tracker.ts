import * as crypto from "node:crypto";

export interface AyudaDistributionEvent {
  eventId: string;
  eventName: string;
  rationItem: string;
  startedAt: number;
  active: boolean;
}

export interface AyudaClaimReceipt {
  receiptId: string;
  eventId: string;
  citizenPseudonym: string;
  citizenIndex: number;
  claimedAt: number;
  stationId: string;
  rationItem: string;
  receiptSignature: string;
}

export interface AyudaCheckResult {
  allowed: boolean;
  reason?: string;
  existingClaim?: AyudaClaimReceipt;
}

/**
 * Offline Anti-Double-Dipping Engine for Disaster Relief & Ayuda Distribution.
 * Prevents citizens from receiving duplicate relief packs across separate tents/checkpoints.
 */
export class AyudaDistributionTracker {
  private events: Map<string, AyudaDistributionEvent> = new Map();
  private claimsByEvent: Map<string, Map<string, AyudaClaimReceipt>> = new Map();
  private signingSecret: Buffer;

  constructor(signingSecret?: Buffer) {
    this.signingSecret = signingSecret ?? crypto.randomBytes(32);

    // Initialize default official Tanza municipal calamity events
    this.registerEvent({
      eventId: "TANZA-RICE-AYUDA-2026",
      eventName: "Lingap Bayanihan: Emergency Rice Subsidy (25kg)",
      rationItem: "25kg Premium Cavite Rice Pack",
      startedAt: Date.now() - 3600000,
      active: true,
    });

    this.registerEvent({
      eventId: "OSCA-MEDICINE-OCT2026",
      eventName: "Tanza OSCA Monthly Senior Maintenance Aid",
      rationItem: "Php 1,500 Essential Prescription Allowance",
      startedAt: Date.now() - 86400000,
      active: true,
    });
  }

  public registerEvent(event: AyudaDistributionEvent): void {
    this.events.set(event.eventId, event);
    if (!this.claimsByEvent.has(event.eventId)) {
      this.claimsByEvent.set(event.eventId, new Map());
    }
  }

  public getEvents(): AyudaDistributionEvent[] {
    return Array.from(this.events.values());
  }

  public checkEligibility(citizenPseudonym: string, eventId: string): AyudaCheckResult {
    const event = this.events.get(eventId);
    if (!event || !event.active) {
      return { allowed: false, reason: "Relief distribution event is inactive or invalid." };
    }

    const eventClaims = this.claimsByEvent.get(eventId);
    if (eventClaims && eventClaims.has(citizenPseudonym)) {
      const existing = eventClaims.get(citizenPseudonym)!;
      return {
        allowed: false,
        reason: `DUPLICATE CLAIM: Citizen already received relief at ${new Date(existing.claimedAt).toLocaleTimeString()}`,
        existingClaim: existing,
      };
    }

    return { allowed: true };
  }

  public recordClaim(
    citizenPseudonym: string,
    citizenIndex: number,
    eventId: string,
    stationId: string = "TERMINAL-TANZA-01"
  ): AyudaClaimReceipt {
    const check = this.checkEligibility(citizenPseudonym, eventId);
    if (!check.allowed) {
      throw new Error(check.reason);
    }

    const event = this.events.get(eventId)!;
    const now = Date.now();
    const receiptId = `RCPT-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;

    // Cryptographically sign receipt
    const signData = `${receiptId}:${eventId}:${citizenPseudonym}:${now}:${stationId}`;
    const receiptSignature = crypto.createHmac("sha256", this.signingSecret).update(signData).digest("hex");

    const receipt: AyudaClaimReceipt = {
      receiptId,
      eventId,
      citizenPseudonym,
      citizenIndex,
      claimedAt: now,
      stationId,
      rationItem: event.rationItem,
      receiptSignature,
    };

    this.claimsByEvent.get(eventId)!.set(citizenPseudonym, receipt);
    return receipt;
  }

  public getAllClaims(eventId?: string): AyudaClaimReceipt[] {
    if (eventId) {
      const map = this.claimsByEvent.get(eventId);
      return map ? Array.from(map.values()) : [];
    }

    const all: AyudaClaimReceipt[] = [];
    for (const map of this.claimsByEvent.values()) {
      all.push(...map.values());
    }
    return all;
  }
}
