import * as crypto from "node:crypto";
import { CorruptedPayloadError } from "../common/errors.js";

export const MESH_CONSTANTS = {
  MAGIC: 0x5152, // ASCII "QR" (Optical Relay Frame)
  HEADER_SIZE: 14, // 2B Magic + 4B SessionId + 2B SeqIdx + 2B TotalChunks + 4B CRC32
  DEFAULT_CHUNK_SIZE: 140, // Bytes per QR frame for high-speed camera optical decodability
} as const;

export interface OpticalFrame {
  sessionId: number;
  sequenceIndex: number;
  totalChunks: number;
  dataChunk: Buffer;
  crc32: number;
  rawBuffer: Buffer;
  base64Url: string;
}

export interface AssemblyProgress {
  sessionId: number;
  totalChunks: number;
  receivedCount: number;
  percentComplete: number;
  isComplete: boolean;
  missingIndices: number[];
}

/**
 * Computes standard IEEE 802.3 CRC-32 checksum.
 */
export function computeCrc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    crc ^= byte;
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Splits a municipal sync package or delta manifest into a sequence of optical QR frames.
 */
export function fragmentPayloadForOpticalRelay(
  payload: Buffer,
  chunkSize: number = MESH_CONSTANTS.DEFAULT_CHUNK_SIZE,
  sessionId?: number
): OpticalFrame[] {
  const session = sessionId ?? crypto.randomInt(100000, 999999);
  const totalChunks = Math.ceil(payload.length / chunkSize) || 1;
  const frames: OpticalFrame[] = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, payload.length);
    const slice = payload.subarray(start, end);
    const crc = computeCrc32(slice);

    const frameBuf = Buffer.alloc(MESH_CONSTANTS.HEADER_SIZE + slice.length);
    frameBuf.writeUInt16BE(MESH_CONSTANTS.MAGIC, 0);
    frameBuf.writeUInt32BE(session, 2);
    frameBuf.writeUInt16BE(i, 6);
    frameBuf.writeUInt16BE(totalChunks, 8);
    frameBuf.writeUInt32BE(crc, 10);
    slice.copy(frameBuf, MESH_CONSTANTS.HEADER_SIZE);

    frames.push({
      sessionId: session,
      sequenceIndex: i,
      totalChunks,
      dataChunk: slice,
      crc32: crc,
      rawBuffer: frameBuf,
      base64Url: frameBuf.toString("base64url"),
    });
  }

  return frames;
}

/**
 * Decodes a raw optical frame buffer or Base64URL string.
 */
export function unpackOpticalFrame(input: Buffer | string): OpticalFrame {
  const buf = typeof input === "string" ? Buffer.from(input, "base64url") : input;
  if (buf.length < MESH_CONSTANTS.HEADER_SIZE) {
    throw new CorruptedPayloadError("Optical frame truncated: less than 14 bytes");
  }

  const magic = buf.readUInt16BE(0);
  if (magic !== MESH_CONSTANTS.MAGIC) {
    throw new CorruptedPayloadError(`Invalid optical frame magic: 0x${magic.toString(16)}`);
  }

  const sessionId = buf.readUInt32BE(2);
  const sequenceIndex = buf.readUInt16BE(6);
  const totalChunks = buf.readUInt16BE(8);
  const expectedCrc = buf.readUInt32BE(10);
  const dataChunk = buf.subarray(MESH_CONSTANTS.HEADER_SIZE);

  const actualCrc = computeCrc32(dataChunk);
  if (actualCrc !== expectedCrc) {
    throw new CorruptedPayloadError(`CRC32 mismatch on optical chunk ${sequenceIndex}: expected ${expectedCrc}, got ${actualCrc}`);
  }

  return {
    sessionId,
    sequenceIndex,
    totalChunks,
    dataChunk,
    crc32: actualCrc,
    rawBuffer: buf,
    base64Url: buf.toString("base64url"),
  };
}

/**
 * In-memory assembler for re-collecting multi-frame optical QR transmissions.
 */
export class OpticalMeshReceiver {
  private currentSessionId: number | null = null;
  private totalChunks: number = 0;
  private chunks: Map<number, Buffer> = new Map();

  public reset(): void {
    this.currentSessionId = null;
    this.totalChunks = 0;
    this.chunks.clear();
  }

  /**
   * Ingests a scanned frame string or buffer.
   */
  public ingestFrame(frameData: Buffer | string): AssemblyProgress {
    const frame = unpackOpticalFrame(frameData);

    // If new session detected, reset state
    if (this.currentSessionId === null || this.currentSessionId !== frame.sessionId) {
      this.currentSessionId = frame.sessionId;
      this.totalChunks = frame.totalChunks;
      this.chunks.clear();
    }

    this.chunks.set(frame.sequenceIndex, frame.dataChunk);

    const receivedCount = this.chunks.size;
    const isComplete = receivedCount === this.totalChunks;
    const missing: number[] = [];
    for (let i = 0; i < this.totalChunks; i++) {
      if (!this.chunks.has(i)) {
        missing.push(i);
      }
    }

    return {
      sessionId: this.currentSessionId,
      totalChunks: this.totalChunks,
      receivedCount,
      percentComplete: Math.round((receivedCount / this.totalChunks) * 100),
      isComplete,
      missingIndices: missing,
    };
  }

  /**
   * Assembles the completed payload buffer.
   */
  public assemble(): Buffer {
    if (!this.isComplete()) {
      throw new Error(`Cannot assemble incomplete transmission: received ${this.chunks.size}/${this.totalChunks} chunks`);
    }

    const orderedBuffers: Buffer[] = [];
    for (let i = 0; i < this.totalChunks; i++) {
      orderedBuffers.push(this.chunks.get(i)!);
    }

    return Buffer.concat(orderedBuffers);
  }

  public isComplete(): boolean {
    return this.totalChunks > 0 && this.chunks.size === this.totalChunks;
  }

  public getSessionId(): number | null {
    return this.currentSessionId;
  }
}
