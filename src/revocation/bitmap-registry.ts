import { CorruptedPayloadError } from "../common/errors.js";

/**
 * Compact memory-bounded bit-indexed revocation accumulator.
 * Supports up to 2,000,000 citizens per LGU within < 250 KB of RAM.
 * Bit = 0: Active, Bit = 1: Revoked.
 */
export class BitmapRevocationRegistry {
  private bitmap: Buffer;
  public readonly capacity: number;

  constructor(capacity = 1_000_000) {
    this.capacity = capacity;
    const byteSize = Math.ceil(capacity / 8);
    this.bitmap = Buffer.alloc(byteSize);
  }

  /**
   * Marks a citizen index as revoked.
   */
  public revoke(citizenIndex: number): void {
    const targetIndex = Math.abs(citizenIndex) % this.capacity;
    const byteOffset = Math.floor(targetIndex / 8);
    const bitOffset = targetIndex % 8;
    this.bitmap[byteOffset] |= 1 << bitOffset;
  }

  /**
   * Restores a previously revoked citizen index to active status.
   */
  public unrevoke(citizenIndex: number): void {
    const targetIndex = Math.abs(citizenIndex) % this.capacity;
    const byteOffset = Math.floor(targetIndex / 8);
    const bitOffset = targetIndex % 8;
    this.bitmap[byteOffset] &= ~(1 << bitOffset);
  }

  /**
   * Checks if a citizen index is revoked. O(1) bitwise evaluation.
   */
  public isRevoked(citizenIndex: number): boolean {
    const targetIndex = Math.abs(citizenIndex) % this.capacity;
    const byteOffset = Math.floor(targetIndex / 8);
    const bitOffset = targetIndex % 8;
    return (this.bitmap[byteOffset] & (1 << bitOffset)) !== 0;
  }

  /**
   * Returns total count of revoked entries in the registry.
   */
  public getRevokedCount(): number {
    let count = 0;
    for (let i = 0; i < this.bitmap.length; i++) {
      let b = this.bitmap[i];
      while (b > 0) {
        count += b & 1;
        b >>= 1;
      }
    }
    return count;
  }

  /**
   * Serializes non-zero 32-byte chunks for low-bandwidth offline distribution.
   * Format per chunk: [chunk_offset: uint32_be (4B)] + [chunk_data (32B)]
   */
  public exportCompressed(): Buffer {
    const CHUNK_SIZE = 32;
    const totalChunks = Math.ceil(this.bitmap.length / CHUNK_SIZE);
    const dirtyChunks: Buffer[] = [];

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, this.bitmap.length);
      const slice = this.bitmap.subarray(start, end);

      // Check if chunk has any revoked bits set
      let hasData = false;
      for (let j = 0; j < slice.length; j++) {
        if (slice[j] !== 0) {
          hasData = true;
          break;
        }
      }

      if (hasData) {
        const header = Buffer.alloc(4);
        header.writeUInt32BE(i, 0);
        const chunkData = Buffer.alloc(CHUNK_SIZE);
        slice.copy(chunkData, 0);
        dirtyChunks.push(Buffer.concat([header, chunkData]));
      }
    }

    const countHeader = Buffer.alloc(8);
    countHeader.writeUInt32BE(this.capacity, 0);
    countHeader.writeUInt32BE(dirtyChunks.length, 4);

    return Buffer.concat([countHeader, ...dirtyChunks]);
  }

  /**
   * Imports a compressed chunked revocation buffer.
   */
  public importCompressed(compressedBuffer: Buffer): void {
    if (compressedBuffer.length < 8) {
      throw new CorruptedPayloadError("Invalid revocation manifest buffer: header too short.");
    }

    const manifestCapacity = compressedBuffer.readUInt32BE(0);
    const chunkCount = compressedBuffer.readUInt32BE(4);
    const CHUNK_SIZE = 32;
    const ENTRY_SIZE = 4 + CHUNK_SIZE; // 36 bytes

    if (compressedBuffer.length !== 8 + chunkCount * ENTRY_SIZE) {
      throw new CorruptedPayloadError("Revocation manifest length does not match chunk count header.");
    }

    // Reset bitmap
    this.bitmap.fill(0);

    let offset = 8;
    for (let c = 0; c < chunkCount; c++) {
      const chunkIndex = compressedBuffer.readUInt32BE(offset);
      const chunkData = compressedBuffer.subarray(offset + 4, offset + ENTRY_SIZE);

      const targetStart = chunkIndex * CHUNK_SIZE;
      if (targetStart + CHUNK_SIZE <= this.bitmap.length) {
        chunkData.copy(this.bitmap, targetStart, 0, CHUNK_SIZE);
      }
      offset += ENTRY_SIZE;
    }
  }

  public getRawBuffer(): Buffer {
    return this.bitmap;
  }
}
