import * as crypto from "node:crypto";

export interface BiometricMatchResult {
  matched: boolean;
  similarityScore: number; // 0.0 to 1.0 (1.0 = identical)
  distanceBits: number;
  thresholdPassed: boolean;
}

/**
 * Computes a deterministic 16-byte facial template hash from normalized landmark vectors.
 */
export function hashFacialFeatureVector(landmarks: number[]): Buffer {
  const floatBuffer = Buffer.alloc(landmarks.length * 4);
  for (let i = 0; i < landmarks.length; i++) {
    floatBuffer.writeFloatLE(landmarks[i], i * 4);
  }
  return crypto.createHash("sha256").update(floatBuffer).digest().subarray(0, 16);
}

/**
 * Performs offline 1:1 facial biometric matching via bitwise Hamming distance.
 * Returns true if similarity exceeds threshold (default: 80% confidence).
 */
export function verifyBiometricTemplate(
  enrolledTemplateHash: Buffer,
  presentedTemplateHash: Buffer,
  similarityThreshold = 0.80
): BiometricMatchResult {
  if (enrolledTemplateHash.length !== 16 || presentedTemplateHash.length !== 16) {
    throw new Error("Biometric template hashes must be exactly 16 bytes.");
  }

  let distanceBits = 0;
  const totalBits = 128; // 16 bytes * 8 bits

  for (let i = 0; i < 16; i++) {
    let xor = enrolledTemplateHash[i] ^ presentedTemplateHash[i];
    while (xor > 0) {
      distanceBits += xor & 1;
      xor >>= 1;
    }
  }

  const similarityScore = (totalBits - distanceBits) / totalBits;
  const matched = similarityScore >= similarityThreshold;

  return {
    matched,
    similarityScore: Number(similarityScore.toFixed(4)),
    distanceBits,
    thresholdPassed: matched,
  };
}
