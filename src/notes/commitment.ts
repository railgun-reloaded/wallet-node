import { hexToUint8Array } from '../hash'

import type { Ciphertext, CommitmentCiphertextStruct, FormattedCommitmentCiphertext } from './definitions'

/**
 * Strips 0x prefix and pads hex string to the target byte length (left-padded with zeros).
 * @param hex - hex string, optionally prefixed with 0x
 * @param byteLength - target length in bytes
 * @returns padded hex string without 0x prefix
 */
function formatToByteLength (hex: string, byteLength: number): string {
  const stripped = hex.startsWith('0x') ? hex.slice(2) : hex
  return stripped.padStart(byteLength * 2, '0')
}

/**
 * Formats raw on-chain commitment ciphertext into the Uint8Array-based
 * format expected by decryptCommitment.
 *
 * Conversion:
 *   ciphertext[0] (32 bytes) → iv (first 16 bytes) + tag (last 16 bytes)
 *   ciphertext[1..] → data blocks (32 bytes each)
 *
 * Mirrors engine's V2Events.formatCommitmentCiphertext.
 * @param struct - raw on-chain commitment ciphertext with hex strings
 * @returns formatted commitment ciphertext with Uint8Array fields
 */
function formatCommitmentCiphertext (
  struct: CommitmentCiphertextStruct
): FormattedCommitmentCiphertext {
  const ciphertextFormatted = struct.ciphertext.map(el => formatToByteLength(el, 32))
  const ivTagHex = ciphertextFormatted[0]

  if (!ivTagHex) {
    throw new Error('Commitment ciphertext must have at least one element')
  }

  const ciphertext: Ciphertext = {
    iv: hexToUint8Array('0x' + ivTagHex.slice(0, 32)),
    tag: hexToUint8Array('0x' + ivTagHex.slice(32, 64)),
    data: ciphertextFormatted.slice(1).map(h => hexToUint8Array('0x' + h)),
  }

  return {
    ciphertext,
    blindedSenderViewingKey: hexToUint8Array('0x' + formatToByteLength(struct.blindedSenderViewingKey, 32)),
    blindedReceiverViewingKey: hexToUint8Array('0x' + formatToByteLength(struct.blindedReceiverViewingKey, 32)),
    annotationData: hexToUint8Array(struct.annotationData),
    memo: hexToUint8Array(struct.memo),
  }
}

export { formatCommitmentCiphertext }
