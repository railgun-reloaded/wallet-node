import { poseidon } from '@railgun-reloaded/cryptography'

import { bigintToUint8Array } from '../hash'

import type { EncryptedData, LegacyCiphertext } from './definitions'

/**
 * Validates that random value is the correct length (16 bytes).
 * @param random - The random value to validate (hex string)
 * @throws {Error} If validation fails
 */
function assertValidNoteRandom (random: string): void {
  const cleanRandom = random.startsWith('0x') ? random.slice(2) : random

  if (cleanRandom.length !== 32) {
    throw new Error(
      `Random must be length 32 hex chars (16 bytes). Got ${random}.`
    )
  }
}

/**
 * Computes the note hash from npk, token hash, and value.
 * NOTE: Requires cryptography libraries to be initialized first via initializeCryptographyLibs()
 * @param npk - The note public key as a Uint8Array
 * @param tokenHash - The token hash as a Uint8Array
 * @param value - The note value as a bigint
 * @returns The note hash as a Uint8Array
 * @throws {Error} If cryptography libraries are not initialized
 */
function getNoteHash (npk: Uint8Array, tokenHash: Uint8Array, value: bigint): Uint8Array {
  const valueBytes = bigintToUint8Array(value, 16) // 128-bit value
  return poseidon([npk, tokenHash, valueBytes])
}

/**
 * Checks if a serialized note is in legacy format.
 * @param noteData - The serialized note data
 * @returns True if legacy format, false otherwise
 */
function isLegacyTransactNote (noteData: any): boolean {
  return 'encryptedRandom' in noteData
}

/**
 * Converts ciphertext to encrypted random data format [ivTag, data].
 * @param ciphertext - The ciphertext object
 * @returns Tuple of [ivTag, data]
 */
function ciphertextToEncryptedRandomData (ciphertext: LegacyCiphertext): EncryptedData {
  const ivTag = ciphertext.iv + ciphertext.tag
  const data = ciphertext.data[0] || ''
  return [ivTag, data]
}

/**
 * Converts encrypted random data format to ciphertext object.
 * @param encryptedRandom - Tuple of [ivTag, data]
 * @returns Ciphertext object
 */
function encryptedDataToCiphertext (encryptedRandom: EncryptedData): LegacyCiphertext {
  const [ivTag, data] = encryptedRandom
  return {
    iv: ivTag.slice(0, 32),
    tag: ivTag.slice(32),
    data: [data]
  }
}

export {
  assertValidNoteRandom,
  getNoteHash,
  isLegacyTransactNote,
  ciphertextToEncryptedRandomData,
  encryptedDataToCiphertext
}
