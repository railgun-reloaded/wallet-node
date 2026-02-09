import { poseidon } from '@railgun-reloaded/cryptography'

import { bigintToUint8Array, hexToUint8Array, uint8ArrayToBigInt } from '../hash.js'

import type { TokenData } from './definitions.js'
import { computeTokenHash } from './token-utils.js'

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
 * Computes the note hash from address, token data, and value.
 * NOTE: Requires cryptography libraries to be initialized first via initializeCryptographyLibs()
 * @param address - The note public key (npk) as a hex string
 * @param tokenData - The token data containing type, address, and subID
 * @param value - The note value as a bigint
 * @returns The note hash as a bigint
 * @throws {Error} If cryptography libraries are not initialized
 */
function getNoteHash (address: string, tokenData: TokenData, value: bigint): bigint {
  const tokenHash = computeTokenHash(tokenData)
  const addressBytes = hexToUint8Array(address)
  const tokenHashBytes = hexToUint8Array(tokenHash)
  const valueBytes = bigintToUint8Array(value, 16) // 128-bit value

  const hash = poseidon([addressBytes, tokenHashBytes, valueBytes])
  return uint8ArrayToBigInt(hash)
}

export {
  assertValidNoteRandom,
  getNoteHash
}
