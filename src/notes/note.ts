import { poseidon } from '@railgun-reloaded/cryptography'

import { bigintToUint8Array, hexlify } from '../encoding'
import { assertCryptoInitialized } from '../keys'

import type { TokenData } from './definitions'
import { assertValidNoteToken, computeTokenHash } from './token-utils'

/**
 * Base parameters shared by all note types.
 */
type NoteParams = {
  notePublicKey: string
  value: bigint
  tokenData: TokenData
  random: string
}

/**
 * Abstract base class for all note types.
 * Provides common properties and serialization interface.
 */
abstract class Note {
  /**
   * The note public key (npk) as a hex string
   */
  notePublicKey: string

  /**
   * The note value as a bigint
   */
  value: bigint

  /**
   * The token data containing address, type, and subID
   */
  tokenData: TokenData

  /**
   * The token hash as a hex string
   */
  tokenHash: string

  /**
   * Random value (16 bytes hex string)
   */
  random: string

  /**
   * Constructs a new Note instance.
   * @param params - The note parameters
   */
  constructor (params: NoteParams) {
    Note.assertValidRandom(params.random)
    assertValidNoteToken(params.tokenData, params.value)
    this.notePublicKey = params.notePublicKey
    this.value = params.value
    this.tokenData = params.tokenData
    this.tokenHash = computeTokenHash(params.tokenData)
    this.random = params.random
  }

  /**
   * Validates that random value is the correct length (16 bytes).
   * @param random - The random value to validate (hex string)
   * @throws {Error} If validation fails
   */
  static assertValidRandom (random: string): void {
    const cleanRandom = hexlify(random)

    if (cleanRandom.length !== 32) {
      throw new Error(
        `Random must be length 32 hex chars (16 bytes). Got ${random}.`
      )
    }
  }

  /**
   * Computes the note hash from npk, token hash, and value.
   * @param npk - The note public key as a Uint8Array
   * @param tokenHash - The token hash as a Uint8Array
   * @param value - The note value as a bigint
   * @returns The note hash as a Uint8Array
   * @throws {Error} If initializeCryptographyLibs() has not been called.
   */
  static getHash (npk: Uint8Array, tokenHash: Uint8Array, value: bigint): Uint8Array {
    assertCryptoInitialized()
    const valueBytes = bigintToUint8Array(value, 16) // 128-bit value
    return poseidon([npk, tokenHash, valueBytes])
  }

  /**
   * Serializes the note to a Uint8Array.
   * Must be implemented by subclasses.
   * @returns The serialized note
   */
  abstract serialize (): Uint8Array
}

export type { NoteParams }
export { Note }
