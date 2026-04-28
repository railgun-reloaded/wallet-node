import { bigIntToBytes, padBytesLeft, stripHexPrefix } from '@railgun-reloaded/bytes'
import { poseidon } from '@railgun-reloaded/cryptography'

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
    const cleanRandom = stripHexPrefix(random).toLowerCase()

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
    const valueBytes = bigIntToBytes(value, 32)
    return poseidon([padBytesLeft(npk, 32), padBytesLeft(tokenHash, 32), valueBytes])
  }

  /**
   * Computes the note public key (NPK) from a master public key and random value.
   * NPK = poseidon(masterPublicKey, random)
   * @param masterPublicKey - The receiver's master public key as a Uint8Array
   * @param random - The note random value as a Uint8Array (16 bytes)
   * @returns The note public key as a Uint8Array
   * @throws {Error} If initializeCryptographyLibs() has not been called.
   */
  static computeNotePublicKey (masterPublicKey: Uint8Array, random: Uint8Array): Uint8Array {
    assertCryptoInitialized()
    return poseidon([padBytesLeft(masterPublicKey, 32), padBytesLeft(random, 32)])
  }

  /**
   * Computes the nullifier for a note at a given leaf index.
   * The nullifier uniquely identifies a note when it is spent.
   * @param nullifyingKey - The wallet's nullifying key as a Uint8Array
   * @param leafIndex - The note's position in the merkle tree
   * @returns The nullifier as a Uint8Array
   * @throws {Error} If initializeCryptographyLibs() has not been called.
   */
  static computeNullifier (nullifyingKey: Uint8Array, leafIndex: bigint): Uint8Array {
    assertCryptoInitialized()
    return poseidon([nullifyingKey, bigIntToBytes(leafIndex, 32)])
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
