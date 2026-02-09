import type { TokenData } from './definitions.js'
import { computeTokenHash } from './token-utils.js'

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
   * @param notePublicKey - The note public key
   * @param value - The note value
   * @param tokenData - The token data
   * @param random - Random value (16 bytes hex string)
   */
  constructor (
    notePublicKey: string,
    value: bigint,
    tokenData: TokenData,
    random: string
  ) {
    this.notePublicKey = notePublicKey
    this.value = value
    this.tokenData = tokenData
    this.tokenHash = computeTokenHash(tokenData)
    this.random = random
  }

  /**
   * Serializes the note to a Uint8Array.
   * Must be implemented by subclasses.
   * @returns The serialized note
   */
  abstract serialize (): Uint8Array

  /**
   * Gets the computed token hash for this note.
   * @returns The token hash
   */
  getTokenHash (): string {
    return this.tokenHash
  }
}

export { Note }
