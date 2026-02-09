import { decode, encode } from '@msgpack/msgpack'

import { uint8ArrayToBigInt, uint8ArrayToHex } from '../hash.js'

import type { GeneratedCommitment, ShieldCommitment, TokenData, TokenType } from './definitions.js'
import { Note } from './note.js'
import { deserializeTokenData } from './token-utils.js'

/**
 * Represents a Shield note with master public key.
 */
class ShieldNote extends Note {
  /**
   * The master public key as a bigint
   */
  masterPublicKey: bigint

  /**
   * Constructs a new ShieldNote instance.
   * @param notePublicKey - The note public key
   * @param value - The note value
   * @param tokenData - The token data
   * @param random - Random value (16 bytes hex string)
   * @param masterPublicKey - The master public key
   */
  constructor (
    notePublicKey: string,
    value: bigint,
    tokenData: TokenData,
    random: string,
    masterPublicKey: bigint
  ) {
    super(notePublicKey, value, tokenData, random)
    this.masterPublicKey = masterPublicKey
  }

  /**
   * Serializes the shield note to a Uint8Array using msgpack encoding.
   * @returns The serialized shield note
   */
  serialize (): Uint8Array {
    return encode({
      random: this.random,
      tokenHash: this.tokenHash,
      notePublicKey: this.notePublicKey,
      value: this.value.toString(),
      masterPublicKey: this.masterPublicKey.toString(),
      token: {
        tokenAddress: this.tokenData.tokenAddress,
        tokenType: this.tokenData.tokenType,
        tokenSubID: this.tokenData.tokenSubID,
      },
    })
  }

  /**
   * Deserializes a shield note from a Uint8Array.
   * @param bytes - The serialized shield note data
   * @returns A new ShieldNote instance
   */
  static deserialize (bytes: Uint8Array): ShieldNote {
    const { notePublicKey, masterPublicKey, token, value, random } = decode(bytes) as any

    return new ShieldNote(
      notePublicKey,
      BigInt(value),
      deserializeTokenData(token),
      random,
      BigInt(masterPublicKey)
    )
  }

  /**
   * Creates a ShieldNote from commitment data.
   * Handles both GeneratedCommitment and ShieldCommitment types.
   * NOTE: Requires cryptography libraries to be initialized first via initializeCryptographyLibs()
   * @param commitment - The commitment object
   * @param masterPublicKey - Optional master public key as bigint (required for GeneratedCommitment)
   * @returns A new ShieldNote instance
   * @throws {Error} If required fields are missing or poseidon is not initialized
   */
  static fromCommitment (
    commitment: GeneratedCommitment | ShieldCommitment,
    masterPublicKey?: bigint
  ): ShieldNote {
    // Extract random from encryptedRandom (GeneratedCommitment) or encryptedBundle (ShieldCommitment)
    const randomBytes = 'encryptedRandom' in commitment
      ? commitment.encryptedRandom?.[0]
      : commitment.encryptedBundle?.[0]

    if (!randomBytes) {
      throw new Error('Missing random data in commitment')
    }

    // Extract masterPublicKey from shieldKey (ShieldCommitment) or use provided parameter
    let mpk: bigint
    if ('shieldKey' in commitment && commitment.shieldKey) {
      mpk = uint8ArrayToBigInt(commitment.shieldKey)
    } else if (masterPublicKey !== undefined) {
      mpk = masterPublicKey
    } else {
      throw new Error('Missing masterPublicKey - required for GeneratedCommitment')
    }

    const { npk, value, token: { tokenAddress, tokenSubID, tokenType } } = commitment.preimage

    // Convert tokenType string to TokenType enum number
    let tokenTypeNum: TokenType
    switch (tokenType.toUpperCase()) {
      case 'ERC20':
        tokenTypeNum = 0 // TokenType.ERC20
        break
      case 'ERC721':
        tokenTypeNum = 1 // TokenType.ERC721
        break
      case 'ERC1155':
        tokenTypeNum = 2 // TokenType.ERC1155
        break
      default:
        throw new Error(`Invalid tokenType: ${tokenType}`)
    }

    const tokenData: TokenData = {
      tokenType: tokenTypeNum,
      tokenAddress: uint8ArrayToHex(tokenAddress),
      tokenSubID: uint8ArrayToHex(tokenSubID),
    }

    return new ShieldNote(
      uint8ArrayToHex(npk),
      value,
      tokenData,
      uint8ArrayToHex(randomBytes),
      mpk
    )
  }
}

export { ShieldNote }
