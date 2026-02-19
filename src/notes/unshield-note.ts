import { decode, encode } from '@msgpack/msgpack'

import { hexToUint8Array, uint8ArrayToBigInt, uint8ArrayToHex } from '../hash'

import type { TokenData, TokenType, Unshield } from './definitions'
import { Note } from './note'
import { getNoteHash } from './note-utils'
import { computeTokenHash, deserializeTokenData, serializeTokenData } from './token-utils'

/**
 * Represents an Unshield note for converting private RAILGUN notes back into public assets.
 * This is the exit point for funds leaving the privacy system, sending tokens to a public
 * destination address on-chain.
 * Extends {@link Note} with a {@link toAddress}, a Poseidon {@link hash}, and an
 * {@link allowOverride} flag.
 *
 * Can be created directly, deserialized from msgpack-encoded bytes, or constructed
 * from on-chain unshield data via {@link UnshieldNote.fromUnshield}.
 */
class UnshieldNote extends Note {
  /**
   * The destination address for unshielding
   */
  toAddress: string

  /**
   * The note hash as a bigint
   */
  hash: bigint

  /**
   * Whether to allow override
   */
  allowOverride: boolean

  /**
   * Constructs a new UnshieldNote instance.
   * @param notePublicKey - The note public key (same as toAddress)
   * @param value - The note value
   * @param tokenData - The token data
   * @param random - Random value (16 bytes hex string)
   * @param toAddress - The destination address
   * @param hash - The note hash
   * @param allowOverride - Whether to allow override
   */
  constructor (
    notePublicKey: string,
    value: bigint,
    tokenData: TokenData,
    random: string,
    toAddress: string,
    hash: bigint,
    allowOverride: boolean
  ) {
    super(notePublicKey, value, tokenData, random)
    this.toAddress = toAddress
    this.hash = hash
    this.allowOverride = allowOverride
  }

  /**
   * Serializes the unshield note to a Uint8Array using msgpack encoding.
   * @returns The serialized unshield note
   */
  serialize (): Uint8Array {
    return encode({
      random: this.random,
      toAddress: this.toAddress,
      notePublicKey: this.notePublicKey,
      value: this.value.toString(),
      hash: this.hash.toString(),
      allowOverride: this.allowOverride,
      token: {
        tokenAddress: this.tokenData.tokenAddress,
        tokenType: this.tokenData.tokenType,
        tokenSubID: this.tokenData.tokenSubID,
      },
    })
  }

  /**
   * Deserializes an unshield note from a Uint8Array.
   * @param bytes - The serialized unshield note data
   * @returns A new UnshieldNote instance
   */
  static deserialize (bytes: Uint8Array): UnshieldNote {
    const { notePublicKey, random, value, token, toAddress, hash, allowOverride } = decode(bytes) as any

    return new UnshieldNote(
      notePublicKey,
      BigInt(value),
      deserializeTokenData(token),
      random,
      toAddress,
      BigInt(hash),
      allowOverride
    )
  }

  /**
   * Creates an UnshieldNote from unshield data.
   * The note hash is computed from amount + fee combined, matching the engine's behavior.
   * NOTE: Requires cryptography libraries to be initialized first via initializeCryptographyLibs()
   * @param unshield - The Unshield object
   * @param random - Random value (16 bytes hex string)
   * @returns A new UnshieldNote instance
   * @throws {Error} If required fields are missing or poseidon is not initialized
   */
  static fromUnshield (
    unshield: Unshield,
    random: string
  ): UnshieldNote {
    const { to, token: { tokenAddress, tokenSubID, tokenType }, amount, fee } = unshield

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

    const tokenData = serializeTokenData(
      uint8ArrayToHex(tokenAddress),
      tokenTypeNum,
      uint8ArrayToHex(tokenSubID)
    )

    const toAddress = uint8ArrayToHex(to)
    const tokenHashBytes = hexToUint8Array(computeTokenHash(tokenData))
    const hash = uint8ArrayToBigInt(getNoteHash(to, tokenHashBytes, amount + fee))

    return new UnshieldNote(
      toAddress,
      amount,
      tokenData,
      random,
      toAddress,
      hash,
      false // Default value
    )
  }

  /**
   * Computes the amount and fee from a total value and fee basis points.
   * @param value - The total value (amount + fee)
   * @param feeBasisPoints - The fee in basis points (e.g. 25 = 0.25%)
   * @returns The amount and fee
   */
  static getAmountFeeFromValue (
    value: bigint,
    feeBasisPoints: bigint
  ): { amount: bigint, fee: bigint } {
    const BASIS_POINTS = 10000n
    const fee = (value * feeBasisPoints) / BASIS_POINTS
    const amount = value - fee
    return { amount, fee }
  }
}

export { UnshieldNote }
