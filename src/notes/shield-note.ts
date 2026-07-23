import { decode, encode } from '@msgpack/msgpack'
import { randomBytes } from '@noble/hashes/utils'
import { bytesToHex, hexToBytes } from '@railgun-reloaded/bytes'
import { AES } from '@railgun-reloaded/cryptography'

import { getSharedSymmetricKey } from '../keys.js'

import type { GeneratedCommitment, ShieldCommitment, TokenData } from './definitions.js'
import { TokenType } from './definitions.js'
import type { NoteParams } from './note.js'
import { Note } from './note.js'
import { assertValidNoteToken, deserializeTokenData, serializeTokenData } from './token-utils.js'

/**
 * Parameters for constructing a ShieldNote.
 */
type ShieldNoteParams = NoteParams & {
  masterPublicKey: Uint8Array
  shieldFee?: bigint | undefined
  blockNumber?: number | undefined
}

/**
 * Parameters for creating a new ShieldNote for a recipient.
 */
type ShieldNoteCreateParams = {
  masterPublicKey: Uint8Array
  value: bigint
  tokenData: TokenData
  random?: Uint8Array | undefined
}

/** Maximum note value representable in the contract's uint120 preimage field. */
const UINT_120_MAX = 2n ** 120n - 1n

/**
 * Represents a Shield note for converting public assets into private RAILGUN notes.
 * This is the entry point for funds entering the privacy system via on-chain shield transactions.
 * Extends {@link Note} with a {@link masterPublicKey} that identifies the receiving wallet.
 *
 * Can be created directly, deserialized from msgpack-encoded bytes, or reconstructed
 * from on-chain commitment data ({@link GeneratedCommitment} or {@link ShieldCommitment}).
 */
class ShieldNote extends Note {
  /**
   * The master public key as a Uint8Array (32 bytes)
   */
  masterPublicKey: Uint8Array

  /**
   * Optional shield fee
   */
  shieldFee: bigint | undefined

  /**
   * Optional block number
   */
  blockNumber: number | undefined

  /**
   * Constructs a new ShieldNote instance.
   * @param params - The shield note parameters
   */
  constructor (params: ShieldNoteParams) {
    super(params)
    this.masterPublicKey = params.masterPublicKey
    this.shieldFee = params.shieldFee
    this.blockNumber = params.blockNumber
  }

  /**
   * Creates a new ShieldNote for a recipient identified by their master public key.
   * Supports ERC20 and ERC721 token data. Derives the note public key from the
   * master public key and the note random, generating a fresh 16-byte random when
   * one is not supplied. The note carries the full pre-fee shield value; the
   * shield fee is deducted on-chain.
   * @param params - The creation parameters
   * @returns A new ShieldNote instance
   * @throws {Error} If a parameter is invalid or initializeCryptographyLibs() has not been called.
   */
  static create (params: ShieldNoteCreateParams): ShieldNote {
    const { masterPublicKey, value, tokenData } = params

    if (masterPublicKey.length !== 32) {
      throw new Error(`Master public key must be 32 bytes. Got ${masterPublicKey.length} bytes.`)
    }
    if (params.random !== undefined && params.random.length !== 16) {
      throw new Error(`Random must be 16 bytes. Got ${params.random.length} bytes.`)
    }
    if (tokenData.tokenType !== TokenType.ERC20 && tokenData.tokenType !== TokenType.ERC721) {
      throw new Error(`Unsupported token type for shield note creation: ${tokenData.tokenType}`)
    }
    if (value <= 0n) {
      throw new Error(`Shield note value must be positive. Got ${value}.`)
    }
    if (value > UINT_120_MAX) {
      throw new Error(`Shield note value must fit uint120. Got ${value}.`)
    }
    assertValidNoteToken(tokenData, value)

    const random = params.random ?? randomBytes(16)
    const notePublicKey = Note.computeNotePublicKey(masterPublicKey, random)

    return new ShieldNote({
      notePublicKey: bytesToHex(notePublicKey, { prefix: true }),
      value,
      tokenData,
      random: bytesToHex(random, { prefix: true }),
      masterPublicKey,
    })
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
      masterPublicKey: bytesToHex(this.masterPublicKey, { prefix: true }),
      token: {
        tokenAddress: this.tokenData.tokenAddress,
        tokenType: this.tokenData.tokenType,
        tokenSubID: this.tokenData.tokenSubID,
      },
      shieldFee: this.shieldFee?.toString(),
      blockNumber: this.blockNumber,
    })
  }

  /**
   * Deserializes a shield note from a Uint8Array.
   * @param bytes - The serialized shield note data
   * @returns A new ShieldNote instance
   */
  static deserialize (bytes: Uint8Array): ShieldNote {
    const { notePublicKey, masterPublicKey, token, value, random, shieldFee, blockNumber } = decode(bytes) as any

    return new ShieldNote({
      notePublicKey,
      value: BigInt(value),
      tokenData: deserializeTokenData(token),
      random,
      masterPublicKey: hexToBytes(masterPublicKey),
      shieldFee: shieldFee ? BigInt(shieldFee) : undefined,
      blockNumber: blockNumber ?? undefined,
    })
  }

  /**
   * Creates a ShieldNote from a GeneratedCommitment (V1).
   * The random is encrypted in encryptedRandom using AES-GCM with the viewing private key.
   * encryptedRandom layout:
   *   [0] = ivTag (32 bytes: iv 16 + tag 16)
   *   [1] = encrypted random data (16 bytes)
   * @param commitment - The GeneratedCommitment object
   * @param viewingPrivateKey - The wallet's viewing private key for decryption
   * @param masterPublicKey - The master public key
   * @returns A new ShieldNote instance, or null if decryption fails (wrong viewing key)
   */
  static fromGeneratedCommitment (
    commitment: GeneratedCommitment,
    viewingPrivateKey: Uint8Array,
    masterPublicKey: Uint8Array
  ): ShieldNote | null {
    const ivTag = commitment.encryptedRandom?.[0]
    const encryptedData = commitment.encryptedRandom?.[1]
    if (!ivTag || !encryptedData) {
      throw new Error('Missing encryptedRandom data in GeneratedCommitment')
    }

    try {
      const iv = ivTag.slice(0, 16)
      const tag = ivTag.slice(16, 32)
      const decrypted = AES.decryptGCM({ iv, tag, data: [encryptedData] }, viewingPrivateKey)
      const randomBytes = decrypted[0]!

      return ShieldNote.buildFromPreimage(commitment, bytesToHex(randomBytes, { prefix: true }), masterPublicKey)
    } catch {
      return null
    }
  }

  /**
   * Creates a ShieldNote from a ShieldCommitment (V2+).
   * The random is encrypted in encryptedBundle and must be decrypted
   * using ECDH(viewingPrivateKey, shieldKey).
   * NOTE: shieldKey is the shielder's public viewing key (used only for ECDH),
   * NOT the master public key.
   * NOTE: Requires cryptography libraries to be initialized first via initializeCryptographyLibs()
   * @param commitment - The ShieldCommitment object
   * @param viewingPrivateKey - The wallet's viewing private key for ECDH decryption
   * @param masterPublicKey - The wallet's master public key
   * @returns A new ShieldNote instance, or null if decryption fails (not addressed to this wallet)
   */
  static async fromShieldCommitment (
    commitment: ShieldCommitment,
    viewingPrivateKey: Uint8Array,
    masterPublicKey: Uint8Array
  ): Promise<ShieldNote | null> {
    if (!commitment.encryptedBundle || commitment.encryptedBundle.length < 3) {
      throw new Error('Invalid encryptedBundle in ShieldCommitment')
    }

    const sharedKey = await getSharedSymmetricKey(viewingPrivateKey, commitment.shieldKey)
    if (!sharedKey) {
      return null
    }

    try {
      // Bundle format
      // [0] = iv (16 bytes) + tag (16 bytes)
      // [1] = encrypted random data (16 bytes) + encrypted receiver IV (16 bytes)
      // [2] = encrypted receiver data (not needed here)
      const ivTag = commitment.encryptedBundle[0]!
      const iv = ivTag.slice(0, 16)
      const tag = ivTag.slice(16, 32)
      const data = [commitment.encryptedBundle[1]!.slice(0, 16)]

      const decrypted = AES.decryptGCM({ iv, tag, data }, sharedKey)

      // The decrypted block is the random value (16 bytes)
      const randomBytes = decrypted[0]!

      return ShieldNote.buildFromPreimage(commitment, bytesToHex(randomBytes, { prefix: true }), masterPublicKey)
    } catch {
      // Decryption failed — commitment not addressed to this wallet
      return null
    }
  }

  /**
   * Builds a ShieldNote from a commitment's preimage data and a decrypted random value.
   * @param commitment - The commitment containing the preimage
   * @param random - The decrypted random value as hex string
   * @param masterPublicKey - The master public key
   * @returns A new ShieldNote instance
   */
  private static buildFromPreimage (
    commitment: GeneratedCommitment | ShieldCommitment,
    random: string,
    masterPublicKey: Uint8Array
  ): ShieldNote {
    const { npk, value, token: { tokenAddress, tokenSubID, tokenType } } = commitment.preimage

    let tokenTypeNum: TokenType
    switch (tokenType.toUpperCase()) {
      case 'ERC20':
        tokenTypeNum = TokenType.ERC20
        break
      case 'ERC721':
        tokenTypeNum = TokenType.ERC721
        break
      case 'ERC1155':
        tokenTypeNum = TokenType.ERC1155
        break
      default:
        throw new Error(`Invalid tokenType: ${tokenType}`)
    }

    const tokenData = serializeTokenData(
      tokenAddress,
      tokenTypeNum,
      tokenSubID
    )

    return new ShieldNote({
      notePublicKey: bytesToHex(npk, { prefix: true }),
      value,
      tokenData,
      random,
      masterPublicKey,
      shieldFee: 'fee' in commitment ? commitment.fee : undefined,
    })
  }
}

export type { ShieldNoteParams, ShieldNoteCreateParams }
export { ShieldNote }
