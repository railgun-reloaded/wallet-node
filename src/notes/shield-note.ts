import { decode, encode } from '@msgpack/msgpack'
import { AES } from '@railgun-reloaded/cryptography'

import { hexToUint8Array, uint8ArrayToHex } from '../encoding'
import { getSharedSymmetricKey } from '../keys'

import type { GeneratedCommitment, ShieldCommitment, TokenData, TokenType } from './definitions'
import { Note } from './note'
import { deserializeTokenData, serializeTokenData } from './token-utils'

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
    masterPublicKey: Uint8Array
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
      masterPublicKey: uint8ArrayToHex(this.masterPublicKey),
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
      hexToUint8Array(masterPublicKey)
    )
  }

  /**
   * Creates a ShieldNote from a GeneratedCommitment (V1).
   * The random value is stored in plaintext in encryptedRandom[0].
   * NOTE: Requires cryptography libraries to be initialized first via initializeCryptographyLibs()
   * @param commitment - The GeneratedCommitment object
   * @param masterPublicKey - The master public key
   * @returns A new ShieldNote instance
   */
  static fromGeneratedCommitment (
    commitment: GeneratedCommitment,
    masterPublicKey: Uint8Array
  ): ShieldNote {
    const randomBytes = commitment.encryptedRandom?.[0]
    if (!randomBytes) {
      throw new Error('Missing random data in GeneratedCommitment')
    }

    return ShieldNote.buildFromPreimage(commitment, uint8ArrayToHex(randomBytes), masterPublicKey)
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

      return ShieldNote.buildFromPreimage(commitment, uint8ArrayToHex(randomBytes), masterPublicKey)
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

    return new ShieldNote(
      uint8ArrayToHex(npk),
      value,
      tokenData,
      random,
      masterPublicKey
    )
  }
}

export { ShieldNote }
