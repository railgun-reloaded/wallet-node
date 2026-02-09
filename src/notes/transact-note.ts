import { decode, encode } from '@msgpack/msgpack'
import { AES } from '@railgun-reloaded/cryptography'

import { hexToUint8Array, uint8ArrayToHex } from '../hash.js'
import { getSharedSymmetricKey } from '../keys.js'

import type { AddressData, Ciphertext, EncryptedCommitment, EncryptedData, LegacyCiphertext, TokenData, TransactCommitment } from './definitions.js'
import { getNoteHash } from './note-utils.js'
import { Note } from './note.js'
import { deserializeTokenData } from './token-utils.js'

/**
 * Represents a Transact note with additional metadata for transactions.
 */
class TransactNote extends Note {
  /**
   * The note hash as a bigint
   */
  hash: bigint

  /**
   * Receiver address data
   */
  receiverAddressData: AddressData

  /**
   * Optional sender address data
   */
  senderAddressData: AddressData | undefined

  /**
   * Optional output type
   */
  outputType: number | undefined

  /**
   * Optional wallet source
   */
  walletSource: string | undefined

  /**
   * Optional sender random value
   */
  senderRandom: string | undefined

  /**
   * Optional memo text
   */
  memoText: string | undefined

  /**
   * Optional shield fee
   */
  shieldFee: string | undefined

  /**
   * Optional block number
   */
  blockNumber: number | undefined

  /**
   * Constructs a new TransactNote instance.
   * @param notePublicKey - The note public key
   * @param value - The note value
   * @param tokenData - The token data
   * @param random - Random value (16 bytes hex string)
   * @param hash - The note hash
   * @param receiverAddressData - Receiver address data
   * @param senderAddressData - Optional sender address data
   * @param outputType - Optional output type
   * @param walletSource - Optional wallet source
   * @param senderRandom - Optional sender random value
   * @param memoText - Optional memo text
   * @param shieldFee - Optional shield fee
   * @param blockNumber - Optional block number
   */
  constructor (
    notePublicKey: string,
    value: bigint,
    tokenData: TokenData,
    random: string,
    hash: bigint,
    receiverAddressData: AddressData,
    senderAddressData?: AddressData,
    outputType?: number,
    walletSource?: string,
    senderRandom?: string,
    memoText?: string,
    shieldFee?: string,
    blockNumber?: number
  ) {
    super(notePublicKey, value, tokenData, random)
    this.hash = hash
    this.receiverAddressData = receiverAddressData
    this.senderAddressData = senderAddressData
    this.outputType = outputType
    this.walletSource = walletSource
    this.senderRandom = senderRandom
    this.memoText = memoText
    this.shieldFee = shieldFee
    this.blockNumber = blockNumber
  }

  /**
   * Serializes the transact note to a Uint8Array using msgpack encoding.
   * @returns The serialized transact note
   */
  serialize (): Uint8Array {
    return encode({
      random: this.random,
      tokenHash: this.tokenHash,
      notePublicKey: this.notePublicKey,
      value: this.value.toString(),
      hash: this.hash.toString(),
      outputType: this.outputType,
      walletSource: this.walletSource,
      senderRandom: this.senderRandom,
      memoText: this.memoText,
      shieldFee: this.shieldFee,
      blockNumber: this.blockNumber,
      token: {
        tokenAddress: this.tokenData.tokenAddress,
        tokenType: this.tokenData.tokenType,
        tokenSubID: this.tokenData.tokenSubID,
      },
      receiverAddressData: this.receiverAddressData
        ? {
            masterPublicKey: this.receiverAddressData.masterPublicKey.toString(),
            viewingPublicKey: uint8ArrayToHex(this.receiverAddressData.viewingPublicKey),
          }
        : undefined,
      senderAddressData: this.senderAddressData
        ? {
            masterPublicKey: this.senderAddressData.masterPublicKey.toString(),
            viewingPublicKey: uint8ArrayToHex(this.senderAddressData.viewingPublicKey),
          }
        : undefined,
    })
  }

  /**
   * Deserializes a transact note from a Uint8Array.
   * @param bytes - The serialized transact note data
   * @returns A new TransactNote instance
   */
  static deserialize (bytes: Uint8Array): TransactNote {
    const data = decode(bytes) as any

    const receiverAddressData: AddressData = data.receiverAddressData
      ? {
          masterPublicKey: BigInt(data.receiverAddressData.masterPublicKey),
          viewingPublicKey: hexToUint8Array(data.receiverAddressData.viewingPublicKey),
        }
      : { masterPublicKey: 0n, viewingPublicKey: new Uint8Array(32) }

    return new TransactNote(
      data.notePublicKey,
      BigInt(data.value),
      deserializeTokenData(data.token),
      data.random,
      BigInt(data.hash),
      receiverAddressData,
      data.senderAddressData
        ? {
            masterPublicKey: BigInt(data.senderAddressData.masterPublicKey),
            viewingPublicKey: hexToUint8Array(data.senderAddressData.viewingPublicKey),
          }
        : undefined,
      data.outputType,
      data.walletSource,
      data.senderRandom,
      data.memoText,
      data.shieldFee,
      data.blockNumber
    )
  }

  /**
   * Creates a TransactNote from commitment data.
   * NOTE: This converts only the commitment data. Full decryption requires viewing keys.
   * NOTE: Requires cryptography libraries to be initialized first via initializeCryptographyLibs()
   * @param _commitment - The TransactCommitment or EncryptedCommitment (reserved for future use)
   * @param random - Random value (16 bytes hex string) - from decrypted ciphertext
   * @param npk - Note public key (hex string) - from decrypted ciphertext
   * @param value - Note value (bigint) - from decrypted ciphertext
   * @param tokenData - Token data - from decrypted ciphertext
   * @param receiverAddressData - Receiver address data
   * @param senderAddressData - Optional sender address data
   * @returns A new TransactNote instance
   */
  static fromCommitment (
    _commitment: TransactCommitment | EncryptedCommitment,
    random: string,
    npk: string,
    value: bigint,
    tokenData: TokenData,
    receiverAddressData: AddressData,
    senderAddressData?: AddressData
  ): TransactNote {
    const hash = getNoteHash(npk, tokenData, value)

    return new TransactNote(
      npk,
      value,
      tokenData,
      random,
      hash,
      receiverAddressData,
      senderAddressData
    )
  }

  /**
   * Serializes a transact note in legacy format (for backward compatibility).
   * Legacy format uses encrypted random field instead of plain random.
   * @param viewingPrivateKey - Viewing private key for encryption (32 bytes)
   * @param receiverViewingPublicKey - Receiver's viewing public key for encryption (32 bytes)
   * @returns The serialized legacy transact note
   */
  async serializeLegacy (viewingPrivateKey: Uint8Array, receiverViewingPublicKey: Uint8Array): Promise<Uint8Array> {
    // Get shared symmetric key for encryption
    const sharedKey = await getSharedSymmetricKey(viewingPrivateKey, receiverViewingPublicKey)
    if (!sharedKey) {
      throw new Error('Failed to generate shared symmetric key')
    }

    // Encrypt the random value using AES-GCM
    const randomBytes = hexToUint8Array(this.random)
    const ciphertext = AES.encryptGCM([randomBytes], sharedKey)

    // Convert ciphertext to legacy format [ivTag, data]
    const ivTag = uint8ArrayToHex(ciphertext.iv, false) + uint8ArrayToHex(ciphertext.tag, false)
    const encryptedData = ciphertext.data[0] ? uint8ArrayToHex(ciphertext.data[0], false) : ''
    const encryptedRandom: EncryptedData = [ivTag, encryptedData]

    return encode({
      npk: this.notePublicKey,
      value: this.value.toString(),
      tokenHash: this.tokenHash,
      encryptedRandom,
      memoField: [],
      recipientAddress: this.receiverAddressData
        ? uint8ArrayToHex(this.receiverAddressData.viewingPublicKey)
        : '0x' + '00'.repeat(32),
      memoText: this.memoText,
      blockNumber: this.blockNumber,
    })
  }

  /**
   * Deserializes a legacy transact note.
   * @param bytes - The serialized legacy note data
   * @param viewingPrivateKey - Viewing private key for decryption (32 bytes)
   * @param senderViewingPublicKey - Sender's viewing public key for decryption (32 bytes)
   * @returns A new TransactNote instance
   */
  static async deserializeLegacy (
    bytes: Uint8Array,
    viewingPrivateKey: Uint8Array,
    senderViewingPublicKey: Uint8Array
  ): Promise<TransactNote> {
    const data = decode(bytes) as any

    // Get shared symmetric key for decryption
    const sharedKey = await getSharedSymmetricKey(viewingPrivateKey, senderViewingPublicKey)

    if (!sharedKey) {
      throw new Error('Failed to generate shared symmetric key')
    }

    // Parse encrypted random from legacy format
    const encryptedData = data.encryptedRandom as EncryptedData
    const [ivTag, encryptedRandomData] = encryptedData

    // Extract IV and tag from ivTag
    const iv = hexToUint8Array('0x' + ivTag.slice(0, 32))
    const tag = hexToUint8Array('0x' + ivTag.slice(32))
    const encData = hexToUint8Array('0x' + encryptedRandomData)

    // Decrypt using AES-GCM
    const ciphertext: Ciphertext = { iv, tag, data: [encData] }
    const decrypted = AES.decryptGCM(ciphertext, sharedKey)
    const random = uint8ArrayToHex(decrypted[0] || new Uint8Array(16))

    // Legacy notes can only be ERC20
    const tokenData: TokenData = {
      tokenType: 0, // ERC20
      tokenAddress: data.tokenHash,
      tokenSubID: '0x00'
    }

    const receiverAddressData: AddressData = {
      masterPublicKey: 0n,
      viewingPublicKey: hexToUint8Array(data.recipientAddress)
    }

    const hash = getNoteHash(data.npk, tokenData, BigInt(data.value))

    return new TransactNote(
      data.npk,
      BigInt(data.value),
      tokenData,
      random,
      hash,
      receiverAddressData,
      undefined,
      undefined,
      undefined,
      undefined,
      data.memoText,
      undefined,
      data.blockNumber
    )
  }
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
  TransactNote,
  isLegacyTransactNote,
  ciphertextToEncryptedRandomData,
  encryptedDataToCiphertext
}
