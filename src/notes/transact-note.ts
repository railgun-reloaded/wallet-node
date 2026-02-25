import { decode, encode } from '@msgpack/msgpack'
import { parse as parse0zkAddress, stringify as stringify0zkAddress } from '@railgun-reloaded/0zk-addresses'
import { AES } from '@railgun-reloaded/cryptography'

import { hexToUint8Array, uint8ArrayToBigInt, uint8ArrayToHex } from '../encoding'

import type { AddressData, Chain, Ciphertext, EncryptedData, LegacyCiphertext, TXIDVersion, TokenData, TokenDataGetter } from './definitions'
import type { NoteParams } from './note'
import { Note } from './note'
import { computeTokenHash, getTokenDataERC20 } from './token-utils'

/**
 * Parameters for constructing a TransactNote.
 */
type TransactNoteParams = NoteParams & {
  hash: bigint
  receiverAddressData: AddressData
  senderAddressData?: AddressData | undefined
  outputType?: number | undefined
  walletSource?: string | undefined
  senderRandom?: string | undefined
  memoText?: string | undefined
  shieldFee?: string | undefined
  blockNumber?: number | undefined
}

/**
 * Represents a Transact note for private-to-private transfers.
 * These notes move value between wallets without ever exposing assets on-chain, carrying
 * receiver/sender address data, a Poseidon {@link hash}, and optional metadata such as
 * {@link memoText}, {@link outputType}, and {@link shieldFee}.
 * Extends {@link Note} with transaction-specific fields.
 *
 * Supports both a modern msgpack serialization format and a legacy format that encrypts the
 * random value with AES-GCM using the viewing private key directly (see {@link TransactNote.serializeLegacy}).
 *
 * Can be created directly, deserialized from either format, or reconstructed from on-chain
 * commitment data ({@link TransactCommitment} or {@link EncryptedCommitment}).
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
   * @param params - The transact note parameters
   */
  constructor (params: TransactNoteParams) {
    super(params)
    this.hash = params.hash
    this.receiverAddressData = params.receiverAddressData
    this.senderAddressData = params.senderAddressData
    this.outputType = params.outputType
    this.walletSource = params.walletSource
    this.senderRandom = params.senderRandom
    this.memoText = params.memoText
    this.shieldFee = params.shieldFee
    this.blockNumber = params.blockNumber
  }

  /**
   * Serializes the transact note to a Uint8Array using msgpack encoding.
   * Output shape matches {@link TransactNoteSerialized}.
   * @returns The serialized transact note
   */
  serialize (): Uint8Array {
    return encode({
      npk: this.notePublicKey,
      value: this.value.toString(),
      tokenHash: this.tokenHash,
      random: this.random,
      recipientAddress: stringify0zkAddress(this.receiverAddressData),
      senderAddress: this.senderAddressData
        ? stringify0zkAddress(this.senderAddressData!)
        : undefined,
      outputType: this.outputType,
      walletSource: this.walletSource,
      senderRandom: this.senderRandom,
      memoText: this.memoText,
      shieldFee: this.shieldFee,
      blockNumber: this.blockNumber,
    })
  }

  /**
   * Deserializes a transact note from a Uint8Array.
   * Resolves tokenHash to full TokenData via tokenDataGetter.
   * @param bytes - The serialized transact note data
   * @param txidVersion - The TXID version
   * @param chain - The chain this note belongs to
   * @param tokenDataGetter - Resolves token hashes to full token data
   * @returns A new TransactNote instance
   */
  static async deserialize (
    bytes: Uint8Array,
    txidVersion: TXIDVersion,
    chain: Chain,
    tokenDataGetter: TokenDataGetter
  ): Promise<TransactNote> {
    const data = decode(bytes) as any

    const receiverAddressData = parse0zkAddress(data.recipientAddress)

    const senderAddressData = data.senderAddress
      ? parse0zkAddress(data.senderAddress)
      : undefined

    const tokenData = await tokenDataGetter.getTokenDataFromHash(txidVersion, chain, data.tokenHash)

    const npkBytes = hexToUint8Array(data.npk)
    const tokenHashBytes = hexToUint8Array(data.tokenHash)
    const value = BigInt(data.value)
    const hash = uint8ArrayToBigInt(Note.getHash(npkBytes, tokenHashBytes, value))

    return new TransactNote({
      notePublicKey: data.npk,
      value,
      tokenData,
      random: data.random,
      hash,
      receiverAddressData,
      senderAddressData,
      outputType: data.outputType,
      walletSource: data.walletSource,
      senderRandom: data.senderRandom,
      memoText: data.memoText,
      shieldFee: data.shieldFee,
      blockNumber: data.blockNumber,
    })
  }

  /**
   * Creates a TransactNote from pre-decrypted commitment fields.
   * Use {@link decryptCommitment} to obtain the fields from an encrypted commitment.
   * NOTE: Requires cryptography libraries to be initialized first via initializeCryptographyLibs()
   * @param random - Random value (16 bytes hex string)
   * @param npk - Note public key (hex string)
   * @param value - Note value (bigint)
   * @param tokenData - Token data
   * @param receiverAddressData - Receiver address data
   * @param senderAddressData - Optional sender address data
   * @returns A new TransactNote instance
   */
  static fromCommitment (
    random: string,
    npk: string,
    value: bigint,
    tokenData: TokenData,
    receiverAddressData: AddressData,
    senderAddressData?: AddressData
  ): TransactNote {
    const npkBytes = hexToUint8Array(npk)
    const tokenHashBytes = hexToUint8Array(computeTokenHash(tokenData))
    const hash = uint8ArrayToBigInt(Note.getHash(npkBytes, tokenHashBytes, value))

    return new TransactNote({
      notePublicKey: npk,
      value,
      tokenData,
      random,
      hash,
      receiverAddressData,
      senderAddressData,
    })
  }

  /**
   * Serializes a transact note in legacy format (for backward compatibility).
   * Legacy format uses encrypted random field instead of plain random.
   * The random is encrypted directly with the viewing private key (no ECDH).
   * Output shape matches {@link LegacyTransactNoteSerialized}.
   * @param viewingPrivateKey - Viewing private key for encryption (32 bytes)
   * @returns The serialized legacy transact note
   */
  serializeLegacy (viewingPrivateKey: Uint8Array): Uint8Array {
    const randomBytes = hexToUint8Array(this.random)
    const ciphertext = AES.encryptGCM([randomBytes], viewingPrivateKey)

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
      recipientAddress: stringify0zkAddress(this.receiverAddressData),
      memoText: this.memoText,
      blockNumber: this.blockNumber,
    })
  }

  /**
   * Deserializes a legacy transact note.
   * The random is decrypted directly with the viewing private key (no ECDH).
   * Legacy notes are always ERC20.
   * @param bytes - The serialized legacy note data
   * @param viewingPrivateKey - Viewing private key for decryption (32 bytes)
   * @returns A new TransactNote instance, or null if decryption fails (wrong viewing key)
   */
  static deserializeLegacy (
    bytes: Uint8Array,
    viewingPrivateKey: Uint8Array
  ): TransactNote | null {
    try {
      const data = decode(bytes) as any

      const encryptedData = data.encryptedRandom as EncryptedData
      const [ivTag, encryptedRandomData] = encryptedData

      const iv = hexToUint8Array('0x' + ivTag.slice(0, 32))
      const tag = hexToUint8Array('0x' + ivTag.slice(32))
      const encData = hexToUint8Array('0x' + encryptedRandomData)

      const ciphertext: Ciphertext = { iv, tag, data: [encData] }
      const decrypted = AES.decryptGCM(ciphertext, viewingPrivateKey)
      const random = uint8ArrayToHex(decrypted[0] || new Uint8Array(16))

      // Legacy notes are always ERC20
      const tokenData = getTokenDataERC20(data.tokenHash)

      const receiverAddressData = parse0zkAddress(data.recipientAddress)

      const npkBytes = hexToUint8Array(data.npk)
      const tokenHashBytes = hexToUint8Array(computeTokenHash(tokenData))
      const hash = uint8ArrayToBigInt(Note.getHash(npkBytes, tokenHashBytes, BigInt(data.value)))

      return new TransactNote({
        notePublicKey: data.npk,
        value: BigInt(data.value),
        tokenData,
        random,
        hash,
        receiverAddressData,
        memoText: data.memoText,
        blockNumber: data.blockNumber,
      })
    } catch {
      return null
    }
  }

  /**
   * Checks if a serialized note is in legacy format.
   * @param noteData - The serialized note data
   * @returns True if legacy format, false otherwise
   */
  static isLegacy (noteData: any): boolean {
    return 'encryptedRandom' in noteData
  }

  /**
   * Converts ciphertext to encrypted random data format [ivTag, data].
   * @param ciphertext - The ciphertext object
   * @returns Tuple of [ivTag, data]
   */
  static ciphertextToEncryptedRandomData (ciphertext: LegacyCiphertext): EncryptedData {
    const ivTag = ciphertext.iv + ciphertext.tag
    const data = ciphertext.data[0] || ''
    return [ivTag, data]
  }

  /**
   * Converts encrypted random data format to ciphertext object.
   * @param encryptedRandom - Tuple of [ivTag, data]
   * @returns Ciphertext object
   */
  static encryptedDataToCiphertext (encryptedRandom: EncryptedData): LegacyCiphertext {
    const [ivTag, data] = encryptedRandom
    return {
      iv: ivTag.slice(0, 32),
      tag: ivTag.slice(32),
      data: [data]
    }
  }
}

export type { TransactNoteParams }
export { TransactNote }
