import { decode, encode } from '@msgpack/msgpack'
import { AES } from '@railgun-reloaded/cryptography'

import { hexToUint8Array, uint8ArrayToBigInt, uint8ArrayToHex } from '../hash'

import { decodeAddress, encodeAddress } from './address-utils'
import type { AddressData, Chain, Ciphertext, EncryptedData, TXIDVersion, TokenData, TokenDataGetter } from './definitions'
import { Note } from './note'
import { getNoteHash } from './note-utils'
import { computeTokenHash, getTokenDataERC20 } from './token-utils'

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
   * Output shape matches {@link TransactNoteSerialized}.
   * @returns The serialized transact note
   */
  serialize (): Uint8Array {
    return encode({
      npk: this.notePublicKey,
      value: this.value.toString(),
      tokenHash: this.tokenHash,
      random: this.random,
      recipientAddress: encodeAddress(this.receiverAddressData),
      senderAddress: this.senderAddressData
        ? encodeAddress(this.senderAddressData)
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

    const receiverAddressData = decodeAddress(data.recipientAddress)

    const senderAddressData = data.senderAddress
      ? decodeAddress(data.senderAddress)
      : undefined

    const tokenData = await tokenDataGetter.getTokenDataFromHash(txidVersion, chain, data.tokenHash)

    const npkBytes = hexToUint8Array(data.npk)
    const tokenHashBytes = hexToUint8Array(data.tokenHash)
    const value = BigInt(data.value)
    const hash = uint8ArrayToBigInt(getNoteHash(npkBytes, tokenHashBytes, value))

    return new TransactNote(
      data.npk,
      value,
      tokenData,
      data.random,
      hash,
      receiverAddressData,
      senderAddressData,
      data.outputType,
      data.walletSource,
      data.senderRandom,
      data.memoText,
      data.shieldFee,
      data.blockNumber
    )
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
    const hash = uint8ArrayToBigInt(getNoteHash(npkBytes, tokenHashBytes, value))

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
      recipientAddress: encodeAddress(this.receiverAddressData),
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
   * @returns A new TransactNote instance
   */
  static deserializeLegacy (
    bytes: Uint8Array,
    viewingPrivateKey: Uint8Array
  ): TransactNote {
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

    const receiverAddressData = decodeAddress(data.recipientAddress)

    const npkBytes = hexToUint8Array(data.npk)
    const tokenHashBytes = hexToUint8Array(computeTokenHash(tokenData))
    const hash = uint8ArrayToBigInt(getNoteHash(npkBytes, tokenHashBytes, BigInt(data.value)))

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

export { TransactNote }
