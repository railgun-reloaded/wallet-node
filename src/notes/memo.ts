import type { CiphertextCTR } from '@railgun-reloaded/cryptography'
import { AES } from '@railgun-reloaded/cryptography'

import { uint8ArrayToHex } from '../hash'

import type { NoteAnnotationData } from './definitions'
import { MEMO_SENDER_RANDOM_NULL, OutputType } from './definitions'
import { WalletInfo } from './wallet-info'

/**
 * Memo encoding, decoding, and V2 annotation data encryption/decryption.
 */
class Memo {
  /**
   * Encodes a memo text string into a Uint8Array using UTF-8 encoding.
   * @param memoText - The memo text to encode, or undefined
   * @returns Uint8Array of the UTF-8 encoded text (empty array if undefined)
   */
  static encodeMemoText (memoText: string | undefined): Uint8Array {
    if (memoText === undefined) {
      return new Uint8Array(0)
    }

    return new TextEncoder().encode(memoText)
  }

  /**
   * Decodes a UTF-8 encoded Uint8Array back to a memo text string.
   * @param encoded - The UTF-8 encoded bytes
   * @returns The decoded string, or undefined if the input is empty
   */
  static decodeMemoText (encoded: Uint8Array): string | undefined {
    if (encoded.length === 0) {
      return undefined
    }
    return new TextDecoder().decode(encoded)
  }

  /**
   * Creates encrypted V2 annotation data for a transact note.
   *
   * Layout (3 blocks of 16 bytes each, AES-CTR encrypted):
   * - Block 0: [outputType (1 byte)][senderRandom (15 bytes)]
   * - Block 1: [16 zero bytes (reserved)]
   * - Block 2: [walletSource encoded base-37, left-padded to 16 bytes]
   *
   * Output: [IV (16 bytes)][encrypted block 0 (16 bytes)][encrypted block 1 (16 bytes)][encrypted block 2 (16 bytes)]
   * @param outputType - The output type (Transfer, BroadcasterFee, Change)
   * @param senderRandom - 15-byte random value as hex string (30 hex chars)
   * @param walletSource - Wallet source identifier string
   * @param viewingPrivateKey - 32-byte viewing private key used as AES-CTR encryption key
   * @returns Uint8Array containing IV + encrypted blocks (64 bytes)
   */
  static encryptAnnotationData (
    outputType: OutputType,
    senderRandom: string,
    walletSource: string,
    viewingPrivateKey: Uint8Array
  ): Uint8Array {
    // Block 0: outputType (1 byte) + senderRandom (15 bytes)
    const block0 = new Uint8Array(16)
    block0[0] = outputType

    const senderRandomClean = senderRandom.startsWith('0x') ? senderRandom.slice(2) : senderRandom
    if (senderRandomClean.length !== 30) {
      throw new Error(`senderRandom must be 15 bytes (30 hex chars), got ${senderRandomClean.length}`)
    }

    for (let i = 0; i < 15; i++) {
      block0[i + 1] = parseInt(senderRandomClean.slice(i * 2, i * 2 + 2), 16)
    }

    // Block 1: 16 zero bytes (reserved)
    const block1 = new Uint8Array(16)

    // Block 2: wallet source encoded, left-padded to 16 bytes
    const block2 = new Uint8Array(16)
    if (walletSource) {
      const encoded = WalletInfo.encodeWalletSource(walletSource)
      const offset = 16 - encoded.length
      block2.set(encoded, offset > 0 ? offset : 0)
    }

    const ciphertext = AES.encryptCTR([block0, block1, block2], viewingPrivateKey)

    // Concatenate IV + encrypted blocks
    const result = new Uint8Array(16 + ciphertext.data.length * 16)
    result.set(ciphertext.iv, 0)
    for (let i = 0; i < ciphertext.data.length; i++) {
      result.set(ciphertext.data[i]!, 16 + i * 16)
    }

    return result
  }

  /**
   * Decrypts V2 annotation data from a transact note.
   * @param annotationData - The encrypted annotation data bytes
   * @param viewingPrivateKey - 32-byte viewing private key used as AES-CTR decryption key
   * @returns NoteAnnotationData or undefined if decryption fails
   */
  static decryptAnnotationData (
    annotationData: Uint8Array,
    viewingPrivateKey: Uint8Array
  ): NoteAnnotationData | undefined {
    if (!annotationData || annotationData.length === 0) {
      return undefined
    }

    try {
      const hasExtendedData = annotationData.length > 32

      // Parse IV (first 16 bytes)
      const iv = annotationData.slice(0, 16)

      // Parse data blocks (16 bytes each)
      const dataBlocks: Uint8Array[] = hasExtendedData
        ? [
            annotationData.slice(16, 32),
            annotationData.slice(32, 48),
            annotationData.slice(48, 64)
          ]
        : [annotationData.slice(16, 32)]

      const ciphertext: CiphertextCTR = { iv, data: dataBlocks }
      const decrypted = AES.decryptCTR(ciphertext, viewingPrivateKey)

      const block0 = decrypted[0]
      if (!block0 || block0.length < 16) {
        return undefined
      }

      const outputType = block0[0]!
      if (!Object.values(OutputType).includes(outputType)) {
        return undefined
      }

      const senderRandom = uint8ArrayToHex(block0.slice(1, 16), false)
      if (senderRandom.length !== 30) {
        return undefined
      }

      let walletSource: string | undefined
      if (hasExtendedData && decrypted[2]) {
        try {
          walletSource = WalletInfo.decodeWalletSource(decrypted[2])
          if (!walletSource) {
            walletSource = undefined
          }
        } catch {
          walletSource = undefined
        }
      }

      return { outputType, senderRandom, walletSource }
    } catch {
      return undefined
    }
  }

  /**
   * Decrypts the sender random value from annotation data.
   * Returns the sender random hex string, or MEMO_SENDER_RANDOM_NULL if decryption fails.
   * @param annotationData - The encrypted annotation data bytes
   * @param viewingPrivateKey - 32-byte viewing private key
   * @returns Hex string of the sender random (30 hex chars), or the null constant
   */
  static decryptSenderRandom (
    annotationData: Uint8Array,
    viewingPrivateKey: Uint8Array
  ): string {
    const noteAnnotationData = Memo.decryptAnnotationData(annotationData, viewingPrivateKey)
    return noteAnnotationData ? noteAnnotationData.senderRandom : MEMO_SENDER_RANDOM_NULL
  }
}

export { Memo }
