import { AES } from '@railgun-reloaded/cryptography'

import { uint8ArrayToHex } from '../hash.js'
import { getSharedSymmetricKey } from '../keys.js'

import type { Ciphertext, TokenData } from './definitions.js'
import { serializeTokenData } from './token-utils.js'

interface DecryptedCommitmentData {
  random: string
  npk: string
  value: bigint
  tokenData: TokenData
}

/**
 * Attempts to decrypt a commitment ciphertext using a viewing key
 * @param ciphertext - The encrypted ciphertext from the commitment
 * @param blindedViewingKey - The blinded viewing key (sender or receiver)
 * @param viewingPrivateKey - The wallet's viewing private key
 * @returns The decrypted data or null if decryption fails
 */
async function decryptCommitment (
  ciphertext: Ciphertext,
  blindedViewingKey: Uint8Array,
  viewingPrivateKey: Uint8Array
): Promise<DecryptedCommitmentData | null> {
  try {
    // Compute shared symmetric key using ECDH
    const sharedKey = await getSharedSymmetricKey(viewingPrivateKey, blindedViewingKey)
    if (!sharedKey) {
      return null
    }

    const decryptedCiphertext = AES.decryptGCM(ciphertext, sharedKey) // The decrypted data contains: [random (16 bytes), npk (32 bytes), value (32 bytes), tokenAddress (20 bytes), tokenType (1 byte), tokenSubID (32 bytes)]

    const combinedData = decryptedCiphertext[0]
    if (!combinedData || combinedData.length < 16 + 32 + 32 + 20 + 1 + 32) {
      return null
    }

    let offset = 0

    const randomBytes = combinedData.slice(offset, offset + 16) // (16 bytes)
    const random = uint8ArrayToHex(randomBytes)
    offset += 16

    const npkBytes = combinedData.slice(offset, offset + 32) // (32 bytes)
    const npk = uint8ArrayToHex(npkBytes)
    offset += 32

    const valueBytes = combinedData.slice(offset, offset + 32) // (32 bytes as big-endian bigint)
    let value = 0n
    for (let i = 0; i < valueBytes.length; i++) {
      value = (value << 8n) | BigInt(valueBytes[i] ?? 0)
    }
    offset += 32

    const tokenAddressBytes = combinedData.slice(offset, offset + 20) // (20 bytes)
    const tokenAddress = uint8ArrayToHex(tokenAddressBytes)
    offset += 20

    const tokenType = combinedData[offset] ?? 0 // (1 byte)
    offset += 1

    const tokenSubIDBytes = combinedData.slice(offset, offset + 32) // (32 bytes)
    const tokenSubID = uint8ArrayToHex(tokenSubIDBytes)

    const tokenData = serializeTokenData(tokenAddress, tokenType, tokenSubID)

    return { random, npk, value, tokenData }
  } catch (error) {
    // Decryption failed - commitment not for this wallet
    return null
  }
}

/**
 * Attempts to decrypt a commitment as either receiver or sender
 * @param ciphertext - The encrypted ciphertext from the commitment
 * @param blindedReceiverViewingKey - The blinded receiver viewing key
 * @param blindedSenderViewingKey - The blinded sender viewing key
 * @param viewingPrivateKey - The wallet's viewing private key
 * @returns Object with decrypted data and role (receiver/sender), or null if decryption fails
 */
async function decryptCommitmentAsReceiverOrSender (
  ciphertext: Ciphertext,
  blindedReceiverViewingKey: Uint8Array,
  blindedSenderViewingKey: Uint8Array,
  viewingPrivateKey: Uint8Array
): Promise<{ data: DecryptedCommitmentData, isReceiver: boolean } | null> {
  const receiverData = await decryptCommitment(
    ciphertext,
    blindedReceiverViewingKey,
    viewingPrivateKey
  )

  if (receiverData) {
    return { data: receiverData, isReceiver: true }
  }

  const senderData = await decryptCommitment(
    ciphertext,
    blindedSenderViewingKey,
    viewingPrivateKey
  )

  if (senderData) {
    return { data: senderData, isReceiver: false }
  }

  return null
}

export type { DecryptedCommitmentData }
export { decryptCommitment, decryptCommitmentAsReceiverOrSender }
