import { bytesToBigInt, bytesToHex } from '@railgun-reloaded/bytes'
import { AES } from '@railgun-reloaded/cryptography'

import { getSharedSymmetricKey } from '../keys'

import type { Chain, Ciphertext, TokenData, TokenDataGetter } from './definitions'
import { TXIDVersion } from './definitions'

interface DecryptedCommitmentData {
  random: string
  encodedMPK: string
  value: bigint
  tokenData: TokenData
}

/**
 * Attempts to decrypt a commitment ciphertext using a viewing key.
 * The decrypted ciphertext is expected to contain at least 3 elements:
 *   [0]: Encoded Master Public Key
 *   [1]: Token hash
 *   [2]: Random (16 bytes) + Value (16 bytes)
 * @param txidVersion - The TXID version (V2 or V3)
 * @param chain - The chain this commitment belongs to
 * @param ciphertext - The encrypted ciphertext from the commitment
 * @param blindedViewingKey - The blinded viewing key (sender or receiver)
 * @param viewingPrivateKey - The wallet's viewing private key
 * @param tokenDataGetter - Resolves token hashes to full token data
 * @returns The decrypted data or null if decryption fails
 */
async function decryptCommitment (
  txidVersion: TXIDVersion,
  chain: Chain,
  ciphertext: Ciphertext,
  blindedViewingKey: Uint8Array,
  viewingPrivateKey: Uint8Array,
  tokenDataGetter: TokenDataGetter
): Promise<DecryptedCommitmentData | null> {
  if (txidVersion !== TXIDVersion.V2_PoseidonMerkle) {
    throw new Error(`Unsupported txidVersion: ${txidVersion}`)
  }

  try {
    // Compute shared symmetric key using ECDH
    const sharedKey = await getSharedSymmetricKey(viewingPrivateKey, blindedViewingKey)
    if (!sharedKey) {
      return null
    }

    const decryptedCiphertext = AES.decryptGCM(ciphertext, sharedKey)

    if (decryptedCiphertext.length < 3) {
      return null
    }

    const mpkBytes = decryptedCiphertext[0]
    const tokenHashBytes = decryptedCiphertext[1]
    const randomValueBytes = decryptedCiphertext[2]

    if (!mpkBytes || !tokenHashBytes || !randomValueBytes || randomValueBytes.length < 32) {
      return null
    }

    const encodedMPK = bytesToHex(mpkBytes, { prefix: true })
    const tokenHash = bytesToHex(tokenHashBytes, { prefix: true })
    const tokenData = await tokenDataGetter.getTokenDataFromHash(txidVersion, chain, tokenHash)

    // decryptedCiphertext[2] contains: random (16 bytes) + value (16 bytes)
    const random = bytesToHex(randomValueBytes.slice(0, 16), { prefix: true })

    const value = bytesToBigInt(randomValueBytes.slice(16, 32))

    return { random, encodedMPK, value, tokenData }
  } catch (error) {
    // Decryption failed - commitment not for this wallet
    return null
  }
}

/**
 * Attempts to decrypt a commitment as both receiver and sender.
 * The sender and receiver could be the same address, so we try decrypting
 * with both keys even if the first one gives valid data.
 * @param txidVersion - The TXID version (V2 or V3)
 * @param chain - The chain this commitment belongs to
 * @param ciphertext - The encrypted ciphertext from the commitment
 * @param blindedReceiverViewingKey - The blinded receiver viewing key
 * @param blindedSenderViewingKey - The blinded sender viewing key
 * @param viewingPrivateKey - The wallet's viewing private key
 * @param tokenDataGetter - Resolves token hashes to full token data
 * @returns Object with receiver and sender decrypted data (either or both may be non-null)
 */
async function decryptCommitmentAsReceiverOrSender (
  txidVersion: TXIDVersion,
  chain: Chain,
  ciphertext: Ciphertext,
  blindedReceiverViewingKey: Uint8Array,
  blindedSenderViewingKey: Uint8Array,
  viewingPrivateKey: Uint8Array,
  tokenDataGetter: TokenDataGetter
): Promise<{ receiverData: DecryptedCommitmentData | null, senderData: DecryptedCommitmentData | null }> {
  // ECDH: to derive the shared key, combine your private key with the OTHER
  // party's blinded public key. The receiver uses the sender's blinded key and vice versa.
  const [receiverData, senderData] = await Promise.all([
    blindedSenderViewingKey.length > 0
      ? decryptCommitment(
        txidVersion,
        chain,
        ciphertext,
        blindedSenderViewingKey,
        viewingPrivateKey,
        tokenDataGetter
      )
      : null,
    blindedReceiverViewingKey.length > 0
      ? decryptCommitment(
        txidVersion,
        chain,
        ciphertext,
        blindedReceiverViewingKey,
        viewingPrivateKey,
        tokenDataGetter
      )
      : null,
  ])

  return { receiverData, senderData }
}

export type { DecryptedCommitmentData }
export { decryptCommitment, decryptCommitmentAsReceiverOrSender }
