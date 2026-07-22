import { combine, hexToBytes } from '@railgun-reloaded/bytes'
import { AES } from '@railgun-reloaded/cryptography'

import { getPublicViewingKey, getSharedSymmetricKey } from '../keys.js'

import type { ShieldNote } from './shield-note.js'

/**
 * Shield request submitted to the RailgunSmartWallet contract, with a plaintext
 * `preimage` and an encrypted `ciphertext`.
 */
type ShieldRequest = {
  preimage: {
    npk: Uint8Array;
    token: {
      tokenType: number;
      tokenAddress: Uint8Array;
      tokenSubID: Uint8Array;
    };
    value: bigint;
  };
  ciphertext: {
    encryptedBundle: [Uint8Array, Uint8Array, Uint8Array];
    shieldKey: Uint8Array;
  };
}

/**
 * Builds the shield request for a note.
 * Encrypts the note random with AES-256-GCM under the ECDH shared key of the
 * shield private key and the receiver viewing public key, and encrypts the
 * receiver viewing public key with AES-256-CTR under the shield private key.
 * The results fill the three 32-byte `encryptedBundle` slots:
 *   [0] = GCM iv (16) + GCM tag (16)
 *   [1] = GCM encrypted random (16) + CTR iv (16)
 *   [2] = CTR encrypted receiver viewing public key (32)
 * @param note - The note to shield.
 * @param shieldPrivateKey - The shielder's ephemeral private key (32 bytes).
 * @param receiverViewingPublicKey - The receiver's viewing public key (32 bytes).
 * @returns The shield request struct expected by the contract.
 * @throws {Error} If the shared symmetric key cannot be derived.
 */
const buildShieldRequest = async (
  note: ShieldNote,
  shieldPrivateKey: Uint8Array,
  receiverViewingPublicKey: Uint8Array
): Promise<ShieldRequest> => {
  const sharedKey = await getSharedSymmetricKey(shieldPrivateKey, receiverViewingPublicKey)
  if (!sharedKey) {
    throw new Error('Could not generate shared symmetric key for shielding.')
  }

  const encryptedRandom = AES.encryptGCM([hexToBytes(note.random)], sharedKey)
  const encryptedReceiver = AES.encryptCTR([receiverViewingPublicKey], shieldPrivateKey)
  const shieldKey = getPublicViewingKey(shieldPrivateKey)

  return {
    preimage: {
      npk: hexToBytes(note.notePublicKey),
      token: {
        tokenType: note.tokenData.tokenType,
        tokenAddress: note.tokenData.tokenAddress,
        tokenSubID: note.tokenData.tokenSubID,
      },
      value: note.value,
    },
    ciphertext: {
      encryptedBundle: [
        combine([encryptedRandom.iv, encryptedRandom.tag]),
        combine([encryptedRandom.data[0]!, encryptedReceiver.iv]),
        combine(encryptedReceiver.data),
      ],
      shieldKey,
    },
  }
}

export type { ShieldRequest }
export { buildShieldRequest }
