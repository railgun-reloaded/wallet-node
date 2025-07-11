import { AES, keccak256, rawSignature } from '@railgun-reloaded/cryptography'

import { bigIntToArray } from '../hash.js'
import { deriveNodes } from '../index.js'
import { getSharedSymmetricKey } from '../keys.js'
import type {
  SpendingKeyPair,
  SpendingPublicKey,
  ViewingKeyPair,
} from '../types.js'

import type { WalletNodes } from './wallet-node.js'
import { WalletNode } from './wallet-node.js'

type RailgunKeystore = {
  spendingKeyPair: SpendingKeyPair;
  viewingKeyPair: ViewingKeyPair;
  nullifyingKey: Uint8Array;
  masterPublicKey: Uint8Array<ArrayBufferLike>;
  zer0xPrivateKey: Uint8Array;
  shieldPrivateKey?: Uint8Array;
}

/**
 * The `RailgunWallet` class provides functionality for managing cryptographic keys and interacting
 * with wallet nodes in a blockchain network. It encapsulates operations related to key management,
 * including spending, viewing, and nullifying keys, as well as deriving master public keys.
 *
 * ### Features:
 * - **Key Management**: Handles cryptographic keys for signing transactions, viewing encrypted data,
 *   and nullifying commitments.
 * - **Keystore Integration**: Stores and retrieves keys securely using an optional keystore.
 * - **Node Interaction**: Derives wallet nodes from a mnemonic phrase and interacts with them for
 *   cryptographic operations.
 *
 * ### Usage:
 * - Instantiate the wallet using a mnemonic phrase and an optional node index.
 * - Access cryptographic keys such as spending, viewing, and nullifying keys through provided methods.
 * - Retrieve the master public key for wallet operations.
 *
 * ### Example:
 * ```typescript
 * const wallet = new RailgunWallet('your mnemonic phrase');
 * const spendingPrivateKey = wallet.getSpendingPrivateKey();
 * const masterPublicKey = wallet.getMasterPublicKey();
 * ```
 * The `RailgunWallet` class assumes that the wallet nodes and keystore are properly initialized.
 * Attempting to access keys without initialization will result in errors.
 * @throws {Error} If the keystore is not initialized when accessing keys.
 */
export class RailgunWallet {
  /**
   * Represents the wallet nodes used for managing and interacting with the blockchain network.
   * This property provides access to the nodes responsible for handling wallet-related operations.
   */
  private nodes: WalletNodes
  /**
   * The keystore instance used for managing cryptographic keys and secure storage.
   * This property is optional and may be undefined if the keystore is not initialized.
   */
  private keystore: RailgunKeystore | undefined

  /**
   * Constructs an instance of the Railgun class.
   * @param mnemonic - The mnemonic phrase used to derive nodes.
   * @param index - The index of the node to derive (default is 0).
   */
  constructor (mnemonic: string, index: number = 0) {
    this.nodes = deriveNodes(mnemonic, index)
    // @ts-ignore
    this.initializeKeyPairs()
  }

  /**
   * Retrieves the constant signature message used for shield private key operations.
   * This message is a predefined string that should not be modified.
   * @returns The constant signature message 'RAILGUN_SHIELD'.
   */
  static getShieldPrivateKeySignatureMessage () {
    // DO NOT MODIFY THIS CONSTANT.
    return 'RAILGUN_SHIELD'
  }

  /**
   * Sets the shield private key in the keystore by generating it from a raw signature.
   * This method requires the keystore to be initialized. It computes the shield private key
   * using the `rawSignature` function and the `keccak256` hash of the concatenated signature components.
   * @throws {Error} If the keystore is not initialized.
   * @returns The computed shield private key.
   */
  async setShieldPrivateKey () {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    const shieldSignature = await rawSignature(RailgunWallet.getShieldPrivateKeySignatureMessage(), this.keystore.zer0xPrivateKey)
    const rBytes = bigIntToArray(shieldSignature.r)
    const sBytes = bigIntToArray(shieldSignature.s)
    const vByte = Uint8Array.of(27 + shieldSignature.recovery)
    const privKeyBytes = new Uint8Array(65)
    privKeyBytes.set(rBytes, 0)
    privKeyBytes.set(sBytes, 32)
    privKeyBytes.set(vByte, 64)
    const shieldPrivateKey = keccak256(privKeyBytes)
    this.keystore.shieldPrivateKey = shieldPrivateKey
    return shieldPrivateKey
  }

  /**
   * Initializes the key pairs and related cryptographic keys for the wallet node.
   * This method retrieves the spending key pair, nullifying key, and viewing key pair
   * from the respective nodes, and computes the master public key using the spending
   * public key and nullifying key. The keys are then stored in the `keystore` property.
   *
   * - The `spendingKeyPair` is used for signing transactions.
   * - The `nullifyingKey` is used for nullifying commitments.
   * - The `viewingKeyPair` is used for viewing encrypted data.
   * - The `masterPublicKey` is derived from the spending public key and nullifying key.
   */
  async initializeKeyPairs (): Promise<void> {
    const spendingKeyPair = this.nodes.spending.getSpendingKeyPair()
    const nullifyingKey = this.nodes.viewing.getNullifyingKey()
    const viewingKeyPair = this.nodes.viewing.getViewingKeyPair()
    const masterPublicKey = WalletNode.getMasterPublicKey(
      spendingKeyPair.pubkey,
      nullifyingKey
    )

    this.keystore = {
      spendingKeyPair,
      viewingKeyPair,
      nullifyingKey,
      masterPublicKey,
      zer0xPrivateKey: new Uint8Array(32), // TODO: calculate 0x private keys.
    }
    console.log(this.keystore)
  }

  /**
   * Retrieves the spending private key from the keystore.
   * @returns The spending private key as a Uint8Array.
   * @throws {Error} If the keystore is not initialized.
   */
  getSpendingPrivateKey (): Uint8Array<ArrayBufferLike> {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.nodes.spending.getSpendingKeyPair().privateKey
  }

  /**
   * Retrieves the spending public key from the keystore.
   * @returns The spending public key associated with the keystore.
   * @throws {Error} If the keystore is not initialized.
   */
  getSpendingPublicKey (): SpendingPublicKey {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.spendingKeyPair.pubkey
  }

  /**
   * Retrieves the master public key from the keystore.
   * @returns The master public key as a Uint8Array.
   * @throws {Error} If the keystore is not initialized.
   */
  getMasterPublicKey (): Uint8Array<ArrayBufferLike> {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.masterPublicKey
  }

  /**
   * Retrieves the nullifying key from the keystore.
   * @returns The nullifying key.
   * @throws {Error} If the keystore is not initialized.
   */
  getNullifyingKey (): Uint8Array {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.nullifyingKey
  }

  /**
   * Retrieves the viewing public key from the keystore.
   * @returns The viewing public key as a Uint8Array.
   * @throws {Error} If the keystore is not initialized.
   */
  getViewingPublicKey (): Uint8Array<ArrayBufferLike> {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.viewingKeyPair.pubkey
  }

  /**
   * Retrieves the viewing private key from the keystore.
   * @returns The viewing private key as a Uint8Array.
   * @throws {Error} If the keystore is not initialized.
   */
  getViewingPrivateKey (): Uint8Array<ArrayBufferLike> {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.viewingKeyPair.privateKey
  }

  /**
   * Decrypts a randomly encrypted bundle using AES-GCM.
   * @param encryptedBundle - An array containing three Uint8Array elements:
   *   - The first element represents the IV and authentication tag.
   *   - The second element contains the encrypted data.
   *   - The third element is unused in this function.
   * @param shieldKey - A Uint8Array representing the shared key used for decryption.
   * @returns The decrypted data as a Uint8Array.
   * @throws Will throw an error if decryption fails or the input data is invalid.
   */
  decryptRandom (
    encryptedBundle: [Uint8Array, Uint8Array, Uint8Array],
    shieldKey: Uint8Array
  ): Uint8Array {
    // rawsign

    const sharedKey = getSharedSymmetricKey(this.getViewingPublicKey(), shieldKey)
    if (!sharedKey) {
      throw new Error('No shared key.')
    }
    const hexlified0 = encryptedBundle[0]
    const hexlified1 = encryptedBundle[1]
    const decrypted = AES.decryptGCM(
      {
        iv: hexlified0.slice(0, 16),
        tag: hexlified0.slice(16, 32),
        data: [hexlified1.slice(0, 16)],
      },
      sharedKey
    )[0]!
    return decrypted
  }
}
