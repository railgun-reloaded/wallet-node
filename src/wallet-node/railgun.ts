import { deriveNodes } from '../index.js'
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
   * Constructs an instance of the RailgunWallet class.
   * @param mnemonic - The mnemonic phrase used to derive wallet nodes.
   * @param index - The derivation index for the wallet nodes (default is 0).
   */
  constructor (mnemonic: string, index: number = 0) {
    this.nodes = deriveNodes(mnemonic, index)
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
  initializeKeyPairs (): void {
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
    }
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
}
