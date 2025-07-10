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
 *
 */
export class RailgunWallet {
  /**
   *
   */
  private nodes: WalletNodes
  /**
   *
   */
  private keystore: RailgunKeystore | undefined

  /**
   *
   * @param mnemonic
   * @param index
   */
  constructor(mnemonic: string, index: number = 0) {
    this.nodes = deriveNodes(mnemonic, index)
    this.initializeKeyPairs()
  }

  /**
   *
   */
  static getShieldPrivateKeySignatureMessage() {
    // DO NOT MODIFY THIS CONSTANT.
    return 'RAILGUN_SHIELD'
  }

  /**
   *
   */
  initializeKeyPairs(): void {
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
   *
   */
  getSpendingPrivateKey(): Uint8Array<ArrayBufferLike> {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.nodes.spending.getSpendingKeyPair().privateKey
  }

  /**
   *
   */
  getSpendingPublicKey(): SpendingPublicKey {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.spendingKeyPair.pubkey
  }

  /**
   *
   */
  getMasterPublicKey(): Uint8Array<ArrayBufferLike> {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.masterPublicKey
  }

  /**
   *
   */
  getNullifyingKey(): Uint8Array {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.nullifyingKey
  }

  /**
   *
   */
  getViewingPublicKey(): Uint8Array<ArrayBufferLike> {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.viewingKeyPair.pubkey
  }

  /**
   *
   */
  getViewingPrivateKey(): Uint8Array<ArrayBufferLike> {
    if (!this.keystore) {
      throw new Error('Keystore not initialized')
    }
    return this.keystore.viewingKeyPair.privateKey
  }
}
