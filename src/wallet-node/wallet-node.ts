import { poseidon } from '@railgun-reloaded/cryptography'

import { getPublicSpendingKey, getPublicViewingKey } from '../keys'
import { childKeyDerivationHardened, getMasterKeyFromSeed, getPathSegments } from '../seed/bip32'
import { Mnemonic } from '../seed/bip39'
import type { KeyNode, SpendingKeyPair, ViewingKeyPair } from '../types'

const HARDENED_OFFSET = 0x80000000
type WalletNodes = { spending: WalletNode; viewing: WalletNode }
/**
 * The `WalletNode` class provides functionality for hierarchical deterministic wallet management,
 * including key derivation, cryptographic operations, and key pair generation. It encapsulates
 * chain key and chain code properties, which are essential for secure key management and derivation.
 *
 * ### Features:
 * - **Key Management**: Handles chain key and chain code for cryptographic operations.
 * - **Mnemonic Support**: Allows creation of wallet nodes from mnemonic phrases.
 * - **Key Derivation**: Supports BIP32 hardened key derivation along specified paths.
 * - **Spending Key Pair**: Generates spending key pairs for transactions.
 * - **Viewing Key Pair**: Provides viewing key pairs for privacy-preserving operations.
 * - **Nullifying Key**: Computes nullifying keys for advanced cryptographic use cases.
 * - **Master Public Key**: Generates master public keys using Poseidon hash function.
 *
 * ### Usage:
 * This class is designed for use in cryptographic wallet implementations, enabling secure
 * key management and hierarchical deterministic wallet functionality.
 *
 * ### Dependencies:
 * - `poseidonFunc`: A cryptographic hash function used for key computations.
 * - `uint8ArrayToBigInt`: Utility for converting Uint8Array to bigint.
 * - External functions for mnemonic seed generation, key derivation, and public key computation.
 *
 * ### Notes:
 * - Ensure proper handling of Uint8Array and bigint conversions in cryptographic operations.
 * - Optimize key storage to avoid recalculating keys repeatedly.
 * - Implement missing TODOs for robust functionality.
 */
class WalletNode {
  /**
   * Represents the chain key used for cryptographic operations.
   * This is a private property containing a byte array (Uint8Array)
   * that is utilized for secure key management within the wallet node.
   */
  private chainKey: Uint8Array

  /**
   * Represents the chain code used in hierarchical deterministic wallets.
   * The chain code is a 32-byte value that, together with the private key,
   * is used to derive child keys in the wallet's key hierarchy.
   */
  private chainCode: Uint8Array

  /**
   * Constructs a new instance of the WalletNode class.
   * @param keyNode - An instance of the KeyNode class containing the chain key and chain code
   *                  used to initialize the WalletNode.
   */
  constructor (keyNode: KeyNode) {
    this.chainKey = keyNode.chainKey
    this.chainCode = keyNode.chainCode
  }

  /**
   * Creates a new instance of `WalletNode` from a given mnemonic phrase.
   * @param mnemonic - The mnemonic phrase used to generate the wallet node.
   * @returns A new `WalletNode` instance derived from the mnemonic.
   */
  static fromMnemonic (mnemonic: string): WalletNode {
    const seed = Mnemonic.toSeed(mnemonic)
    return new WalletNode(getMasterKeyFromSeed(seed))
  }

  /**
   * Derives new BIP32Node along path
   * @param path - path to derive along
   * @returns - new BIP32 implementation Node
   */
  derive (path: string): WalletNode {
    // Get path segments
    const segments = getPathSegments(path)

    // Calculate new key node
    const keyNode = segments.reduce(
      (parentKeys: KeyNode, segment: number) =>
        childKeyDerivationHardened(parentKeys, segment, HARDENED_OFFSET),
      {
        chainKey: this.chainKey,
        chainCode: this.chainCode,
      }
    )
    return new WalletNode(keyNode)
  }

  /**
   * Get spending key-pair
   * @returns keypair
   */
  getSpendingKeyPair (): SpendingKeyPair {
    const privateKey = this.chainKey
    const pubkey = getPublicSpendingKey(privateKey)
    return {
      privateKey,
      pubkey,
    }
  }

  /**
   * Generates the master public key using the provided spending public key and nullifying key.
   * @param spendingPublicKey - A tuple containing two bigints representing the spending public key.
   * @param nullifyingKey - A bigint representing the nullifying key.
   * @returns A Uint8Array representing the computed master public key.
   * This function utilizes the `poseidonFunc` to compute the master public key.
   * Ensure that the input keys are properly converted to the expected format before calling this function.
   * The conversion from `bigint` to `Uint8Array` is currently a TODO and should be implemented correctly.
   */
  static getMasterPublicKey (
    spendingPublicKey: [Uint8Array, Uint8Array],
    nullifyingKey: Uint8Array
  ): Uint8Array {
    // convert these from uint8Arrays here, they should be
    // TODO: properly do this, as its being 'set to' uint8 array inside here, and now revisded as bigint
    const output = poseidon([...spendingPublicKey, nullifyingKey]) as Uint8Array
    return output
  }

  /**
   * Retrieves the viewing key pair associated with the wallet node.
   * The viewing key pair consists of a private key and a public viewing key.
   * The private key is derived from the node's chain key, and the public viewing key
   * is generated using the `getPublicViewingKey` function.
   * @returns An object containing the private key and the public viewing key.
   * @todo Refactor to use a separate node chain key for enhanced security.
   */
  getViewingKeyPair (): ViewingKeyPair {
    // TODO: THIS should be a separate node chainkey
    const privateKey = this.chainKey
    const pubkey = getPublicViewingKey(privateKey)
    return { privateKey, pubkey }
  }

  /**
   * Generates the nullifying key for the wallet node.
   * This method calculates the nullifying key using the private key obtained
   * from the viewing key pair. The calculation involves converting the private
   * key into a bigint and applying the Poseidon hash function.
   * @returns The calculated nullifying key.
   * - The private key is currently recalculated every time this method is called.
   *   Consider securely storing the private key to optimize performance.
   * - The conversion and hashing process may need refinement to ensure proper
   *   handling of data types (e.g., uint8 array vs bigint).
   */
  getNullifyingKey (): Uint8Array {
    // TODO: store these securely instead of calculating every time?
    const { privateKey } = this.getViewingKeyPair()

    // const uint8Array = [uint8ArrayToBigInt(privateKey)]
    // TODO: properly do this, as its being 'set to' uint8 array inside here, and now revisded as bigint
    return poseidon([privateKey])
  }
}

export { WalletNode }
export type { WalletNodes }
