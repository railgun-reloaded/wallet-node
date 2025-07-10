import type { WalletNodes } from '../wallet-node/wallet-node'
import { WalletNode } from '../wallet-node/wallet-node'

/**
 * A collection of derivation path prefixes used for generating hierarchical deterministic (HD) wallet keys.
 * These prefixes are used to define specific purposes for the derived keys.
 *
 * - `SPENDING`: Represents the derivation path prefix for spending keys, used for transactions and payments.
 *   Format: "m/44'/1984'/0'/0'/"
 *
 * - `VIEWING`: Represents the derivation path prefix for viewing keys, used for observing wallet balances and activity.
 *   Format: "m/420'/1984'/0'/0'/"
 */
const DERIVATION_PATH_PREFIXES = {
  SPENDING: "m/44'/1984'/0'/0'/",
  VIEWING: "m/420'/1984'/0'/0'/",
}

/**
 * Generates derivation paths for a given index based on predefined prefixes.
 *
 * The derivation paths are used for cryptographic key generation and are
 * constructed using the BIP44 standard with custom coin types and account indices.
 * @param index - The index to append to the derivation path. Defaults to 0 if not provided.
 * @returns An object containing the derivation paths for spending and viewing keys:
 * - `spending`: The derivation path for spending keys.
 * - `viewing`: The derivation path for viewing keys.
 *
 * Example:
 * ```typescript
 * const paths = derivePathsForIndex(1);
 * console.log(paths.spending); // "m/44'/1984'/0'/0'/1'"
 * console.log(paths.viewing);  // "m/420'/1984'/0'/0'/1'"
 * ```
 */
const derivePathsForIndex = (index: number = 0) => {
  return {
    spending: `${DERIVATION_PATH_PREFIXES.SPENDING}${index}'`,
    viewing: `${DERIVATION_PATH_PREFIXES.VIEWING}${index}'`,
  }
}

/**
 * Derives wallet nodes for spending and viewing purposes based on a mnemonic and an optional index.
 * @param mnemonic - The mnemonic phrase used to generate the wallet nodes.
 * @param index - The index used to derive specific paths (default is 0).
 * @returns An object containing the derived wallet nodes:
 *          - `spending`: The wallet node for spending operations.
 *          - `viewing`: The wallet node for viewing operations.
 */
const deriveNodes = (
  mnemonic: string,
  index: number = 0
): WalletNodes => {
  const paths = derivePathsForIndex(index)
  return {
    spending: WalletNode.fromMnemonic(mnemonic).derive(paths.spending),
    viewing: WalletNode.fromMnemonic(mnemonic).derive(paths.viewing),
  }
}

export { derivePathsForIndex, deriveNodes, DERIVATION_PATH_PREFIXES }
