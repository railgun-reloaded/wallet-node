// TODO: lintfix
// eslint-disable-next-line camelcase
import { keccak_256 } from '@noble/hashes/sha3'
import { bytesToHex, pointConversion } from '@railgun-reloaded/cryptography'
import { HDKey } from '@scure/bip32'
import {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToEntropy,
  mnemonicToSeedSync,
  validateMnemonic,
} from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'

/**
 * Generates a hierarchical deterministic (HD) wallet path based on the specified index.
 * The path follows the BIP-44 standard for Ethereum wallets:
 * `m/44'/60'/0'/0/{index}`
 * @param index - The index of the address to derive. Defaults to `0` if not specified.
 * @returns The HD wallet path as a string.
 */
const getPath = (index = 0) => {
  return `m/44'/60'/0'/0/${index}`
}

/**
 * The `Mnemonic` class provides utility methods for working with BIP-39 mnemonic phrases.
 * It includes functionality for generating, validating, and converting mnemonic phrases
 * to entropy, seeds, and private keys. This class leverages the BIP-39 standard for secure
 * and deterministic key generation.
 *
 * Methods:
 * - `generate(strength: 128 | 192 | 256 = 128): string`:
 *   Generates a mnemonic phrase based on the specified entropy strength.
 *   Acceptable values are 128, 192, or 256 bits. Defaults to 128 if not specified.
 *
 * - `validate(mnemonic: string): boolean`:
 *   Validates a given mnemonic phrase against the BIP-39 wordlist.
 *   Returns `true` if the mnemonic is valid, otherwise `false`.
 *
 * - `toSeed(mnemonic: string, password: string = ""): Uint8Array`:
 *   Converts a BIP-39 mnemonic phrase into a seed. An optional password can be provided
 *   to secure the seed. Defaults to an empty string if not specified.
 *
 * - `toEntropy(mnemonic: string): Uint8Array`:
 *   Converts a BIP-39 mnemonic phrase into its corresponding entropy.
 *
 * - `fromEntropy(entropy: Uint8Array): string`:
 *   Generates a mnemonic phrase from the provided entropy.
 *
 * - `to0xPrivateKey(mnemonic: string, derivationIndex?: number): Uint8Array`:
 *   Converts a mnemonic phrase into a private key in the form of a `Uint8Array`.
 *   Optionally accepts a derivation index for hierarchical deterministic (HD) path derivation.
 */
export class Mnemonic {
  /**
   * Generates a mnemonic phrase based on the specified strength.
   * @param strength - The entropy strength for the mnemonic generation.
   *                   Acceptable values are 128, 192, or 256 bits.
   *                   Defaults to 128 if not specified.
   * @returns A mnemonic phrase as a string.
   */
  static generate (strength: 128 | 192 | 256 = 128): string {
    return generateMnemonic(wordlist, strength)
  }

  /**
   * Validates a given mnemonic phrase against the BIP39 wordlist.
   * @param mnemonic - The mnemonic phrase to validate.
   * @returns `true` if the mnemonic is valid, otherwise `false`.
   */
  static validate (mnemonic: string): boolean {
    return validateMnemonic(mnemonic, wordlist)
  }

  /**
   * Converts a BIP-39 mnemonic phrase into a seed.
   * @param mnemonic - The BIP-39 mnemonic phrase to be converted into a seed.
   * @param password - An optional password used to secure the seed. Defaults to an empty string if not provided.
   * @returns A `Uint8Array` representing the generated seed.
   */
  static toSeed (mnemonic: string, password: string = ''): Uint8Array {
    return mnemonicToSeedSync(mnemonic, password)
  }

  /**
   * Converts a BIP-39 mnemonic phrase into its corresponding entropy.
   * @param mnemonic - The BIP-39 mnemonic phrase to be converted.
   * @returns A `Uint8Array` representing the entropy derived from the mnemonic.
   */
  static toEntropy (mnemonic: string): Uint8Array {
    return mnemonicToEntropy(mnemonic, wordlist)
  }

  /**
   * Generates a mnemonic phrase from the provided entropy.
   * @param entropy - A `Uint8Array` representing the entropy used to generate the mnemonic.
   * @returns A string containing the mnemonic phrase derived from the entropy.
   */
  static fromEntropy (entropy: Uint8Array): string {
    return entropyToMnemonic(entropy, wordlist)
  }

  /**
   * Converts a mnemonic phrase into a private key in the form of a `Uint8Array`.
   * @param mnemonic - The BIP-39 mnemonic phrase used to generate the seed.
   * @param derivationIndex - (Optional) The index used for deriving the key from the hierarchical deterministic (HD) path.
   *                          If not provided, a default derivation path will be used.
   * @returns The derived private key as a `Uint8Array`.
   */
  static to0xPrivateKey (
    mnemonic: string,
    derivationIndex?: number
  ): Uint8Array {
    const node = Mnemonic.to0xSigner(mnemonic, derivationIndex)
    const privateKey = node.privateKey as Uint8Array
    return privateKey
  }

  /**
   * Converts a mnemonic phrase into a signer object using the specified derivation path.
   * @param mnemonic - The mnemonic phrase used to generate the seed.
   * @param derivationIndex - Optional index for deriving the path. If not provided, a default path is used.
   * @returns An HDKey node derived from the seed and path.
   */
  static to0xSigner (
    mnemonic: string,
    derivationIndex?: number
  ) {
    const seed = mnemonicToSeedSync(mnemonic)
    const path = getPath(derivationIndex)
    const node = HDKey.fromMasterSeed(seed).derive(path)
    return node
  }

  /**
   * Converts an HDKey instance to an Ethereum address in hexadecimal format (0x-prefixed).
   * @param hdkey - The HDKey instance containing the public key to derive the address from.
   * @returns The Ethereum address as a hexadecimal string (0x-prefixed).
   * @throws {Error} If the HDKey instance is invalid or the public key is missing.
   * @throws {Error} If the public key length is invalid (compressed public keys are not supported).
   */
  static hdkeyTo0xAddress (hdkey: HDKey): string {
    // @ts-ignore TODO: typefix incorrect typescript error
    const { pubKey } = hdkey
    if (!pubKey) {
      throw new Error('Invalid HDKey.')
    }

    // Ensure it's compressed (should be 33 bytes, starts with 0x04)
    if (pubKey.length !== 33) {
      throw new Error('Invalid public key length')
    }
    const point = pointConversion(bytesToHex(pubKey))
    const uncompressed = point.toRawBytes(false) // 65 bytes

    const hash = keccak_256(uncompressed.slice(1))
    const address = hash.slice(-20)
    return '0x' + Buffer.from(address).toString('hex')
  }
}
