import { encodeBytes, sha512HMAC } from '../hash.js'
import type { KeyNode } from '../types.js'

const CURVE_SEED = encodeBytes('babyjubjub seed') // same calculation as current engine

/**
 * Tests derivation path to see if it's valid.
 * Valid paths must start with 'm' and contain only hardened derivation segments (e.g., "m/44'/0'/0'").
 * @param path - The derivation path string to test
 * @returns True if the path is valid, false otherwise
 */
function isValidPath (path: string): boolean {
  return /^m(\/[0-9]+')+$/g.test(path)
}

/**
 * Converts path string into segments.
 * Parses a BIP32 derivation path and extracts the numeric indices.
 * @param path - The derivation path string to parse (e.g., "m/44'/0'/0'")
 * @returns Array of numeric indices extracted from the path
 * @throws {Error} If the derivation path is invalid
 */
function getPathSegments (path: string): number[] {
  // Throw if path is invalid
  if (!isValidPath(path)) throw new Error('Invalid derivation path')

  // Split along '/' to get each component
  // Remove the first segment as it is the 'm'
  // Remove the ' from each segment
  // Parse each segment into an integer
  return path
    .split('/')
    .slice(1)
    .map((val) => val.replace("'", ''))
    .map((el) => parseInt(el, 10))
}

/**
 * Derives a hardened child key from a given parent key node using the BIP-32 specification.
 * Hardened derivation is achieved by including the parent key's chain key and an offset in the derivation process.
 * @param node - The parent key node containing the chain key and chain code.
 * @param index - The index of the child key to derive. Must be a non-negative integer.
 * @param offset - The offset value used for hardened derivation. Defaults to `0x80000000`.
 * @returns A new `KeyNode` object containing the derived chain key and chain code.
 * - Hardened derivation ensures that the child key cannot be derived without access to the parent key's chain key.
 * - The function uses HMAC-SHA512 to compute the derived values.
 * - The `index` is converted to a 32-bit big-endian byte array and combined with the parent chain key to form the HMAC input.
 */
function childKeyDerivationHardened (
  node: KeyNode,
  index: number,
  offset: number = 0x80000000
): KeyNode {
  // Convert index to bytes as 32bit big endian
  const indexBytes = new Uint8Array(4)
  const view = new DataView(indexBytes.buffer)
  view.setUint32(0, index + offset, false) // big-endian

  // Calculate HMAC preImage
  //   const preImage = `00${node.chainKey}${indexFormatted as string}`;
  const preImageBytes = new Uint8Array(
    1 + node.chainKey.byteLength + indexBytes.byteLength
  )
  preImageBytes.set([0x00], 0)
  preImageBytes.set(node.chainKey, 1)
  preImageBytes.set(indexBytes, 1 + node.chainKey.length)

  // Calculate I
  const I = sha512HMAC(node.chainCode, preImageBytes)

  // Slice 32 bytes for IL and IR values, IL = key, IR = chainCode
  const chainKey = new Uint8Array(I.slice(0, 32))
  const chainCode = new Uint8Array(I.slice(32))

  return {
    chainKey,
    chainCode,
  }
}

/**
 * Creates KeyNode from seed.
 * Generates the master key node using HMAC-SHA512 with the babyjubjub seed.
 * @param seed - The BIP32 seed (Uint8Array)
 * @returns KeyNode containing chainKey and chainCode
 */
function getMasterKeyFromSeed (seed: Uint8Array): KeyNode {
  // HMAC with seed to get I
  const I = sha512HMAC(CURVE_SEED, seed)

  // Slice 32 bytes for IL and IR values, IL = key, IR = chainCode
  const chainKey = I.slice(0, 32)
  const chainCode = I.slice(32)

  // Return node
  return {
    chainKey,
    chainCode,
  }
}

export { getPathSegments, getMasterKeyFromSeed, childKeyDerivationHardened }
