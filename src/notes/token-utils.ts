import { keccak_256 as keccak256 } from '@noble/hashes/sha3'

import { bigintToUint8Array, hexToUint8Array, uint8ArrayToBigInt, uint8ArrayToHex } from '../hash.js'

import type { TokenData } from './definitions.js'
import { SNARK_PRIME } from './definitions.js'

/**
 * Computes the token hash for ERC20 tokens.
 * ERC20 token hash is simply the token address padded to 32 bytes.
 * @param tokenAddress - The ERC20 token address (hex string)
 * @returns The token hash as a hex string (32 bytes)
 */
function computeTokenHashERC20 (tokenAddress: string): string {
  const cleanAddress = tokenAddress.startsWith('0x') ? tokenAddress.slice(2) : tokenAddress
  // Pad to 32 bytes (64 hex chars)
  const padded = cleanAddress.padStart(64, '0')
  return '0x' + padded
}

/**
 * Computes the token hash for NFT tokens (ERC721/ERC1155).
 * NFT token hash uses keccak256 of (tokenType + tokenAddress + tokenSubID) mod SNARK_PRIME.
 * @param tokenData - The NFT token data
 * @returns The token hash as a hex string (32 bytes)
 */
function computeTokenHashNFT (tokenData: TokenData): string {
  // Prepare 32-byte components
  const tokenTypeBytes = bigintToUint8Array(BigInt(tokenData.tokenType), 32)
  const tokenAddressBytes = hexToUint8Array(tokenData.tokenAddress)

  // Pad address to 32 bytes if needed
  const paddedAddress = new Uint8Array(32)
  paddedAddress.set(tokenAddressBytes, 32 - tokenAddressBytes.length)

  const tokenSubIDBytes = hexToUint8Array(tokenData.tokenSubID)

  // Combine: tokenType (32) + tokenAddress (32) + tokenSubID (32) = 96 bytes
  const combined = new Uint8Array(96)
  combined.set(tokenTypeBytes, 0)
  combined.set(paddedAddress, 32)
  combined.set(tokenSubIDBytes, 64)

  // Hash with keccak256
  const hashed = keccak256(combined)
  const hashedBigInt = uint8ArrayToBigInt(hashed)

  // Modulo SNARK_PRIME
  const modulo = hashedBigInt % SNARK_PRIME

  return uint8ArrayToHex(bigintToUint8Array(modulo, 32), true)
}

/**
 * Computes the token hash from token data.
 * Uses different algorithms based on token type:
 * - ERC20: Direct address padding
 * - ERC721/ERC1155: keccak256 hash modulo SNARK_PRIME
 * @param tokenData - The token data to hash
 * @returns The token hash as a hex string
 */
function computeTokenHash (tokenData: TokenData): string {
  switch (tokenData.tokenType) {
    case 0: // TokenType.ERC20
      return computeTokenHashERC20(tokenData.tokenAddress)
    case 1: // TokenType.ERC721
    case 2: // TokenType.ERC1155
      return computeTokenHashNFT(tokenData)
    default:
      throw new Error(`Unrecognized token type: ${tokenData.tokenType}`)
  }
}

/**
 * Gets a human-readable representation of a token address.
 * @param tokenData - The token data
 * @returns A formatted string representation
 */
function getReadableTokenAddress (tokenData: TokenData): string {
  switch (tokenData.tokenType) {
    case 0: { // TokenType.ERC20
      const cleanAddress = tokenData.tokenAddress.startsWith('0x')
        ? tokenData.tokenAddress.slice(2)
        : tokenData.tokenAddress
      // Trim to 20 bytes (40 hex chars)
      const trimmed = cleanAddress.slice(-40)
      return '0x' + trimmed
    }
    case 1: // TokenType.ERC721
    case 2: // TokenType.ERC1155
      return `${tokenData.tokenAddress} (${tokenData.tokenSubID})`
    default:
      throw new Error(`Unrecognized token type: ${tokenData.tokenType}`)
  }
}

/**
 * Serializes token data to a plain object.
 * @param token - The token data to serialize
 * @returns The serialized token data object
 */
function serializeTokenData (token: TokenData): object {
  return {
    tokenAddress: token.tokenAddress,  // string
    tokenType: token.tokenType,        // number
    tokenSubID: token.tokenSubID,      // string
  }
}

/**
 * Deserializes token data from a plain object.
 * @param data - The object containing serialized token data
 * @returns The deserialized TokenData object
 */
function deserializeTokenData (data: any): TokenData {
  return {
    tokenAddress: data.tokenAddress,
    tokenType: data.tokenType,
    tokenSubID: data.tokenSubID,
  }
}

/**
 * Validates that a note's token data and value are valid.
 * @param tokenData - The token data to validate
 * @param value - The note value to validate
 * @throws {Error} If validation fails
 */
function assertValidNoteToken (tokenData: TokenData, value: bigint): void {
  const addressHex = tokenData.tokenAddress.startsWith('0x')
    ? tokenData.tokenAddress.slice(2)
    : tokenData.tokenAddress
  const addressLength = addressHex.length

  switch (tokenData.tokenType) {
    case 0: {
      // TokenType.ERC20
      if (addressLength !== 40 && addressLength !== 64) {
        throw new Error(
          `ERC20 address must be length 40 (20 bytes) or 64 (32 bytes). Got ${tokenData.tokenAddress}.`
        )
      }

      const subID = BigInt(tokenData.tokenSubID)
      if (subID !== 0n) {
        throw new Error('ERC20 note cannot have tokenSubID parameter.')
      }

      return
    }
    case 1: {
      // TokenType.ERC721
      if (addressLength !== 40) {
        throw new Error(
          `ERC721 address must be length 40 (20 bytes). Got ${tokenData.tokenAddress}.`
        )
      }

      if (!tokenData.tokenSubID || tokenData.tokenSubID === '0x' || tokenData.tokenSubID === '0x0') {
        throw new Error('ERC721 note must have tokenSubID parameter.')
      }

      if (value !== BigInt(1)) {
        throw new Error('ERC721 note must have value of 1.')
      }

      return
    }
    case 2: {
      // TokenType.ERC1155
      if (addressLength !== 40) {
        throw new Error(
          `ERC1155 address must be length 40 (20 bytes). Got ${tokenData.tokenAddress}.`
        )
      }

      if (!tokenData.tokenSubID || tokenData.tokenSubID === '0x' || tokenData.tokenSubID === '0x0') {
        throw new Error('ERC1155 note must have tokenSubID parameter.')
      }

      return
    }
    default:
      throw new Error(`Unrecognized token type: ${tokenData.tokenType}`)
  }
}

export {
  computeTokenHashERC20,
  computeTokenHashNFT,
  computeTokenHash,
  getReadableTokenAddress,
  serializeTokenData,
  deserializeTokenData,
  assertValidNoteToken
}
