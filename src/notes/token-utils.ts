import { keccak_256 as keccak256 } from '@noble/hashes/sha3'

import { bigintToHex, bigintToUint8Array, formatToByteLength, hexToUint8Array, hexlify, uint8ArrayToBigInt, uint8ArrayToHex } from '../encoding'

import type { TokenData } from './definitions'
import { SNARK_PRIME, TokenType } from './definitions'

/**
 * Computes the token hash for ERC20 tokens.
 * ERC20 token hash is simply the token address padded to 32 bytes.
 * @param tokenAddress - The ERC20 token address (hex string)
 * @returns The token hash as a hex string (32 bytes)
 */
function computeTokenHashERC20 (tokenAddress: string): string {
  return formatToByteLength(hexlify(tokenAddress), 32)
}

/**
 * Computes the token hash for NFT tokens (ERC721/ERC1155).
 * NFT token hash uses keccak256 of (tokenType + tokenAddress + tokenSubID) mod SNARK_PRIME.
 * @param tokenData - The NFT token data
 * @returns The token hash as a hex string (32 bytes)
 */
function computeTokenHashNFT (tokenData: TokenData): string {
  const tokenTypeBytes = bigintToUint8Array(BigInt(tokenData.tokenType), 32)
  const tokenAddressBytes = hexToUint8Array(formatToByteLength(hexlify(tokenData.tokenAddress), 32))
  const tokenSubIDBytes = hexToUint8Array(formatToByteLength(hexlify(tokenData.tokenSubID), 32))

  // Combine: tokenType (32) + tokenAddress (32) + tokenSubID (32) = 96 bytes
  const combined = new Uint8Array(96)
  combined.set(tokenTypeBytes, 0)
  combined.set(tokenAddressBytes, 32)
  combined.set(tokenSubIDBytes, 64)

  const hashed: Uint8Array = keccak256(combined)
  const modulo: bigint = uint8ArrayToBigInt(hashed) % SNARK_PRIME

  return uint8ArrayToHex(bigintToUint8Array(modulo, 32), false)
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
    case TokenType.ERC20:
      return computeTokenHashERC20(tokenData.tokenAddress)
    case TokenType.ERC721:
    case TokenType.ERC1155:
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
    case TokenType.ERC20: {
      const cleanAddress = hexlify(tokenData.tokenAddress)

      const trimmed = cleanAddress.slice(-40) // Trim to 20 bytes (40 hex chars)
      return '0x' + trimmed
    }
    case TokenType.ERC721:
    case TokenType.ERC1155:
      return `${tokenData.tokenAddress} (${tokenData.tokenSubID})`
    default:
      throw new Error(`Unrecognized token type: ${tokenData.tokenType}`)
  }
}

/** Null token sub ID for ERC20 tokens (no sub-identifier). */
const TOKEN_SUB_ID_NULL = '0x00'

/**
 * Normalizes a hex string to a fixed byte length with 0x prefix.
 * Left-pads with zeros, then trims from the left to the target length
 * (keeps the least-significant bytes).
 * @param hex - Input hex string (with or without 0x prefix)
 * @param byteLength - Target length in bytes
 * @returns Normalized hex string with 0x prefix
 */
function formatHexToByteLength (hex: string, byteLength: number): string {
  const padded = formatToByteLength(hex, byteLength)
  return '0x' + padded.slice(-byteLength * 2)
}

/**
 * Serializes raw token components into a normalized TokenData object.
 * Inspired by the engine's serializeTokenData in note-util.ts.
 *
 * Normalizations applied:
 * - tokenAddress: formatted to 20 bytes (40 hex chars) with 0x prefix
 * - tokenType: coerced to number (handles bigint from contract calls)
 * - tokenSubID: formatted to 32 bytes (64 hex chars) with 0x prefix
 * @param tokenAddress - The token contract address (hex string)
 * @param tokenType - The token type (0=ERC20, 1=ERC721, 2=ERC1155), accepts bigint or number
 * @param tokenSubID - The token sub-identifier (hex string or bigint), 0 for ERC20
 * @returns A normalized TokenData object
 */
function serializeTokenData (
  tokenAddress: string,
  tokenType: bigint | number,
  tokenSubID: bigint | string
): TokenData {
  return {
    tokenAddress: formatHexToByteLength(tokenAddress, 20),
    tokenType: Number(tokenType),
    tokenSubID: bigintToHex(BigInt(tokenSubID), 32),
  }
}

/**
 * Creates a normalized TokenData for an ERC20 token.
 * @param tokenAddress - The ERC20 token contract address (hex string)
 * @returns A normalized TokenData object with tokenType=0 and tokenSubID=0
 */
function getTokenDataERC20 (tokenAddress: string): TokenData {
  return serializeTokenData(tokenAddress, 0, TOKEN_SUB_ID_NULL)
}

/**
 * Deserializes and validates token data from a plain object (e.g. from msgpack decoding).
 * Ensures all fields are present and properly formatted.
 * @param data - The object containing serialized token data
 * @returns A validated and normalized TokenData object
 * @throws {Error} If required fields are missing or tokenType is invalid
 */
function deserializeTokenData (data: any): TokenData {
  if (!data || typeof data !== 'object') {
    throw new Error('Invalid token data: expected an object')
  }
  if (data.tokenAddress == null || data.tokenType == null || data.tokenSubID == null) {
    throw new Error('Invalid token data: missing required fields (tokenAddress, tokenType, tokenSubID)')
  }

  const tokenType = Number(data.tokenType)
  if (tokenType !== 0 && tokenType !== 1 && tokenType !== 2) {
    throw new Error(`Invalid token type: ${data.tokenType}`)
  }

  return {
    tokenAddress: formatHexToByteLength(String(data.tokenAddress), 20),
    tokenType,
    tokenSubID: bigintToHex(BigInt(data.tokenSubID), 32),
  }
}

/**
 * Validates that a note's token data and value are valid.
 * @param tokenData - The token data to validate
 * @param value - The note value to validate
 * @throws {Error} If validation fails
 */
function assertValidNoteToken (tokenData: TokenData, value: bigint): void {
  const tokenAddressLength = hexlify(tokenData.tokenAddress).length

  switch (tokenData.tokenType) {
    case TokenType.ERC20: {
      if (tokenAddressLength !== 40 && tokenAddressLength !== 64) {
        throw new Error(
          `ERC20 address must be length 40 (20 bytes) or 64 (32 bytes). Got ${tokenData.tokenAddress}.`
        )
      }
      if (BigInt(tokenData.tokenSubID) !== 0n) {
        throw new Error('ERC20 note cannot have tokenSubID parameter.')
      }
      return
    }

    case TokenType.ERC721: {
      if (tokenAddressLength !== 40) {
        throw new Error(
          `ERC721 address must be length 40 (20 bytes). Got ${tokenData.tokenAddress}.`
        )
      }
      if (!tokenData.tokenSubID.length) {
        throw new Error('ERC721 note must have tokenSubID parameter.')
      }
      if (value !== BigInt(1)) {
        throw new Error('ERC721 note must have value of 1.')
      }
      return
    }

    case TokenType.ERC1155: {
      if (tokenAddressLength !== 40) {
        throw new Error(
          `ERC1155 address must be length 40 (20 bytes). Got ${tokenData.tokenAddress}.`
        )
      }
      if (!tokenData.tokenSubID.length) {
        throw new Error('ERC1155 note must have tokenSubID parameter.')
      }
      return
    }

    default:
      throw new Error(`Unrecognized token type: ${tokenData.tokenType}`)
  }
}

export {
  TOKEN_SUB_ID_NULL,
  computeTokenHashERC20,
  computeTokenHashNFT,
  computeTokenHash,
  getReadableTokenAddress,
  serializeTokenData,
  getTokenDataERC20,
  deserializeTokenData,
  assertValidNoteToken
}
