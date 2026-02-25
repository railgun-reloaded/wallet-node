import { keccak_256 as keccak256 } from '@noble/hashes/sha3'

import { bigintToUint8Array, hexToUint8Array, padUint8Array, uint8ArrayToBigInt, uint8ArrayToHex } from '../encoding'

import type { TokenData } from './definitions'
import { SNARK_PRIME, TokenType } from './definitions'

/**
 * Computes the token hash for ERC20 tokens.
 * ERC20 token hash is simply the token address left-padded to 32 bytes.
 * @param tokenAddress - The ERC20 token address (20 bytes)
 * @returns The token hash as a hex string (32 bytes, no 0x prefix)
 */
function computeTokenHashERC20 (tokenAddress: Uint8Array): string {
  return uint8ArrayToHex(padUint8Array(tokenAddress, 32), false)
}

/**
 * Computes the token hash for NFT tokens (ERC721/ERC1155).
 * NFT token hash uses keccak256 of (tokenType + tokenAddress + tokenSubID) mod SNARK_PRIME.
 * @param tokenData - The NFT token data
 * @returns The token hash as a hex string (32 bytes, no 0x prefix)
 */
function computeTokenHashNFT (tokenData: TokenData): string {
  const tokenTypeBytes = bigintToUint8Array(BigInt(tokenData.tokenType), 32)
  const tokenAddressBytes = padUint8Array(tokenData.tokenAddress, 32)
  const tokenSubIDBytes = padUint8Array(tokenData.tokenSubID, 32)

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
    case TokenType.ERC20:
      return uint8ArrayToHex(tokenData.tokenAddress)
    case TokenType.ERC721:
    case TokenType.ERC1155:
      return `${uint8ArrayToHex(tokenData.tokenAddress)} (${uint8ArrayToHex(tokenData.tokenSubID)})`
    default:
      throw new Error(`Unrecognized token type: ${tokenData.tokenType}`)
  }
}

/** Null token sub ID for ERC20 tokens (32 zero bytes). */
const TOKEN_SUB_ID_NULL = new Uint8Array(32)

/**
 * Normalizes raw token components into a TokenData object.
 * @param tokenAddress - The token contract address (20 bytes)
 * @param tokenType - The token type (0=ERC20, 1=ERC721, 2=ERC1155), accepts bigint or number
 * @param tokenSubID - The token sub-identifier (32 bytes), or bigint
 * @returns A normalized TokenData object
 */
function serializeTokenData (
  tokenAddress: Uint8Array,
  tokenType: bigint | number,
  tokenSubID: Uint8Array | bigint
): TokenData {
  const normalizedSubID = typeof tokenSubID === 'bigint'
    ? bigintToUint8Array(tokenSubID, 32)
    : padUint8Array(tokenSubID, 32)

  return {
    tokenAddress: padUint8Array(tokenAddress, 20),
    tokenType: Number(tokenType),
    tokenSubID: normalizedSubID,
  }
}

/**
 * Creates a normalized TokenData for an ERC20 token.
 * Accepts a hex string for legacy compatibility (e.g. token hash used as address).
 * If the input is longer than 20 bytes (e.g. a 32-byte token hash), the last 20
 * bytes are extracted as the address.
 * @param tokenAddress - The ERC20 token contract address or hash (hex string)
 * @returns A normalized TokenData object with tokenType=0 and tokenSubID=0
 */
function getTokenDataERC20 (tokenAddress: string): TokenData {
  const bytes = hexToUint8Array(tokenAddress)
  const address = bytes.length > 20 ? bytes.slice(bytes.length - 20) : bytes
  return serializeTokenData(address, 0, TOKEN_SUB_ID_NULL)
}

/**
 * Deserializes and validates token data from a plain object (e.g. from msgpack decoding).
 * Handles both Uint8Array (new format) and string (legacy format) fields.
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

  const tokenAddress = data.tokenAddress instanceof Uint8Array
    ? padUint8Array(data.tokenAddress, 20)
    : padUint8Array(hexToUint8Array(String(data.tokenAddress)), 20)

  const tokenSubID = data.tokenSubID instanceof Uint8Array
    ? padUint8Array(data.tokenSubID, 32)
    : bigintToUint8Array(BigInt(data.tokenSubID), 32)

  return { tokenAddress, tokenType, tokenSubID }
}

/**
 * Validates that a note's token data and value are valid.
 * @param tokenData - The token data to validate
 * @param value - The note value to validate
 * @throws {Error} If validation fails
 */
function assertValidNoteToken (tokenData: TokenData, value: bigint): void {
  if (tokenData.tokenAddress.length !== 20) {
    throw new Error(
      `Token address must be 20 bytes. Got ${tokenData.tokenAddress.length} bytes.`
    )
  }

  switch (tokenData.tokenType) {
    case TokenType.ERC20: {
      if (!tokenData.tokenSubID.every(b => b === 0)) {
        throw new Error('ERC20 note cannot have tokenSubID parameter.')
      }
      return
    }

    case TokenType.ERC721: {
      if (tokenData.tokenSubID.length === 0) {
        throw new Error('ERC721 note must have tokenSubID parameter.')
      }
      if (value !== 1n) {
        throw new Error('ERC721 note must have value of 1.')
      }
      return
    }

    case TokenType.ERC1155: {
      if (tokenData.tokenSubID.length === 0) {
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
