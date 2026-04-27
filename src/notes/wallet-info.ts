import { bytesToBigInt, hexToBytes, hexlify } from '@railgun-reloaded/bytes'

const MAX_LENGTH = 16
const WALLET_SOURCE_CHARSET = ' 0123456789abcdefghijklmnopqrstuvwxyz'

/**
 * Base-37 encoding and decoding for wallet source identifiers.
 */
class WalletInfo {
  /**
   * Encodes a wallet source string into a base-37 representation as a Uint8Array.
   * Each character is mapped to the WALLET_SOURCE_CHARSET (space + 0-9 + a-z = 37 chars).
   * The result is a big-endian byte representation of the base-37 number.
   * @param walletSource - The wallet source string to encode (max 16 chars, lowercase)
   * @returns Uint8Array containing the encoded wallet source
   */
  static encodeWalletSource (walletSource: string): Uint8Array {
    if (!walletSource.length) {
      return new Uint8Array(0)
    }

    const lowercase = walletSource.toLowerCase()

    if (lowercase.length > MAX_LENGTH) {
      throw new Error(`Wallet source must be less than ${MAX_LENGTH} characters.`)
    }

    let outputNumber = 0n
    const base = BigInt(WALLET_SOURCE_CHARSET.length)

    for (let i = 0; i < lowercase.length; i += 1) {
      const charIndex = WALLET_SOURCE_CHARSET.indexOf(lowercase[i]!)

      if (charIndex === -1) {
        throw new Error(`Invalid character for wallet source: ${lowercase[i]}`)
      }

      const positional = base ** BigInt(lowercase.length - i - 1)
      outputNumber += BigInt(charIndex) * positional
    }

    if (outputNumber === 0n) {
      return new Uint8Array([0])
    }

    // Convert bigint to bytes (big-endian)
    return hexToBytes(hexlify(outputNumber))
  }

  /**
   * Decodes a base-37 encoded Uint8Array back to a wallet source string.
   * @param encoded - The encoded wallet source bytes (big-endian base-37 number)
   * @returns The decoded wallet source string
   */
  static decodeWalletSource (encoded: Uint8Array): string {
    if (encoded.length === 0) {
      return ''
    }

    // Convert bytes to bigint (big-endian)
    let inputNumber = bytesToBigInt(encoded)

    if (inputNumber === 0n) {
      return ''
    }

    let output = ''
    const base = BigInt(WALLET_SOURCE_CHARSET.length)

    while (inputNumber > 0) {
      const remainder = inputNumber % base
      output = WALLET_SOURCE_CHARSET[Number(remainder)] + output
      inputNumber = (inputNumber - remainder) / base
    }

    return output
  }
}

export { WalletInfo }
