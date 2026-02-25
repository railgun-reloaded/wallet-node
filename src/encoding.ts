import { createHmac } from 'node:crypto'

/**
 * Computes the HMAC (Hash-based Message Authentication Code) using the SHA-512 hash function.
 * @param key - The secret key used for the HMAC computation as a `Uint8Array`.
 * @param data - The input data to be hashed as a `Uint8Array`.
 * @returns A `Uint8Array` containing the resulting HMAC digest.
 */
const sha512HMAC = (key: Uint8Array, data: Uint8Array): Uint8Array => {
  return createHmac('sha512', key).update(data).digest()
}

/**
 * Converts a Uint8Array into a bigint by interpreting the array as a big-endian sequence of bytes.
 * Each byte is shifted and combined into the resulting bigint.
 * @param uint8Array - The input Uint8Array to be converted.
 * @returns The resulting bigint representation of the input array.
 */
const uint8ArrayToBigInt = (uint8Array: Uint8Array): bigint => {
  let result = BigInt(0)
  for (const byte of uint8Array) {
    result = (result << BigInt(8)) | BigInt(byte)
  }
  return result
}

/**
 * Converts a hexadecimal string into a Uint8Array.
 * @param hex - The hexadecimal string to convert. Must have an even length.
 * @returns A Uint8Array representing the binary data of the hexadecimal string.
 * @throws {Error} If the hexadecimal string has an odd length.
 */
const hexToArray = (hex: string): Uint8Array => {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have an even length')
  }
  const array = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }

  return array
}

/**
 * Converts a bigint value into a Uint8Array of a specified length.
 * This function is useful for representing large integers as byte arrays,
 * such as for cryptographic or serialization purposes.
 * @param value - The bigint value to convert into a byte array.
 * @param length - The desired length of the resulting Uint8Array. Defaults to 32 bytes.
 *                 Ensure the length is sufficient to represent the bigint value.
 * @returns A Uint8Array representing the bigint value, with the specified length.
 *          The array is filled with zeroes if the bigint value is smaller than the specified length.
 */
const bigintToUint8Array = (value: bigint, length = 32): Uint8Array => {
  const bytes = new Uint8Array(length) // 32 bytes for 256-bit
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn) // Extract last 8 bits
    value >>= 8n // Shift right by 8 bits
  }
  return bytes
}

/**
 * Performs an in-place XOR operation between two input byte arrays (`a` and `b`) and stores the result
 * in the provided output buffer (`outputBuffer`). The operation starts at the specified offset.
 * @param a - The first input byte array.
 * @param b - The second input byte array.
 * @param outputBuffer - The buffer where the XOR result will be stored.
 * @param offset - The starting index for the XOR operation. Defaults to 0.
 * @throws {RangeError} If the `outputBuffer` does not have sufficient length to store the result.
 * @throws {Error} If the lengths of `a` and `b` do not match.
 */
const xorBytesInPlace = (
  a: Uint8Array,
  b: Uint8Array,
  outputBuffer: Uint8Array,
  offset: number = 0
): void => {
  for (let i = offset; i < a.length; i++) {
    outputBuffer[i] = a[i]! ^ b[i]!
  }
}

/**
 * Converts a Uint8Array to a hexadecimal string representation.
 * @param bytes - The Uint8Array to convert
 * @param prefix - Whether to include '0x' prefix (default: true)
 * @returns A hexadecimal string
 */
const uint8ArrayToHex = (bytes: Uint8Array, prefix: boolean = true): string => {
  const hex = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
  return prefix ? '0x' + hex : hex
}

/**
 * Converts a hex string to Uint8Array with proper validation.
 * @param hex - The hex string to convert (with or without 0x prefix)
 * @returns The converted Uint8Array
 * @throws {Error} If hex string is invalid
 */
const hexToUint8Array = (hex: string): Uint8Array => {
  const cleanHex = strip0x(hex)
  if (cleanHex.length % 2 !== 0) {
    throw new Error(`Hex string must have even length. Got: ${hex}`)
  }
  if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
    throw new Error(`Invalid hex string: ${hex}`)
  }
  return hexToArray(cleanHex)
}

/**
 * Strips 0x prefix and pads hex string to the target byte length (left-padded with zeros).
 * @param hex - hex string, optionally prefixed with 0x
 * @param byteLength - target length in bytes
 * @returns padded hex string without 0x prefix
 */
const formatToByteLength = (hex: string, byteLength: number): string => {
  const stripped = strip0x(hex)
  return stripped.padStart(byteLength * 2, '0')
}

/**
 * Converts a bigint to a 0x-prefixed hex string of a fixed byte length.
 * @param value - The bigint value
 * @param byteLength - Target length in bytes
 * @returns Hex string with 0x prefix, zero-padded to the specified length
 */
const bigintToHex = (value: bigint, byteLength: number): string => {
  const hex = value.toString(16)
  const charLength = byteLength * 2
  return '0x' + hex.padStart(charLength, '0')
}

/**
 * Strips the '0x' prefix from a hex string if present.
 * @param hex - The hex string to strip
 * @returns The hex string without '0x' prefix
 */
const strip0x = (hex: string): string => hex.startsWith('0x') ? hex.slice(2) : hex

/**
 * Coerces various data types into a normalized lowercase hex string.
 * Strips 0x prefix from strings, pads odd-length hex to even, converts
 * bigints/numbers to hex, and converts Uint8Arrays to hex.
 * @param data - The data to hexlify (string, bigint, number, or Uint8Array)
 * @returns A normalized lowercase hex string without 0x prefix
 */
const hexlify = (data: string | bigint | number | Uint8Array): string => {
  let hexString: string

  if (typeof data === 'string') {
    hexString = strip0x(data)
  } else if (typeof data === 'bigint' || typeof data === 'number') {
    hexString = BigInt(data).toString(16)
    if (hexString.length % 2 === 1) {
      hexString = '0' + hexString
    }
  } else {
    hexString = Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('')
  }

  return hexString.toLowerCase()
}

/**
 * Left-pads a Uint8Array with zeros to a target byte length.
 * Returns the input unchanged if already at or above the target length.
 * @param bytes - The input Uint8Array
 * @param targetLength - Desired length in bytes
 * @returns A Uint8Array of exactly targetLength bytes, zero-padded on the left
 */
const padUint8Array = (bytes: Uint8Array, targetLength: number): Uint8Array => {
  if (bytes.length >= targetLength) {
    return bytes
  }
  const padded = new Uint8Array(targetLength)
  padded.set(bytes, targetLength - bytes.length)
  return padded
}

export { xorBytesInPlace, bigintToUint8Array, uint8ArrayToBigInt, sha512HMAC, uint8ArrayToHex, hexToUint8Array, formatToByteLength, bigintToHex, hexlify, padUint8Array }
