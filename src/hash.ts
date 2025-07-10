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
 * Encodes a given string into a Uint8Array using UTF-8 encoding.
 * @param string - The input string to be encoded.
 * @returns A Uint8Array representing the UTF-8 encoded bytes of the input string.
 */
const encodeBytes = (string: string): Uint8Array => {
  return new TextEncoder().encode(string)
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
 * Converts a bigint value into a Uint8Array representation.
 * The function calculates the required length of the byte array based on the
 * decimal string representation of the bigint value, ensuring sufficient space
 * to store the value in bytes. It then iteratively extracts the least significant
 * 8 bits of the bigint and shifts the value right by 8 bits until the entire
 * bigint is converted into the byte array.
 * @param value - The bigint value to be converted into a Uint8Array.
 * @returns A Uint8Array containing the byte representation of the input bigint.
 */
const bigIntToArray = (value: bigint): Uint8Array => {
  // length = value.toString(2).length / 2
  const length = Math.ceil(value.toString(10).length / 2)

  console.log('length', length)
  const byteArray = new Uint8Array(length) // 256 bits = 32 bytes
  for (let i = 0; i < byteArray.length; i++) {
    byteArray[i] = Number(value & 0xffn) // Extract last 8 bits
    value >>= 8n // Shift right by 8 bits
  }
  return byteArray
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

// assumes buffers are both the same length.
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
    // @ts-ignore -- TODO: come back and fix this type error later.
    outputBuffer[i] = a[i] ^ b[i]
  }
}

export { xorBytesInPlace, bigIntToArray, bigintToUint8Array, encodeBytes, uint8ArrayToBigInt, sha512HMAC, hexToArray }
