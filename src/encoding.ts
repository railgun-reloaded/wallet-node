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
  for (let i = offset; i < a.length; i += 1) {
    outputBuffer[i] = a[i]! ^ b[i]!
  }
}

export { sha512HMAC, xorBytesInPlace }
