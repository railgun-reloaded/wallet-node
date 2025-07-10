// @ts-ignore

import * as ed25519 from '@noble/ed25519'
import { ExtendedPoint as Point, getPublicKey } from '@noble/ed25519'
import { sha256, sha512 } from '@noble/hashes/sha2'
import { randomBytes } from '@noble/hashes/utils'
import { eddsaBuild, initCircomlib, initializeEddsa, poseidonBuild, poseidonFunc } from '@railgun-reloaded/cryptography'

import {
  bigintToUint8Array,
  uint8ArrayToBigInt,
  xorBytesInPlace,
} from './hash.js'

const CURVE_L = BigInt(
  '7237005577332262213973186563042994240857116359379907606001950938285454250989'
)

const CURVE_L_BYTES = bigintToUint8Array(CURVE_L)

// Set the SHA-512 implementation
// https://github.com/paulmillr/noble-ed25519/blob/main/README.md#enabling-synchronous-methods
// Sync methods can be used now:
// ed25519.getPublicKey(privKey);
// ed25519.sign(msg, privKey);
// ed25519.verify(signature, msg, pubKey);
/**
 *1
 * @param m a
 * @returns a
 */
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m))

/**
 * Initializes the cryptography libraries required for the application.
 * This function sets up Circomlib and EDDSA cryptographic primitives.
 * @throws {Error} Throws an error if EDDSA fails to initialize.
 * @returns A promise that resolves when the cryptography libraries are successfully initialized.
 */
const initializeCryptographyLibs = async () => {
  initCircomlib('pure')
  initializeEddsa(poseidonBuild.pure)
  if (typeof eddsaBuild === 'undefined') { throw new Error('EDDSA failed to initialize.') }
}

/**
 * Derives the public spending key from a given private key using the EdDSA algorithm.
 * @param privateKey - A 32-byte Uint8Array representing the private key.
 * @returns A tuple containing two bigints representing the public key coordinates.
 * @throws Error if the provided private key does not have a length of 32 bytes.
 */
const getPublicSpendingKey = (privateKey: Uint8Array): [bigint, bigint] => {
  // convert this from
  if (privateKey.length !== 32) throw Error('Invalid private key length')
  return eddsaBuild.prv2pub(Buffer.from(privateKey))
}

/**
 * Derives the public viewing key from the given private viewing key.
 * @param privateViewingKey - A `Uint8Array` representing the private viewing key.
 * @returns A promise that resolves to a `Uint8Array` containing the derived public viewing key.
 */
const getPublicViewingKey = (
  privateViewingKey: Uint8Array
): Uint8Array => {
  return getPublicKey(privateViewingKey)
}

/**
 * Adjust bits to match the pattern xxxxx000...01xxxxxx for little endian and 01xxxxxx...xxxxx000 for big endian
 * This ensures that the bytes are a little endian representation of an integer of the form (2^254 + 8) * x where
 * 0 \< x \<= 2^251 - 1, which can be decoded as an X25519 integer.
 * @param bytes - bytes to adjust
 * @param endian - what endian to use
 * @returns adjusted bytes
 */
const adjustBytes25519 = (bytes: Uint8Array, endian: 'be' | 'le'): Uint8Array => {
  // Create new array to prevent side effects
  const adjustedBytes = new Uint8Array(bytes)

  if (typeof adjustedBytes === 'undefined' || adjustedBytes.byteLength !== 32) {
    throw new Error('Invalid input: bytes must be a Uint8Array of length 32')
  }

  if (adjustedBytes && endian === 'be') {
    // BIG ENDIAN
    // AND operation to ensure the last 3 bits of the last byte are 0 leaving the rest unchanged
    // @ts-ignore
    adjustedBytes[31] &= 0b11111000

    // AND operation to ensure the first bit of the first byte is 0 leaving the rest unchanged
    // @ts-ignore
    adjustedBytes[0] &= 0b01111111

    // OR operation to ensure the second bit of the first byte is 0 leaving the rest unchanged
    // @ts-ignore
    adjustedBytes[0] |= 0b01000000
  } else {
    // LITTLE ENDIAN
    // AND operation to ensure the last 3 bits of the first byte are 0 leaving the rest unchanged
    // @ts-ignore
    adjustedBytes[0] &= 0b11111000

    // AND operation to ensure the first bit of the last byte is 0 leaving the rest unchanged
    // @ts-ignore
    adjustedBytes[31] &= 0b01111111

    // OR operation to ensure the second bit of the last byte is 0 leaving the rest unchanged
    // @ts-ignore
    adjustedBytes[31] |= 0b01000000
  }

  // Return adjusted bytes
  return adjustedBytes
}

/**
 * Extracts a private scalar from a given private key.
 *
 * This function takes a 32-byte private key, hashes it using SHA-512, and processes
 * the first 32 bytes of the hash to derive a scalar value. The scalar is adjusted
 * to fit within the curve's order (CURVE_L). If the resulting scalar is zero, the
 * function returns a predefined constant `CURVE_L_BYTES`.
 * @param privateKey - A 32-byte Uint8Array representing the private key.
 * @returns A Promise that resolves to a Uint8Array containing the derived scalar.
 * @throws An error if the provided private key is not exactly 32 bytes.
 */
const getPrivateScalarFromPrivateKey = async (
  privateKey: Uint8Array
): Promise<Uint8Array> => {
  // Private key should be 32 bytes
  if (privateKey.length !== 32) throw new Error('Expected 32 bytes')

  // SHA512 hash private key
  const hash = sha512(privateKey)

  // Get key head, this is the first 32 bytes of the hash
  // We aren't interested in the rest of the hash as we only want the scalar
  const head = adjustBytes25519(hash.slice(0, 32), 'le')

  // Convert head to scalar
  const scalarBigInt = uint8ArrayToBigInt(head.reverse()) % CURVE_L

  const scalar = bigintToUint8Array(scalarBigInt)

  return scalarBigInt > 0n ? scalar : CURVE_L_BYTES
}

/**
 * Generates a shared symmetric key using a private key pair and a blinded public key pair.
 * This function performs the following steps:
 * 1. Extracts the private scalar from the provided private key pair.
 * 2. Multiplies the blinded public key pair by the private scalar to compute the shared key preimage.
 * 3. Hashes the shared key preimage using SHA-256 to produce the final symmetric key.
 * @param privateKeyPairA - The private key pair of party A as a Uint8Array.
 * @param blindedPublicKeyPairB - The blinded public key pair of party B as a Uint8Array.
 * @returns A Promise that resolves to the generated symmetric key as a Uint8Array, or `undefined` if an error occurs.
 */
const getSharedSymmetricKey = async (
  privateKeyPairA: Uint8Array,
  blindedPublicKeyPairB: Uint8Array
): Promise<Uint8Array | undefined> => {
  try {
    // Retrieve private scalar from private key
    const scalar: Uint8Array = await getPrivateScalarFromPrivateKey(
      privateKeyPairA
    )

    // Multiply ephemeral key by private scalar to get shared key
    const keyPreimage: Uint8Array = scalarMultiplyWasmFallbackToJavascript(
      blindedPublicKeyPairB,
      scalar
    )

    // SHA256 hash to get the final key
    const hashed: Uint8Array = sha256(keyPreimage)
    return hashed
  } catch (err) {
    console.log(err)
    return undefined
  }
}

/**
 * Performs scalar multiplication on a blinded public key pair using a fallback mechanism.
 * If WebAssembly-based cryptographic operations are unavailable, it defaults to a JavaScript implementation.
 * @param blindedPublicKeyPairB - A Uint8Array containing the blinded public key pair.
 * @param scalar - A Uint8Array containing the scalar value for multiplication.
 * @returns A Uint8Array containing the result of the scalar multiplication.
 */
const scalarMultiplyWasmFallbackToJavascript = (
  blindedPublicKeyPairB: Uint8Array<ArrayBufferLike>,
  scalar: Uint8Array<ArrayBufferLike>
): Uint8Array<ArrayBufferLike> => {
  // const wasm = require("wasm-crypto");
  return scalarMultiplyJavascript(blindedPublicKeyPairB, scalar)
}

/**
 * Performs scalar multiplication of a given elliptic curve point and scalar using JavaScript.
 * @param point - A `Uint8Array` representing the elliptic curve point in hexadecimal format.
 * @param scalar - A `Uint8Array` representing the scalar value to multiply the point by.
 * @returns A `Uint8Array` containing the resulting elliptic curve point after scalar multiplication.
 * This function assumes that the `Point.fromHex` method is used to parse the input point,
 * and the `uint8ArrayToBigInt` function is used to convert the scalar to a `BigInt`.
 * The result is returned as raw bytes using the `toRawBytes` method.
 */
const scalarMultiplyJavascript = (
  point: Uint8Array,
  scalar: Uint8Array
) => {
  const pk = Point.fromHex(point)
  return pk.multiply(uint8ArrayToBigInt(scalar)).toRawBytes()
}

/**
 * Generates a random scalar value using the Poseidon hash function.
 *
 * This function creates a random 32-byte value, converts it to a bigint,
 * and then hashes it using the Poseidon hash function to produce a scalar.
 * @returns A random scalar value derived from the Poseidon hash.
 */
const getRandomScalar = (): bigint => {
  return poseidonFunc([uint8ArrayToBigInt(randomBytes(32))], true) as bigint
}

/**
 * Converts seed to curve scalar
 * @param seed - seed to convert
 * @returns scalar
 */
const seedToScalar = (seed: Uint8Array): Uint8Array => {
  // Hash to 512 bit value as per FIPS-186
  const seedHash = sha512(seed)

  // Return (seedHash mod (n - 1)) + 1 to fit to range 0 < scalar < n
  return bigintToUint8Array(
    (uint8ArrayToBigInt(seedHash) % ed25519.CURVE.n) - 1n + 1n
  )
}

/**
 * Generate blinding scalar value.
 * Combine sender and shared random via XOR
 * XOR is used because a 0 value senderRandom result in a no change to the sharedRandom
 * allowing the receiver to invert the blinding operation
 * Final random value is padded to 32 bytes
 * Get blinding scalar from random
 * @param sharedRandom - random value shared by both parties
 * @param senderRandom - random value only known to sender
 * @returns ephemeral keys
 */
const getBlindingScalar = (
  sharedRandom: Uint8Array,
  senderRandom: Uint8Array
): bigint => {
  // const finalRandom =
  //   uint8ArrayToBigInt(sharedRandom) ^ uint8ArrayToBigInt(senderRandom);
  const finalRandom = new Uint8Array(sharedRandom.length)
  xorBytesInPlace(sharedRandom, senderRandom, finalRandom)

  return uint8ArrayToBigInt(seedToScalar(finalRandom))
}

/**
 * Blinds sender and receiver public keys
 * @param senderViewingPublicKey - Sender's viewing public key
 * @param receiverViewingPublicKey - Receiver's viewing public key
 * @param sharedRandom - random value shared by both parties
 * @param senderRandom - random value only known to sender
 * @returns ephemeral keys
 */
const getNoteBlindingKeys = (
  senderViewingPublicKey: Uint8Array,
  receiverViewingPublicKey: Uint8Array,
  sharedRandom: Uint8Array,
  senderRandom: Uint8Array
): {
  blindedSenderViewingKey: Uint8Array;
  blindedReceiverViewingKey: Uint8Array;
} => {
  const blindingScalar = getBlindingScalar(sharedRandom, senderRandom)

  // Get public key points
  const senderPublicKeyPoint = Point.fromHex(senderViewingPublicKey)
  const receiverPublicKeyPoint = Point.fromHex(receiverViewingPublicKey)

  // Multiply both public keys by blinding scalar
  const blindedSenderViewingKey = senderPublicKeyPoint
    .multiply(blindingScalar)
    .toRawBytes()
  const blindedReceiverViewingKey = receiverPublicKeyPoint
    .multiply(blindingScalar)
    .toRawBytes()

  // Return blinded keys
  return { blindedSenderViewingKey, blindedReceiverViewingKey }
}

/**
 * Unblinds a blinded note key using the provided shared random and sender random values.
 * This function reverses the blinding operation applied to a note key by calculating
 * the blinding scalar, inverting it, and applying the inverse scalar to the blinded note key.
 * @param blindedNoteKey - The blinded note key as a Uint8Array.
 * @param sharedRandom - A shared random value used in the blinding operation as a Uint8Array.
 * @param senderRandom - A sender-specific random value used in the blinding operation as a Uint8Array.
 * @returns The unblinded note key as a Uint8Array, or `undefined` if the operation fails.
 */
const unblindNoteKey = (
  blindedNoteKey: Uint8Array,
  sharedRandom: Uint8Array,
  senderRandom: Uint8Array
): Uint8Array | undefined => {
  try {
    const blindingScalar = getBlindingScalar(sharedRandom, senderRandom)

    // Create curve point instance from ephemeral key bytes
    const point = Point.fromHex(
      // uint8ArrayToBigInt(
      blindedNoteKey
      // ).toString(16)
    )

    // Invert the scalar to undo blinding multiplication operation
    const inverse = ed25519.etc.invert(blindingScalar, ed25519.CURVE.n)

    // Unblind by multiplying by the inverted scalar
    const unblinded = point.multiply(inverse)

    return unblinded.toRawBytes()
  } catch {
    return undefined
  }
}
export {
  getPublicSpendingKey,
  getPublicViewingKey,
  adjustBytes25519,
  getPrivateScalarFromPrivateKey,
  getSharedSymmetricKey,
  initializeCryptographyLibs,
  scalarMultiplyWasmFallbackToJavascript,
  scalarMultiplyJavascript,
  getRandomScalar,
  seedToScalar,
  getBlindingScalar,
  getNoteBlindingKeys,
  unblindNoteKey
}
