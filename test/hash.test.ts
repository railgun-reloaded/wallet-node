import { test } from 'brittle'

import {
  bigintToUint8Array,
  encodeBytes,
  hexToArray,
  sha512HMAC,
  uint8ArrayToBigInt,
  xorBytesInPlace
} from '../src/hash'

test('hash - sha512HMAC', (t) => {
  const key = new Uint8Array([1, 2, 3, 4])
  const data = new Uint8Array([5, 6, 7, 8])
  const result = sha512HMAC(key, data)

  t.ok(result instanceof Uint8Array, 'should return Uint8Array')
  t.is(result.length, 64, 'should return 64 bytes (512 bits)')
})

test('hash - encodeBytes', (t) => {
  const vectors = [
    { input: '', expected: new Uint8Array([]) },
    { input: 'RAILGUN', expected: new Uint8Array([82, 65, 73, 76, 71, 85, 78]) },
    { input: 'PRIVACY & ANONYMITY', expected: new Uint8Array([80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89]) }
  ]

  for (const vector of vectors) {
    const result = encodeBytes(vector.input)
    t.alike(result, vector.expected, `should encode "${vector.input}" correctly`)
  }
})

test('hash - uint8ArrayToBigInt', (t) => {
  const vectors = [
    { array: new Uint8Array([1, 56, 188]), expected: BigInt('80060') },
    { array: new Uint8Array([82, 65, 73, 76, 71, 85, 78]), expected: BigInt('23152731158435150') },
    { array: new Uint8Array([0, 0, 0, 0]), expected: BigInt('0') }
  ]

  for (const vector of vectors) {
    const result = uint8ArrayToBigInt(vector.array)
    t.is(result, vector.expected, 'should convert array to bigint correctly')
  }
})

test('hash - hexToArray', (t) => {
  const vectors = [
    { hex: '0138bc', expected: new Uint8Array([1, 56, 188]) },
    { hex: '5241494c47554e', expected: new Uint8Array([82, 65, 73, 76, 71, 85, 78]) },
    { hex: '50524956414359202620414e4f4e594d495459', expected: new Uint8Array([80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89]) }
  ]

  for (const vector of vectors) {
    const result = hexToArray(vector.hex)
    t.alike(result, vector.expected, `should convert hex "${vector.hex}" to array correctly`)
  }
})

test('hash - hexToArray error on odd length', (t) => {
  t.exception(() => {
    hexToArray('abc')
  }, 'should throw error for odd length hex string')
})

test('hash - bigintToUint8Array', (t) => {
  const value = BigInt('256')
  const result = bigintToUint8Array(value)

  t.ok(result instanceof Uint8Array, 'should return Uint8Array')
  t.is(result.length, 32, 'should return 32 bytes by default')

  const result16 = bigintToUint8Array(value, 16)
  t.is(result16.length, 16, 'should return 16 bytes when specified')
})

test('hash - xorBytesInPlace', (t) => {
  const a = new Uint8Array([0xFF, 0x00, 0xAA])
  const b = new Uint8Array([0x0F, 0xF0, 0x55])
  const output = new Uint8Array(3)

  xorBytesInPlace(a, b, output, 0)

  t.alike(output, new Uint8Array([0xF0, 0xF0, 0xFF]), 'should XOR bytes correctly')
})

test('hash - round trip conversions', (t) => {
  const testBigInt = BigInt('1234567890')
  const asArray = bigintToUint8Array(testBigInt, 32)
  const backToBigInt = uint8ArrayToBigInt(asArray)

  t.is(backToBigInt, testBigInt, 'should convert bigint to array and back')
})
