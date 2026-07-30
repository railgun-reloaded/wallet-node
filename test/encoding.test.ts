import assert from 'node:assert/strict'
import { test } from 'node:test'

import { bytesToHex, hexToBytes } from '@railgun-reloaded/bytes'

import {
  sha512HMAC,
  xorBytesInPlace,
} from '../src/encoding.js'

test('encoding - sha512HMAC', () => {
  const key = new Uint8Array([1, 2, 3, 4])
  const data = new Uint8Array([5, 6, 7, 8])
  const result = sha512HMAC(key, data)

  assert.ok(result instanceof Uint8Array, 'should return Uint8Array')
  assert.equal(result.length, 64, 'should return 64 bytes (512 bits)')
})

test('encoding - sha512HMAC known vectors', () => {
  const vectors = [
    {
      key: new Uint8Array([170]),
      data: new Uint8Array([]),
      expected: '4e9f386d58475d4e030c55c47f54ab3e2e5790d2aaaedc2f4465b5665a5307da3416778a481a09a2f18e1db63c26d741aa0a82af5a38a893bf9793fb7dea031e',
    },
    {
      key: new Uint8Array([187]),
      data: new Uint8Array([82, 65, 73, 76, 71, 85, 78]),
      expected: '206aca0dd9a7d87873692ff48a91f0c495ab896c488c4af5e7062774e8841298ddc9eee9699a6930b545aebf6dd3504bcef331231368318da26bb3783fdcc086',
    },
    {
      key: new Uint8Array([204]),
      data: new Uint8Array([80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89]),
      expected: 'b3513bb5230d933d8dc2cf28eddfa566bb76f49aa9bdf6f2475df0405feaaab4782d9d7a177ee9e32aa1e0af0ca0bb93a3c0312aa18788c7944a24f761bdcc1a',
    },
  ]

  for (const v of vectors) {
    assert.equal(bytesToHex(sha512HMAC(v.key, v.data)), v.expected, `HMAC for key=0x${bytesToHex(v.key)}`)
  }
})

/**
 * Build a byte array of `length` bytes all set to `value`.
 * @param value - Byte value to repeat.
 * @param length - Number of bytes to produce.
 * @returns The filled byte array.
 */
const repeatByte = (value: number, length: number): Uint8Array => new Uint8Array(length).fill(value)

/**
 * Encode an ASCII string as bytes.
 * @param text - Text to encode.
 * @returns UTF-8 encoded bytes.
 */
const ascii = (text: string): Uint8Array => new TextEncoder().encode(text)

// HMAC-SHA-512 known-answer vectors from RFC 4231 section 4. Cases 6 and 7 use a
// 131-byte key, longer than SHA-512's 128-byte block, which forces the key to be
// pre-hashed before use. Case 5 is omitted: it covers 128-bit tag truncation,
// which this helper does not perform.
// Source: https://www.rfc-editor.org/rfc/rfc4231
const rfc4231Vectors = [
  {
    name: '1 - 20-byte key',
    key: repeatByte(0x0b, 20),
    data: ascii('Hi There'),
    expected: '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
  },
  {
    name: '2 - short key, longer data',
    key: ascii('Jefe'),
    data: ascii('what do ya want for nothing?'),
    expected: '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  },
  {
    name: '3 - 20-byte key, 50-byte data',
    key: repeatByte(0xaa, 20),
    data: repeatByte(0xdd, 50),
    expected: 'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
  },
  {
    name: '4 - 25-byte key, 50-byte data',
    key: hexToBytes('0102030405060708090a0b0c0d0e0f10111213141516171819'),
    data: repeatByte(0xcd, 50),
    expected: 'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
  },
  {
    name: '6 - 131-byte key, over the SHA-512 block size',
    key: repeatByte(0xaa, 131),
    data: ascii('Test Using Larger Than Block-Size Key - Hash Key First'),
    expected: '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
  },
  {
    name: '7 - 131-byte key, over-length data',
    key: repeatByte(0xaa, 131),
    data: ascii('This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.'),
    expected: 'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
  },
]

for (const v of rfc4231Vectors) {
  test(`encoding - sha512HMAC matches RFC 4231 test case ${v.name}`, () => {
    assert.equal(bytesToHex(sha512HMAC(v.key, v.data)), v.expected)
  })
}

test('encoding - sha512HMAC has no key-length restriction', () => {
  const empty = sha512HMAC(new Uint8Array([]), new Uint8Array([]))
  assert.equal(empty.length, 64, 'empty key and data should still produce a 64-byte digest')

  // Keys longer than the SHA-512 block size (128 bytes) are pre-hashed internally,
  // so there is no upper bound on key length.
  const longKey = sha512HMAC(new Uint8Array(200).fill(7), new Uint8Array([1, 2, 3]))
  assert.equal(longKey.length, 64, 'over-length key should produce a 64-byte digest')
})

test('encoding - sha512HMAC is deterministic', () => {
  const key = new Uint8Array([9, 8, 7])
  const data = new Uint8Array([1, 2, 3, 4, 5])
  assert.equal(
    bytesToHex(sha512HMAC(key, data)),
    bytesToHex(sha512HMAC(key, data)),
    'same inputs should yield identical output'
  )
})

test('encoding - sha512HMAC rejects non-byte-array input', () => {
  assert.throws(
    () => sha512HMAC(new Uint8Array([1]), 123 as unknown as Uint8Array),
    /Uint8Array/,
    'non-byte-array data should throw'
  )
  assert.throws(
    () => sha512HMAC(null as unknown as Uint8Array, new Uint8Array([1])),
    /Uint8Array/,
    'null key should throw'
  )
})

test('encoding - xorBytesInPlace', () => {
  const a = new Uint8Array([0xFF, 0x00, 0xAA])
  const b = new Uint8Array([0x0F, 0xF0, 0x55])
  const output = new Uint8Array(3)

  xorBytesInPlace(a, b, output, 0)

  assert.deepEqual(output, new Uint8Array([0xF0, 0xF0, 0xFF]), 'should XOR bytes correctly')
})
