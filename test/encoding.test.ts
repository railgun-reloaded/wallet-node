import assert from 'node:assert/strict'
import { test } from 'node:test'

import { bytesToHex } from '@railgun-reloaded/bytes'

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
    /Uint8Array expected/,
    'non-byte-array data should throw'
  )
  assert.throws(
    () => sha512HMAC(null as unknown as Uint8Array, new Uint8Array([1])),
    /Uint8Array expected/,
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
