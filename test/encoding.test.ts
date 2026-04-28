import { bytesToHex } from '@railgun-reloaded/bytes'
import { test } from 'brittle'

import {
  sha512HMAC,
  xorBytesInPlace,
} from '../src/encoding'

test('encoding - sha512HMAC', (t) => {
  const key = new Uint8Array([1, 2, 3, 4])
  const data = new Uint8Array([5, 6, 7, 8])
  const result = sha512HMAC(key, data)

  t.ok(result instanceof Uint8Array, 'should return Uint8Array')
  t.is(result.length, 64, 'should return 64 bytes (512 bits)')
})

test('encoding - sha512HMAC known vectors', (t) => {
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
    t.is(bytesToHex(sha512HMAC(v.key, v.data)), v.expected, `HMAC for key=0x${bytesToHex(v.key)}`)
  }
})

test('encoding - xorBytesInPlace', (t) => {
  const a = new Uint8Array([0xFF, 0x00, 0xAA])
  const b = new Uint8Array([0x0F, 0xF0, 0x55])
  const output = new Uint8Array(3)

  xorBytesInPlace(a, b, output, 0)

  t.alike(output, new Uint8Array([0xF0, 0xF0, 0xFF]), 'should XOR bytes correctly')
})
