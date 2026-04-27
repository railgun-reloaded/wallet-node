import {
  bigIntToBytes,
  bigIntToHex,
  bytesToBigInt,
  bytesToHex,
  hexToBytes,
  hexlify,
  padBytesLeft,
} from '@railgun-reloaded/bytes'
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

test('encoding - uint8ArrayToBigInt', (t) => {
  const vectors = [
    { array: new Uint8Array([1, 56, 188]), expected: BigInt('80060') },
    { array: new Uint8Array([82, 65, 73, 76, 71, 85, 78]), expected: BigInt('23152731158435150') },
    { array: new Uint8Array([0, 0, 0, 0]), expected: BigInt('0') }
  ]

  for (const vector of vectors) {
    const result = bytesToBigInt(vector.array)
    t.is(result, vector.expected, 'should convert array to bigint correctly')
  }
})

test('encoding - hexToUint8Array', (t) => {
  const vectors = [
    { hex: '0x0138bc', expected: new Uint8Array([1, 56, 188]) },
    { hex: '5241494c47554e', expected: new Uint8Array([82, 65, 73, 76, 71, 85, 78]) },
    { hex: '0x50524956414359202620414e4f4e594d495459', expected: new Uint8Array([80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89]) }
  ]

  for (const vector of vectors) {
    const result = hexToBytes(vector.hex)
    t.alike(result, vector.expected, `should convert hex "${vector.hex}" to array correctly`)
  }
})

test('encoding - hexToUint8Array error on odd length', (t) => {
  t.exception(() => {
    hexToBytes('0xabc')
  }, 'should throw error for odd length hex string')
})

test('encoding - bigintToUint8Array', (t) => {
  const value = BigInt('256')
  const result = bigIntToBytes(value, 32)

  t.ok(result instanceof Uint8Array, 'should return Uint8Array')
  t.is(result.length, 32, 'should return 32 bytes by default')

  const result16 = bigIntToBytes(value, 16)
  t.is(result16.length, 16, 'should return 16 bytes when specified')
})

test('encoding - xorBytesInPlace', (t) => {
  const a = new Uint8Array([0xFF, 0x00, 0xAA])
  const b = new Uint8Array([0x0F, 0xF0, 0x55])
  const output = new Uint8Array(3)

  xorBytesInPlace(a, b, output, 0)

  t.alike(output, new Uint8Array([0xF0, 0xF0, 0xFF]), 'should XOR bytes correctly')
})

test('encoding - round trip conversions', (t) => {
  const testBigInt = BigInt('1234567890')
  const asArray = bigIntToBytes(testBigInt, 32)
  const backToBigInt = bytesToBigInt(asArray)

  t.is(backToBigInt, testBigInt, 'should convert bigint to array and back')
})

test('encoding - uint8ArrayToHex empty array', (t) => {
  t.is(bytesToHex(new Uint8Array([]), { prefix: true }), '0x', 'empty array with prefix')
  t.is(bytesToHex(new Uint8Array([])), '', 'empty array without prefix')
})

test('encoding - uint8ArrayToHex single bytes', (t) => {
  t.is(bytesToHex(new Uint8Array([0]), { prefix: true }), '0x00', 'zero byte')
  t.is(bytesToHex(new Uint8Array([255]), { prefix: true }), '0xff', '0xff byte')
  t.is(bytesToHex(new Uint8Array([16]), { prefix: true }), '0x10', 'byte 16 zero-padded')
})

test('encoding - uint8ArrayToHex multiple bytes', (t) => {
  t.is(bytesToHex(new Uint8Array([1, 2, 3]), { prefix: true }), '0x010203', 'with prefix')
  t.is(bytesToHex(new Uint8Array([1, 2, 3])), '010203', 'without prefix')
})

test('encoding - padUint8Array shorter than target', (t) => {
  t.alike(
    padBytesLeft(new Uint8Array([1]), 3),
    new Uint8Array([0, 0, 1]),
    'should left-pad with zeros'
  )
})

test('encoding - padUint8Array equal to target', (t) => {
  const input = new Uint8Array([1, 2])
  t.is(padBytesLeft(input, 2), input, 'should return same reference')
})

test('encoding - padUint8Array longer than target', (t) => {
  const input = new Uint8Array([1, 2, 3])
  t.is(padBytesLeft(input, 2), input, 'should return unchanged')
})

test('encoding - padUint8Array empty input', (t) => {
  t.alike(
    padBytesLeft(new Uint8Array([]), 3),
    new Uint8Array([0, 0, 0]),
    'should pad empty to target'
  )
})

test('encoding - padUint8Array targetLength zero', (t) => {
  const input = new Uint8Array([1, 2])
  t.is(padBytesLeft(input, 0), input, 'should return unchanged when target is 0')
})

test('encoding - hexlify string inputs', (t) => {
  t.is(hexlify('0xAbCd'), 'abcd', 'strips 0x and lowercases')
  t.is(hexlify('abcd'), 'abcd', 'no prefix unchanged')
  t.is(hexlify('ABCD'), 'abcd', 'uppercase to lowercase')
})

test('encoding - hexlify bigint inputs', (t) => {
  t.is(hexlify(256n), '0100', '256n → 0100')
  t.is(hexlify(0n), '00', '0n → 00')
  t.is(hexlify(255n), 'ff', '255n → ff')
  t.is(hexlify(1n), '01', '1n → 01 (padded to even)')
})

test('encoding - hexlify number inputs', (t) => {
  t.is(hexlify(256), '0100', '256 → 0100')
  t.is(hexlify(0), '00', '0 → 00')
})

test('encoding - hexlify Uint8Array inputs', (t) => {
  t.is(hexlify(new Uint8Array([255, 0, 1])), 'ff0001', 'bytes to hex')
  t.is(hexlify(new Uint8Array([])), '', 'empty array → empty string')
})

test('encoding - bigintToHex', (t) => {
  t.is(bigIntToHex(0n, 1, { prefix: true }), '0x00', 'zero with 1 byte')
  t.is(bigIntToHex(255n, 1, { prefix: true }), '0xff', '255 with 1 byte')
  t.is(bigIntToHex(1n, 4, { prefix: true }), '0x00000001', 'small value with large byteLength')
})

test('encoding - hexToUint8Array empty inputs', (t) => {
  t.alike(hexToBytes('0x'), new Uint8Array([]), 'empty with 0x prefix')
  t.alike(hexToBytes(''), new Uint8Array([]), 'empty string')
})

test('encoding - hexToUint8Array uppercase', (t) => {
  t.alike(hexToBytes('0xABCD'), new Uint8Array([0xab, 0xcd]), 'uppercase chars')
})

test('encoding - hexToUint8Array invalid characters', (t) => {
  t.exception(() => {
    hexToBytes('0xGGGG')
  }, 'should throw for invalid hex characters')
})

test('encoding - bigintToUint8Array zero', (t) => {
  const result = bigIntToBytes(0n, 4)
  t.alike(result, new Uint8Array([0, 0, 0, 0]), '0n produces all zeros')
})

test('encoding - bigintToUint8Array small value with length 1', (t) => {
  t.alike(bigIntToBytes(42n, 1), new Uint8Array([42]), 'single byte')
})

test('encoding - bigintToUint8Array overflow throws', (t) => {
  t.exception(() => {
    bigIntToBytes(256n, 1)
  }, 'value that does not fit in byteLength should throw')
})

test('encoding - uint8ArrayToBigInt empty array', (t) => {
  t.is(bytesToBigInt(new Uint8Array([])), 0n, 'empty array → 0n')
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
