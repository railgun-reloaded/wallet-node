import { hook, test } from 'brittle'

import {
  hexToUint8Array,
  uint8ArrayToBigInt,
  uint8ArrayToHex,
} from '../src/encoding'
import { initializeCryptographyLibs } from '../src/keys'
import { Note } from '../src/notes/note'
import { computeTokenHash } from '../src/notes/token-utils'

const TEST_TOKEN_ADDRESS = hexToUint8Array('0x1234567890123456789012345678901234567890')
const TEST_NPK =
  '0x1234567890123456789012345678901234567890123456789012345678901234'
const TEST_RANDOM = '12345678901234567890123456789012'

const ERC20_TOKEN_DATA = {
  tokenType: 0,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: new Uint8Array(32),
}

/**
 * Brittle does not have a built-in beforeAll/beforeEach hook.
 * The hook() function creates a test that always runs even in --solo mode.
 * Placed at the top of the file, it acts as a setup step that runs before
 * all other tests, ensuring cryptography libs are initialized once.
 */
hook('setup cryptography libs', async (t) => {
  await initializeCryptographyLibs()
  t.pass('cryptography libraries initialized')
})

test('Note.assertValidRandom valid', (t) => {
  t.execution(() => {
    Note.assertValidRandom(TEST_RANDOM)
  }, 'should not throw for valid random')

  t.execution(() => {
    Note.assertValidRandom('0x' + TEST_RANDOM)
  }, 'should not throw for valid random with 0x prefix')
})

test('Note.assertValidRandom invalid length', (t) => {
  t.exception(() => {
    Note.assertValidRandom('0x12345678')
  }, 'should throw for short random')

  t.exception(() => {
    Note.assertValidRandom('0x' + '12'.repeat(100))
  }, 'should throw for long random')
})

test('Note.getHash - known vector and properties', async (t) => {
  const npkBytes = hexToUint8Array(TEST_NPK)
  const tokenHashBytes = hexToUint8Array(computeTokenHash(ERC20_TOKEN_DATA))

  const hash1 = Note.getHash(npkBytes, tokenHashBytes, BigInt('1000000000000000000'))
  t.is(
    uint8ArrayToBigInt(hash1),
    7822264150748016131168246751038092891550418438611309934403065338118898163274n,
    'should match known poseidon hash'
  )

  // Different value produces different hash
  const hash2 = Note.getHash(npkBytes, tokenHashBytes, BigInt('2000000000000000000'))
  t.not(uint8ArrayToHex(hash1), uint8ArrayToHex(hash2), 'different values should produce different hashes')

  // Different address produces different hash
  const address2 = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd'
  const hash3 = Note.getHash(hexToUint8Array(address2), tokenHashBytes, BigInt('1000000000000000000'))
  t.not(uint8ArrayToHex(hash1), uint8ArrayToHex(hash3), 'different addresses should produce different hashes')
})

test('Note.getHash - zero value', (t) => {
  const npkBytes = hexToUint8Array(TEST_NPK)
  const tokenHashBytes = hexToUint8Array(computeTokenHash(ERC20_TOKEN_DATA))

  const hash = Note.getHash(npkBytes, tokenHashBytes, 0n)
  t.ok(hash instanceof Uint8Array, 'should return Uint8Array for zero value')
  t.is(hash.length, 32, 'should be 32 bytes')
})

test('Note.getHash - determinism', (t) => {
  const npkBytes = hexToUint8Array(TEST_NPK)
  const tokenHashBytes = hexToUint8Array(computeTokenHash(ERC20_TOKEN_DATA))

  const hash1 = Note.getHash(npkBytes, tokenHashBytes, 42n)
  const hash2 = Note.getHash(npkBytes, tokenHashBytes, 42n)
  t.alike(hash1, hash2, 'same inputs should produce same hash')
})

test('Note.assertValidRandom - empty string', (t) => {
  t.exception(() => {
    Note.assertValidRandom('')
  }, 'should throw for empty string')
})

test('Note.computeNullifier - engine test vectors', (t) => {
  const vectors = [
    {
      privateKey: '08ad9143ae793cdfe94b77e4e52bc4e9f13666966cffa395e3d412ea4e20480f',
      position: 0,
      nullifier: '0x03f68801f3ee2ed10178c162b4f7f1bd466bc9718f4f98175fc04934c5caba6e',
    },
    {
      privateKey: '11299eb10424d82de500a440a2874d12f7c477afb5a3eb31dbb96295cdbcf165',
      position: 12,
      nullifier: '0x1aeadb64bf8faff93dfe26bcf0b2e2d0e9724293cc7a455f028b6accabee13b8',
    },
    {
      privateKey: '09b57736523cda7412ddfed0d2f1f4a86d8a7e26de6b0638cd092c2a2b524705',
      position: 6500,
      nullifier: '0x091961ce11c244db49a25668e57dfa2b5ffb1fe63055dd64a14af6f2be58b0e7',
    },
  ]

  for (const v of vectors) {
    const result = Note.computeNullifier(
      hexToUint8Array(v.privateKey),
      BigInt(v.position)
    )
    t.is(uint8ArrayToHex(result), v.nullifier, `nullifier for position ${v.position}`)
  }
})

test('Note.computeNullifier - determinism', (t) => {
  const key = hexToUint8Array('08ad9143ae793cdfe94b77e4e52bc4e9f13666966cffa395e3d412ea4e20480f')
  const result1 = Note.computeNullifier(key, 42n)
  const result2 = Note.computeNullifier(key, 42n)
  t.alike(result1, result2, 'same inputs should produce same nullifier')
})

test('Note.computeNullifier - different inputs produce different nullifiers', (t) => {
  const key = hexToUint8Array('08ad9143ae793cdfe94b77e4e52bc4e9f13666966cffa395e3d412ea4e20480f')
  const nullifier0 = Note.computeNullifier(key, 0n)
  const nullifier1 = Note.computeNullifier(key, 1n)
  t.not(uint8ArrayToHex(nullifier0), uint8ArrayToHex(nullifier1), 'different positions should produce different nullifiers')

  const key2 = hexToUint8Array('11299eb10424d82de500a440a2874d12f7c477afb5a3eb31dbb96295cdbcf165')
  const nullifierA = Note.computeNullifier(key, 0n)
  const nullifierB = Note.computeNullifier(key2, 0n)
  t.not(uint8ArrayToHex(nullifierA), uint8ArrayToHex(nullifierB), 'different keys should produce different nullifiers')
})
