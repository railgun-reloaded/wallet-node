import { randomBytes } from '@noble/hashes/utils'
import { AES } from '@railgun-reloaded/cryptography'
import { hook, test } from 'brittle'

import {
  hexToUint8Array,
  uint8ArrayToHex,
} from '../src/encoding'
import {
  getPublicViewingKey,
  getSharedSymmetricKey,
  initializeCryptographyLibs,
} from '../src/keys'
import { ShieldNote } from '../src/notes/shield-note'
import { computeTokenHash } from '../src/notes/token-utils'

const TEST_TOKEN_ADDRESS = '0x1234567890123456789012345678901234567890'
const TEST_TOKEN_SUB_ID_ZERO =
  '0x0000000000000000000000000000000000000000000000000000000000000000'
const TEST_NPK =
  '0x1234567890123456789012345678901234567890123456789012345678901234'
const TEST_RANDOM = '12345678901234567890123456789012'
const TEST_VALUE = 1000000000000000000n // 1 ETH

const ERC20_TOKEN_DATA = {
  tokenType: 0,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
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

test('shield-note - create ShieldNote', async (t) => {
  const masterPublicKey = 123456789012345678901234567890n
  const shieldNote = new ShieldNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    masterPublicKey
  )

  t.ok(shieldNote instanceof ShieldNote, 'should create ShieldNote instance')
  t.is(shieldNote.value, TEST_VALUE, 'should set value correctly')
  t.is(
    shieldNote.masterPublicKey,
    masterPublicKey,
    'should set masterPublicKey correctly'
  )
  t.is(shieldNote.random, TEST_RANDOM, 'should set random correctly')
  t.is(
    shieldNote.notePublicKey,
    TEST_NPK,
    'should set notePublicKey correctly'
  )
  t.is(
    shieldNote.tokenHash,
    computeTokenHash(ERC20_TOKEN_DATA),
    'should compute token hash'
  )
})

test('shield-note - serialize and deserialize', async (t) => {
  const masterPublicKey = 123456789012345678901234567890n
  const shieldNote = new ShieldNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    masterPublicKey
  )
  const serialized = shieldNote.serialize()

  t.ok(serialized instanceof Uint8Array, 'should serialize to Uint8Array')

  const deserialized = ShieldNote.deserialize(serialized)

  t.ok(deserialized instanceof ShieldNote, 'should deserialize to ShieldNote')
  t.is(deserialized.value, TEST_VALUE, 'should preserve value')
  t.is(
    deserialized.masterPublicKey,
    masterPublicKey,
    'should preserve masterPublicKey'
  )
  t.is(deserialized.random, TEST_RANDOM, 'should preserve random')
  t.is(deserialized.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
  t.is(
    deserialized.tokenData.tokenType,
    ERC20_TOKEN_DATA.tokenType,
    'should preserve tokenType'
  )
  t.is(
    deserialized.tokenData.tokenAddress,
    ERC20_TOKEN_DATA.tokenAddress,
    'should preserve tokenAddress'
  )
})

test('shield-note - fromGeneratedCommitment with GeneratedCommitment', async (t) => {
  const masterPublicKey = 999888777666555444333222111n
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC20',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  const shieldNote = ShieldNote.fromGeneratedCommitment(commitment, masterPublicKey)

  t.ok(
    shieldNote instanceof ShieldNote,
    'should create ShieldNote from GeneratedCommitment'
  )
  t.is(shieldNote.value, 5000n, 'should set value from preimage')
  t.is(
    shieldNote.masterPublicKey,
    masterPublicKey,
    'should set masterPublicKey from parameter'
  )
  t.is(
    shieldNote.tokenData.tokenType,
    0,
    'should convert ERC20 string to enum'
  )
})

test('shield-note - fromShieldCommitment with ShieldCommitment', async (t) => {
  // Shielder's key pair
  const shieldPrivateKey = randomBytes(32)
  const shieldKey = getPublicViewingKey(shieldPrivateKey)

  // Receiver's key pair
  const viewingPrivateKey = randomBytes(32)
  const receiverViewingPublicKey = getPublicViewingKey(viewingPrivateKey)

  // Build plaintext: random (16 bytes) + padding (16 bytes) = block0 (32 bytes), block1 (32 bytes)
  const noteRandom = hexToUint8Array('0x' + 'ef'.repeat(16))
  const block0 = new Uint8Array(32)
  block0.set(noteRandom, 0)
  const block1 = new Uint8Array(32)

  // Shielder encrypts: ECDH(shieldPrivateKey, receiverViewingPublicKey)
  const sharedKey = await getSharedSymmetricKey(shieldPrivateKey, receiverViewingPublicKey)
  t.ok(sharedKey, 'should derive shared key')
  const ciphertext = AES.encryptGCM([block0, block1], sharedKey!)

  // Pack into bundle format: [data0, data1, ivTag]
  const ivTag = new Uint8Array(32)
  ivTag.set(ciphertext.iv, 0)
  ivTag.set(ciphertext.tag, 16)

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 1n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC721',
        tokenSubID: hexToUint8Array(
          '0x0000000000000000000000000000000000000000000000000000000000000001'
        ),
      },
    },
    encryptedBundle: [ciphertext.data[0]!, ciphertext.data[1]!, ivTag],
    shieldKey,
  }

  const masterPublicKey = 12345n
  const shieldNote = await ShieldNote.fromShieldCommitment(commitment, viewingPrivateKey, masterPublicKey)

  t.ok(
    shieldNote instanceof ShieldNote,
    'should create ShieldNote from ShieldCommitment'
  )
  t.is(shieldNote!.value, 1n, 'should set value')
  t.is(
    shieldNote!.random,
    uint8ArrayToHex(noteRandom),
    'should decrypt random correctly'
  )
  t.is(
    shieldNote!.tokenData.tokenType,
    1,
    'should convert ERC721 string to enum'
  )
  t.is(
    shieldNote!.masterPublicKey,
    masterPublicKey,
    'should set masterPublicKey from parameter, not shieldKey'
  )
})

test('shield-note - fromShieldCommitment returns null for wrong key', async (t) => {
  // Shielder's key pair
  const shielderPrivateKey = randomBytes(32)
  const shieldKey = getPublicViewingKey(shielderPrivateKey)

  // Intended receiver's key pair
  const receiverPrivateKey = randomBytes(32)
  const receiverViewingPublicKey = getPublicViewingKey(receiverPrivateKey)

  // Shielder encrypts: ECDH(shielderPrivateKey, receiverViewingPublicKey)
  const sharedKey = await getSharedSymmetricKey(shielderPrivateKey, receiverViewingPublicKey)
  const block0 = new Uint8Array(32)
  const block1 = new Uint8Array(32)
  const ciphertext = AES.encryptGCM([block0, block1], sharedKey!)
  const ivTag = new Uint8Array(32)
  ivTag.set(ciphertext.iv, 0)
  ivTag.set(ciphertext.tag, 16)

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC20',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedBundle: [ciphertext.data[0]!, ciphertext.data[1]!, ivTag],
    shieldKey,
  }

  // Try to decrypt with a different private key
  const wrongPrivateKey = randomBytes(32)
  const result = await ShieldNote.fromShieldCommitment(commitment, wrongPrivateKey, 99999n)

  t.is(result, null, 'should return null when decryption fails')
})

test('shield-note - fromGeneratedCommitment ERC1155 token type conversion', async (t) => {
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 100n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC1155',
        tokenSubID: hexToUint8Array(
          '0x0000000000000000000000000000000000000000000000000000000000000005'
        ),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  const shieldNote = ShieldNote.fromGeneratedCommitment(commitment, 1n)

  t.is(
    shieldNote.tokenData.tokenType,
    2,
    'should convert ERC1155 string to enum'
  )
})

test('shield-note - fromGeneratedCommitment missing random throws', async (t) => {
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC20',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [] as Uint8Array[],
  }

  t.exception(() => {
    ShieldNote.fromGeneratedCommitment(commitment, 1n)
  }, 'should throw when random data is missing')
})

test('shield-note - fromGeneratedCommitment invalid tokenType throws', async (t) => {
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'INVALID',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  t.exception(() => {
    ShieldNote.fromGeneratedCommitment(commitment, 1n)
  }, 'should throw for invalid token type string')
})
