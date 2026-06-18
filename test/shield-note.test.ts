import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { randomBytes } from '@noble/hashes/utils'
import { bytesToHex, hexToBytes } from '@railgun-reloaded/bytes'
import { AES } from '@railgun-reloaded/cryptography'

import {
  getPublicViewingKey,
  getSharedSymmetricKey,
  initializeCryptographyLibs,
} from '../src/keys.js'
import { ShieldNote } from '../src/notes/shield-note.js'
import { computeTokenHash } from '../src/notes/token-utils.js'

const TEST_TOKEN_ADDRESS = hexToBytes('0x1234567890123456789012345678901234567890')
const TEST_TOKEN_SUB_ID_ZERO = new Uint8Array(32)
const TEST_NPK =
  '0x1234567890123456789012345678901234567890123456789012345678901234'
const TEST_RANDOM = '12345678901234567890123456789012'
const TEST_VALUE = 1000000000000000000n // 1 ETH

const ERC20_TOKEN_DATA = {
  tokenType: 0,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
}

before(async () => {
  await initializeCryptographyLibs()
  assert.ok(true, 'cryptography libraries initialized')
})

test('shield-note - create ShieldNote', async () => {
  const masterPublicKey = randomBytes(32)
  const shieldNote = new ShieldNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    masterPublicKey,
  })

  assert.ok(shieldNote instanceof ShieldNote, 'should create ShieldNote instance')
  assert.equal(shieldNote.value, TEST_VALUE, 'should set value correctly')
  assert.deepEqual(
    shieldNote.masterPublicKey,
    masterPublicKey,
    'should set masterPublicKey correctly'
  )
  assert.equal(shieldNote.random, TEST_RANDOM, 'should set random correctly')
  assert.equal(
    shieldNote.notePublicKey,
    TEST_NPK,
    'should set notePublicKey correctly'
  )
  assert.equal(
    shieldNote.tokenHash,
    computeTokenHash(ERC20_TOKEN_DATA),
    'should compute token hash'
  )
})

test('shield-note - serialize and deserialize', async () => {
  const masterPublicKey = randomBytes(32)
  const shieldNote = new ShieldNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    masterPublicKey,
  })
  const serialized = shieldNote.serialize()

  assert.ok(serialized instanceof Uint8Array, 'should serialize to Uint8Array')

  const deserialized = ShieldNote.deserialize(serialized)

  assert.ok(deserialized instanceof ShieldNote, 'should deserialize to ShieldNote')
  assert.equal(deserialized.value, TEST_VALUE, 'should preserve value')
  assert.deepEqual(
    deserialized.masterPublicKey,
    masterPublicKey,
    'should preserve masterPublicKey'
  )
  assert.equal(deserialized.random, TEST_RANDOM, 'should preserve random')
  assert.equal(deserialized.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
  assert.equal(
    deserialized.tokenData.tokenType,
    ERC20_TOKEN_DATA.tokenType,
    'should preserve tokenType'
  )
  assert.deepEqual(
    deserialized.tokenData.tokenAddress,
    ERC20_TOKEN_DATA.tokenAddress,
    'should preserve tokenAddress'
  )
})

test('shield-note - fromGeneratedCommitment with GeneratedCommitment', async () => {
  const viewingPrivateKey = randomBytes(32)
  const masterPublicKey = randomBytes(32)
  const noteRandom = hexToBytes('0x' + 'ef'.repeat(16))

  // Encrypt the random with AES-GCM using viewingPrivateKey
  const ciphertext = AES.encryptGCM([noteRandom], viewingPrivateKey)
  const ivTag = new Uint8Array(32)
  ivTag.set(ciphertext.iv, 0)
  ivTag.set(ciphertext.tag, 16)

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToBytes('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: TEST_TOKEN_ADDRESS,
        tokenType: 'ERC20',
        tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
      },
    },
    encryptedRandom: [ivTag, ciphertext.data[0]!],
  }

  const shieldNote = ShieldNote.fromGeneratedCommitment(commitment, viewingPrivateKey, masterPublicKey)

  assert.ok(shieldNote, 'should create ShieldNote from GeneratedCommitment')
  assert.equal(shieldNote!.value, 5000n, 'should set value from preimage')
  assert.deepEqual(
    shieldNote!.masterPublicKey,
    masterPublicKey,
    'should set masterPublicKey from parameter'
  )
  assert.equal(
    shieldNote!.tokenData.tokenType,
    0,
    'should convert ERC20 string to enum'
  )
  assert.equal(
    shieldNote!.random,
    bytesToHex(noteRandom, { prefix: true }),
    'should decrypt random correctly'
  )
})

test('shield-note - fromShieldCommitment with ShieldCommitment', async () => {
  // Shielder's key pair
  const shieldPrivateKey = randomBytes(32)
  const shieldKey = getPublicViewingKey(shieldPrivateKey)

  // Receiver's key pair
  const viewingPrivateKey = randomBytes(32)
  const receiverViewingPublicKey = getPublicViewingKey(viewingPrivateKey)

  // Build plaintext: random (16 bytes)
  const noteRandom = hexToBytes('0x' + 'ef'.repeat(16))

  // Shielder encrypts: ECDH(shieldPrivateKey, receiverViewingPublicKey)
  const sharedKey = await getSharedSymmetricKey(shieldPrivateKey, receiverViewingPublicKey)
  assert.ok(sharedKey, 'should derive shared key')
  const ciphertext = AES.encryptGCM([noteRandom], sharedKey!)

  // On-chain bundle format:
  // [0] = iv (16 bytes) + tag (16 bytes)
  // [1] = encrypted random data (16 bytes) + padding (16 bytes)
  // [2] = encrypted receiver data (not used for random decryption)
  const ivTag = new Uint8Array(32)
  ivTag.set(ciphertext.iv, 0)
  ivTag.set(ciphertext.tag, 16)

  const dataBlock = new Uint8Array(32)
  dataBlock.set(ciphertext.data[0]!, 0)

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToBytes('0x' + 'ab'.repeat(32)),
      value: 1n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: TEST_TOKEN_ADDRESS,
        tokenType: 'ERC721',
        tokenSubID: hexToBytes(
          '0x0000000000000000000000000000000000000000000000000000000000000001'
        ),
      },
    },
    encryptedBundle: [ivTag, dataBlock, new Uint8Array(32)],
    shieldKey,
  }

  const masterPublicKey = randomBytes(32)
  const shieldNote = await ShieldNote.fromShieldCommitment(commitment, viewingPrivateKey, masterPublicKey)

  assert.ok(
    shieldNote instanceof ShieldNote,
    'should create ShieldNote from ShieldCommitment'
  )
  assert.equal(shieldNote!.value, 1n, 'should set value')
  assert.equal(
    shieldNote!.random,
    bytesToHex(noteRandom, { prefix: true }),
    'should decrypt random correctly'
  )
  assert.equal(
    shieldNote!.tokenData.tokenType,
    1,
    'should convert ERC721 string to enum'
  )
  assert.deepEqual(
    shieldNote!.masterPublicKey,
    masterPublicKey,
    'should set masterPublicKey from parameter, not shieldKey'
  )
})

test('shield-note - fromShieldCommitment returns null for wrong key', async () => {
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
      npk: hexToBytes('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: TEST_TOKEN_ADDRESS,
        tokenType: 'ERC20',
        tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
      },
    },
    encryptedBundle: [ciphertext.data[0]!, ciphertext.data[1]!, ivTag],
    shieldKey,
  }

  // Try to decrypt with a different private key
  const wrongPrivateKey = randomBytes(32)
  const result = await ShieldNote.fromShieldCommitment(commitment, wrongPrivateKey, new Uint8Array(32))

  assert.equal(result, null, 'should return null when decryption fails')
})

test('shield-note - fromGeneratedCommitment ERC1155 token type conversion', async () => {
  const viewingPrivateKey = randomBytes(32)
  const noteRandom = randomBytes(16)

  const ciphertext = AES.encryptGCM([noteRandom], viewingPrivateKey)
  const ivTag = new Uint8Array(32)
  ivTag.set(ciphertext.iv, 0)
  ivTag.set(ciphertext.tag, 16)

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToBytes('0x' + 'ab'.repeat(32)),
      value: 100n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: TEST_TOKEN_ADDRESS,
        tokenType: 'ERC1155',
        tokenSubID: hexToBytes(
          '0x0000000000000000000000000000000000000000000000000000000000000005'
        ),
      },
    },
    encryptedRandom: [ivTag, ciphertext.data[0]!],
  }

  const shieldNote = ShieldNote.fromGeneratedCommitment(commitment, viewingPrivateKey, new Uint8Array(32))

  assert.ok(shieldNote, 'should create ShieldNote')
  assert.equal(
    shieldNote!.tokenData.tokenType,
    2,
    'should convert ERC1155 string to enum'
  )
})

test('shield-note - fromGeneratedCommitment missing random throws', async () => {
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToBytes('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: TEST_TOKEN_ADDRESS,
        tokenType: 'ERC20',
        tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
      },
    },
    encryptedRandom: [] as Uint8Array[],
  }

  assert.throws(() => {
    ShieldNote.fromGeneratedCommitment(commitment, new Uint8Array(32), new Uint8Array(32))
  }, 'should throw when random data is missing')
})

test('shield-note - fromGeneratedCommitment returns null for wrong viewing key', async () => {
  const correctKey = randomBytes(32)
  const wrongKey = randomBytes(32)
  const noteRandom = randomBytes(16)

  const ciphertext = AES.encryptGCM([noteRandom], correctKey)
  const ivTag = new Uint8Array(32)
  ivTag.set(ciphertext.iv, 0)
  ivTag.set(ciphertext.tag, 16)

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToBytes('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: TEST_TOKEN_ADDRESS,
        tokenType: 'ERC20',
        tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
      },
    },
    encryptedRandom: [ivTag, ciphertext.data[0]!],
  }

  const result = ShieldNote.fromGeneratedCommitment(commitment, wrongKey, new Uint8Array(32))
  assert.equal(result, null, 'should return null when decryption fails')
})

test('shield-note - fromGeneratedCommitment returns null for invalid tokenType', async () => {
  const viewingPrivateKey = randomBytes(32)
  const noteRandom = randomBytes(16)

  const ciphertext = AES.encryptGCM([noteRandom], viewingPrivateKey)
  const ivTag = new Uint8Array(32)
  ivTag.set(ciphertext.iv, 0)
  ivTag.set(ciphertext.tag, 16)

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToBytes('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: TEST_TOKEN_ADDRESS,
        tokenType: 'INVALID',
        tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
      },
    },
    encryptedRandom: [ivTag, ciphertext.data[0]!],
  }

  const result = ShieldNote.fromGeneratedCommitment(commitment, viewingPrivateKey, new Uint8Array(32))
  assert.equal(result, null, 'should return null for invalid token type')
})

test('shield-note - serialize and deserialize ERC721', async () => {
  const masterPublicKey = randomBytes(32)
  const erc721TokenData = {
    tokenType: 1,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000001'),
  }

  const shieldNote = new ShieldNote({
    notePublicKey: TEST_NPK,
    value: 1n,
    tokenData: erc721TokenData,
    random: TEST_RANDOM,
    masterPublicKey,
  })
  const serialized = shieldNote.serialize()
  const deserialized = ShieldNote.deserialize(serialized)

  assert.equal(deserialized.tokenData.tokenType, 1, 'should preserve ERC721 tokenType')
  assert.deepEqual(deserialized.tokenData.tokenSubID, erc721TokenData.tokenSubID, 'should preserve tokenSubID')
  assert.equal(deserialized.value, 1n, 'should preserve value')
})

test('shield-note - serialize and deserialize with optional fields', async () => {
  const masterPublicKey = randomBytes(32)
  const shieldNote = new ShieldNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    masterPublicKey,
    shieldFee: 500n,
    blockNumber: 12345678,
  })

  const serialized = shieldNote.serialize()
  const deserialized = ShieldNote.deserialize(serialized)

  assert.equal(deserialized.shieldFee, 500n, 'should preserve shieldFee')
  assert.equal(deserialized.blockNumber, 12345678, 'should preserve blockNumber')
})

test('shield-note - fromGeneratedCommitment lowercase tokenType', async () => {
  const viewingPrivateKey = randomBytes(32)
  const noteRandom = randomBytes(16)

  const ciphertext = AES.encryptGCM([noteRandom], viewingPrivateKey)
  const ivTag = new Uint8Array(32)
  ivTag.set(ciphertext.iv, 0)
  ivTag.set(ciphertext.tag, 16)

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToBytes('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: TEST_TOKEN_ADDRESS,
        tokenType: 'erc20',
        tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
      },
    },
    encryptedRandom: [ivTag, ciphertext.data[0]!],
  }

  const result = ShieldNote.fromGeneratedCommitment(commitment, viewingPrivateKey, randomBytes(32))
  assert.ok(result, 'should handle lowercase tokenType')
  assert.equal(result!.tokenData.tokenType, 0, 'should convert to enum')
})

test('shield-note - fromShieldCommitment throws for short encryptedBundle', async () => {
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToBytes('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: TEST_TOKEN_ADDRESS,
        tokenType: 'ERC20',
        tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
      },
    },
    encryptedBundle: [new Uint8Array(32)],
    shieldKey: randomBytes(32),
  }

  await assert.rejects(async () => {
    await ShieldNote.fromShieldCommitment(commitment, randomBytes(32), randomBytes(32))
  }, 'should throw for encryptedBundle with < 3 elements')
})
