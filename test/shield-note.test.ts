import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { randomBytes } from '@noble/hashes/utils.js'
import { bytesToHex, hexToBytes } from '@railgun-reloaded/bytes'
import { AES } from '@railgun-reloaded/cryptography'

import {
  getPublicViewingKey,
  getSharedSymmetricKey,
  initializeCryptographyLibs,
} from '../src/keys.js'
import { Note } from '../src/notes/note.js'
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

// Fixed vectors derived with @railgun-community/circomlibjs poseidon
//   npk  = poseidon([masterPublicKey, random])
//   hash = poseidon([npk, tokenHash, value])
// where each input is a big-endian field element, with
//   masterPublicKey = 0x01 repeated 32 bytes
//   random          = 0x02 repeated 16 bytes
//   tokenHash       = TEST_TOKEN_ADDRESS left-padded to 32 bytes (ERC20)
//   value           = TEST_VALUE (1000000000000000000)
const VECTOR_MASTER_PUBLIC_KEY = hexToBytes('0x' + '01'.repeat(32))
const VECTOR_RANDOM = hexToBytes('0x' + '02'.repeat(16))
const VECTOR_NPK = '0x161282156a67c78ebb2a008653f4e06d1096f77266b9b07e5cd811de4cb9e9ed'
const VECTOR_HASH = '0x21c5374b6f96417510c5ec1036970c027a4eaaad84ce43727453e7d67d1c84f8'

// ERC721 fixed vector derived with the same community implementations
// (ethereum-cryptography keccak256 and @railgun-community/circomlibjs poseidon):
//   tokenHash = keccak256(tokenType(32) || tokenAddress(32) || tokenSubID(32)) mod SNARK_PRIME
//   hash      = poseidon([npk, tokenHash, value])
// with the same masterPublicKey/random as above (npk = VECTOR_NPK), and
//   tokenType  = 1 (ERC721)
//   tokenAddress = TEST_TOKEN_ADDRESS
//   tokenSubID = 1 (32 bytes)
//   value      = 1
const VECTOR_ERC721_TOKEN_DATA = {
  tokenType: 1,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000001'),
}
const VECTOR_ERC721_TOKEN_HASH = '075b737079de804169d5e006add4da4942063ab4fce32268c469c49460e52be0'
const VECTOR_ERC721_HASH = '0x1cef1d8f80a46090ea1b751505583a5ff1e331b4d155d070632d17c5937da9c3'

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

test('shield-note - create builds note from masterPublicKey, value and tokenData', async () => {
  const shieldNote = ShieldNote.create({
    masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: VECTOR_RANDOM,
  })

  assert.ok(shieldNote instanceof ShieldNote, 'should create ShieldNote instance')
  assert.equal(shieldNote.value, TEST_VALUE, 'should carry full pre-fee value')
  assert.deepEqual(
    shieldNote.masterPublicKey,
    VECTOR_MASTER_PUBLIC_KEY,
    'should set masterPublicKey'
  )
  assert.equal(
    shieldNote.random,
    bytesToHex(VECTOR_RANDOM, { prefix: true }),
    'should store random as hex string'
  )
  assert.equal(
    shieldNote.notePublicKey,
    bytesToHex(
      Note.computeNotePublicKey(VECTOR_MASTER_PUBLIC_KEY, VECTOR_RANDOM),
      { prefix: true }
    ),
    'should derive notePublicKey from masterPublicKey and random'
  )
  assert.equal(
    shieldNote.tokenHash,
    computeTokenHash(ERC20_TOKEN_DATA),
    'should compute token hash'
  )
  assert.equal(shieldNote.shieldFee, undefined, 'should not set any fee')
})

test('shield-note - create npk matches fixed community vector', async () => {
  const npk = Note.computeNotePublicKey(VECTOR_MASTER_PUBLIC_KEY, VECTOR_RANDOM)

  assert.equal(
    bytesToHex(npk, { prefix: true }),
    VECTOR_NPK,
    'computeNotePublicKey should match community npk vector'
  )

  const shieldNote = ShieldNote.create({
    masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: VECTOR_RANDOM,
  })

  assert.equal(
    shieldNote.notePublicKey,
    VECTOR_NPK,
    'created note should carry the community npk'
  )
})

test('shield-note - create commitment hash matches fixed community vector', async () => {
  const shieldNote = ShieldNote.create({
    masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: VECTOR_RANDOM,
  })

  const hash = Note.getHash(
    hexToBytes(shieldNote.notePublicKey),
    hexToBytes(shieldNote.tokenHash),
    shieldNote.value
  )

  assert.equal(
    bytesToHex(hash, { prefix: true }),
    VECTOR_HASH,
    'commitment hash should match community shield note hash vector'
  )
})

test('shield-note - create generates 16-byte random when omitted', async () => {
  const first = ShieldNote.create({
    masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
  })
  const second = ShieldNote.create({
    masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
  })

  assert.equal(
    hexToBytes(first.random).length,
    16,
    'generated random should be 16 bytes'
  )
  assert.notEqual(
    first.random,
    second.random,
    'generated randoms should differ between notes'
  )
  assert.notEqual(
    first.notePublicKey,
    second.notePublicKey,
    'notePublicKey should differ with random'
  )
})

test('shield-note - create round-trips through serialize/deserialize', async () => {
  const shieldNote = ShieldNote.create({
    masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: VECTOR_RANDOM,
  })

  const deserialized = ShieldNote.deserialize(shieldNote.serialize())

  assert.equal(deserialized.notePublicKey, shieldNote.notePublicKey, 'should preserve notePublicKey')
  assert.equal(deserialized.value, shieldNote.value, 'should preserve value')
  assert.equal(deserialized.random, shieldNote.random, 'should preserve random')
  assert.equal(deserialized.tokenHash, shieldNote.tokenHash, 'should preserve tokenHash')
  assert.deepEqual(deserialized.masterPublicKey, shieldNote.masterPublicKey, 'should preserve masterPublicKey')
  assert.equal(deserialized.tokenData.tokenType, shieldNote.tokenData.tokenType, 'should preserve tokenType')
  assert.deepEqual(deserialized.tokenData.tokenAddress, shieldNote.tokenData.tokenAddress, 'should preserve tokenAddress')
  assert.deepEqual(deserialized.tokenData.tokenSubID, shieldNote.tokenData.tokenSubID, 'should preserve tokenSubID')
  assert.equal(deserialized.shieldFee, shieldNote.shieldFee, 'should preserve undefined shieldFee')
  assert.equal(deserialized.blockNumber, shieldNote.blockNumber, 'should preserve undefined blockNumber')
})

test('shield-note - create rejects invalid masterPublicKey length', async () => {
  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: randomBytes(31),
      value: TEST_VALUE,
      tokenData: ERC20_TOKEN_DATA,
    })
  }, /32 bytes/, 'should reject short masterPublicKey')
})

test('shield-note - create rejects invalid random length', async () => {
  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: TEST_VALUE,
      tokenData: ERC20_TOKEN_DATA,
      random: randomBytes(15),
    })
  }, /16 bytes/, 'should reject short random')
})

test('shield-note - create builds ERC721 note', async () => {
  const shieldNote = ShieldNote.create({
    masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
    value: 1n,
    tokenData: VECTOR_ERC721_TOKEN_DATA,
    random: VECTOR_RANDOM,
  })

  assert.ok(shieldNote instanceof ShieldNote, 'should create ShieldNote instance')
  assert.equal(shieldNote.value, 1n, 'should carry ERC721 value of 1')
  assert.equal(shieldNote.notePublicKey, VECTOR_NPK, 'should derive notePublicKey')
  assert.equal(
    shieldNote.tokenHash,
    computeTokenHash(VECTOR_ERC721_TOKEN_DATA),
    'should compute NFT token hash'
  )

  const deserialized = ShieldNote.deserialize(shieldNote.serialize())

  assert.equal(deserialized.notePublicKey, shieldNote.notePublicKey, 'should preserve notePublicKey')
  assert.equal(deserialized.value, shieldNote.value, 'should preserve value')
  assert.equal(deserialized.random, shieldNote.random, 'should preserve random')
  assert.equal(deserialized.tokenHash, shieldNote.tokenHash, 'should preserve tokenHash')
  assert.deepEqual(deserialized.masterPublicKey, shieldNote.masterPublicKey, 'should preserve masterPublicKey')
  assert.equal(deserialized.tokenData.tokenType, shieldNote.tokenData.tokenType, 'should preserve tokenType')
  assert.deepEqual(deserialized.tokenData.tokenAddress, shieldNote.tokenData.tokenAddress, 'should preserve tokenAddress')
  assert.deepEqual(deserialized.tokenData.tokenSubID, shieldNote.tokenData.tokenSubID, 'should preserve tokenSubID')
})

test('shield-note - create ERC721 commitment hash matches fixed community vector', async () => {
  const shieldNote = ShieldNote.create({
    masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
    value: 1n,
    tokenData: VECTOR_ERC721_TOKEN_DATA,
    random: VECTOR_RANDOM,
  })

  assert.equal(
    shieldNote.tokenHash,
    VECTOR_ERC721_TOKEN_HASH,
    'NFT token hash should match community token hash vector'
  )

  const hash = Note.getHash(
    hexToBytes(shieldNote.notePublicKey),
    hexToBytes(shieldNote.tokenHash),
    shieldNote.value
  )

  assert.equal(
    bytesToHex(hash, { prefix: true }),
    VECTOR_ERC721_HASH,
    'commitment hash should match community shield note hash vector'
  )
})

test('shield-note - create rejects ERC721 value other than 1', async () => {
  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: 2n,
      tokenData: VECTOR_ERC721_TOKEN_DATA,
    })
  }, /value of 1/, 'should reject ERC721 value above 1')
})

test('shield-note - create rejects unsupported token type', async () => {
  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: TEST_VALUE,
      tokenData: { ...ERC20_TOKEN_DATA, tokenType: 2 },
    })
  }, /Unsupported token type/, 'should reject token types other than ERC20 and ERC721')
})

test('shield-note - create rejects tokenSubID that is not exactly 32 bytes', async () => {
  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: TEST_VALUE,
      tokenData: { ...ERC20_TOKEN_DATA, tokenSubID: new Uint8Array(0) },
    })
  }, /Token sub ID must be 32 bytes/, 'should reject empty ERC20 tokenSubID')

  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: TEST_VALUE,
      tokenData: { ...ERC20_TOKEN_DATA, tokenSubID: new Uint8Array(16) },
    })
  }, /Token sub ID must be 32 bytes/, 'should reject short ERC20 tokenSubID')

  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: 1n,
      tokenData: { ...VECTOR_ERC721_TOKEN_DATA, tokenSubID: new Uint8Array(0) },
    })
  }, /Token sub ID must be 32 bytes/, 'should reject empty ERC721 tokenSubID')

  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: 1n,
      tokenData: { ...VECTOR_ERC721_TOKEN_DATA, tokenSubID: hexToBytes('0x01') },
    })
  }, /Token sub ID must be 32 bytes/, 'should reject short ERC721 tokenSubID')
})

test('shield-note - create rejects non-zero ERC20 tokenSubID', async () => {
  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: TEST_VALUE,
      tokenData: {
        ...ERC20_TOKEN_DATA,
        tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000001'),
      },
    })
  }, /tokenSubID/, 'should reject non-zero ERC20 tokenSubID')
})

test('shield-note - create rejects non-positive value', async () => {
  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: 0n,
      tokenData: ERC20_TOKEN_DATA,
    })
  }, /positive/, 'should reject zero value')

  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: -1n,
      tokenData: ERC20_TOKEN_DATA,
    })
  }, /positive/, 'should reject negative value')
})

test('shield-note - create enforces uint120 value bound', async () => {
  const maxValue = 2n ** 120n - 1n

  const shieldNote = ShieldNote.create({
    masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
    value: maxValue,
    tokenData: ERC20_TOKEN_DATA,
  })
  assert.equal(shieldNote.value, maxValue, 'should accept maximum uint120 value')

  assert.throws(() => {
    ShieldNote.create({
      masterPublicKey: VECTOR_MASTER_PUBLIC_KEY,
      value: maxValue + 1n,
      tokenData: ERC20_TOKEN_DATA,
    })
  }, /uint120/, 'should reject value exceeding uint120')
})
