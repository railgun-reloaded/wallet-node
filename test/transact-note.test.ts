import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { randomBytes } from '@noble/hashes/utils'
import { bytesToBigInt, hexToBytes, stripHexPrefix } from '@railgun-reloaded/bytes'

import { initializeCryptographyLibs } from '../src/keys'
import type { TokenDataGetter } from '../src/notes/definitions'
import { ChainType, TXIDVersion } from '../src/notes/definitions'
import { Note } from '../src/notes/note'
import { computeTokenHash } from '../src/notes/token-utils'
import { TransactNote } from '../src/notes/transact-note'

const TEST_CHAIN = { type: ChainType.EVM, id: 1 }

const TEST_TOKEN_ADDRESS = hexToBytes('0x1234567890123456789012345678901234567890')
const TEST_NPK =
  '0x1234567890123456789012345678901234567890123456789012345678901234'
const TEST_RANDOM = '12345678901234567890123456789012'
const TEST_VALUE = 1000000000000000000n // 1 ETH

const ERC20_TOKEN_DATA = {
  tokenType: 0,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: new Uint8Array(32),
}

/**
 * Mock TokenDataGetter for tests.
 * Assumes all token hashes are ERC20 (address zero-padded to 32 bytes).
 */
const mockTokenDataGetter: TokenDataGetter = {
  /**
   * Resolves a token hash to ERC20 token data.
   * @param _txidVersion - Unused TXID version
   * @param _chain - Unused chain
   * @param tokenHash - The token hash to resolve
   * @returns ERC20 token data with address extracted from hash
   */
  async getTokenDataFromHash (_txidVersion, _chain, tokenHash) {
    const cleanHash = stripHexPrefix(tokenHash).toLowerCase()
    const addressHex = cleanHash.slice(24) // last 20 bytes
    return {
      tokenType: 0,
      tokenAddress: hexToBytes(addressHex),
      tokenSubID: new Uint8Array(32),
    }
  }
}

before(async () => {
  await initializeCryptographyLibs()
  assert.ok(true, 'cryptography libraries initialized')
})

test('transact-note - create TransactNote', async () => {
  const hash = 99999999999999999999n
  const receiverAddressData = {
    masterPublicKey: randomBytes(32),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = new TransactNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    hash,
    receiverAddressData,
  })

  assert.ok(
    transactNote instanceof TransactNote,
    'should create TransactNote instance'
  )
  assert.equal(transactNote.value, TEST_VALUE, 'should set value correctly')
  assert.equal(transactNote.hash, hash, 'should set hash correctly')
  assert.ok(transactNote.receiverAddressData, 'should set receiverAddressData')
  assert.equal(
    transactNote.tokenHash,
    computeTokenHash(ERC20_TOKEN_DATA),
    'should compute token hash'
  )
})

test('transact-note - serialize and deserialize', async () => {
  const hash = 99999999999999999999n
  const receiverAddressData = {
    masterPublicKey: randomBytes(32),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = new TransactNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    hash,
    receiverAddressData,
  })
  const serialized = transactNote.serialize()

  assert.ok(serialized instanceof Uint8Array, 'should serialize to Uint8Array')

  const deserialized = await TransactNote.deserialize(
    serialized,
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    mockTokenDataGetter
  )

  assert.ok(
    deserialized instanceof TransactNote,
    'should deserialize to TransactNote'
  )
  assert.equal(deserialized.value, TEST_VALUE, 'should preserve value')
  assert.equal(deserialized.random, TEST_RANDOM, 'should preserve random')
  assert.equal(deserialized.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
  assert.equal(
    deserialized.tokenData.tokenType,
    ERC20_TOKEN_DATA.tokenType,
    'should preserve tokenType'
  )
  assert.deepEqual(
    deserialized.receiverAddressData.masterPublicKey,
    receiverAddressData.masterPublicKey,
    'should preserve receiver masterPublicKey'
  )
  assert.equal(
    deserialized.senderAddressData,
    undefined,
    'senderAddressData should be undefined when not set'
  )
})

test('transact-note - serialize and deserialize with all optional fields', async () => {
  const hash = 99999999999999999999n
  const receiverAddressData = {
    masterPublicKey: new Uint8Array(32).fill(0x11),
    viewingPublicKey: new Uint8Array(32).fill(0xaa),
  }
  const senderAddressData = {
    masterPublicKey: new Uint8Array(32).fill(0x22),
    viewingPublicKey: new Uint8Array(32).fill(0xbb),
  }

  const transactNote = new TransactNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    hash,
    receiverAddressData,
    senderAddressData,
    outputType: 1,
    walletSource: 'test-wallet',
    senderRandom: 'aabbccdd11223344aabbccdd11223344',
    memoText: 'Hello memo',
    shieldFee: '1000',
    blockNumber: 42,
  })

  const serialized = transactNote.serialize()
  const deserialized = await TransactNote.deserialize(
    serialized,
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    mockTokenDataGetter
  )

  assert.equal(deserialized.value, TEST_VALUE, 'should preserve value')
  assert.equal(deserialized.random, TEST_RANDOM, 'should preserve random')
  assert.deepEqual(
    deserialized.receiverAddressData.masterPublicKey,
    receiverAddressData.masterPublicKey,
    'should preserve receiver masterPublicKey'
  )
  assert.ok(deserialized.senderAddressData, 'should preserve senderAddressData')
  assert.deepEqual(
    deserialized.senderAddressData!.masterPublicKey,
    senderAddressData.masterPublicKey,
    'should preserve sender masterPublicKey'
  )
  assert.equal(deserialized.outputType, 1, 'should preserve outputType')
  assert.equal(
    deserialized.walletSource,
    'test-wallet',
    'should preserve walletSource'
  )
  assert.equal(
    deserialized.senderRandom,
    'aabbccdd11223344aabbccdd11223344',
    'should preserve senderRandom'
  )
  assert.equal(deserialized.memoText, 'Hello memo', 'should preserve memoText')
  assert.equal(deserialized.shieldFee, '1000', 'should preserve shieldFee')
  assert.equal(deserialized.blockNumber, 42, 'should preserve blockNumber')
})

test('transact-note - fromCommitment', async () => {
  const random = TEST_RANDOM
  const npk = TEST_NPK
  const value = TEST_VALUE
  const receiverAddressData = {
    masterPublicKey: randomBytes(32),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = TransactNote.fromCommitment(
    random,
    npk,
    value,
    ERC20_TOKEN_DATA,
    receiverAddressData
  )

  assert.ok(
    transactNote instanceof TransactNote,
    'should create TransactNote from commitment'
  )
  assert.equal(transactNote.value, TEST_VALUE, 'should set value')
  assert.equal(transactNote.random, TEST_RANDOM, 'should set random')
  assert.equal(transactNote.notePublicKey, TEST_NPK, 'should set npk')

  // The hash should be computed via Note.getHash
  assert.equal(typeof transactNote.hash, 'bigint', 'should compute hash as bigint')
  assert.ok(transactNote.hash > 0n, 'hash should be positive')
})

test('transact-note - fromCommitment with senderAddressData', async () => {
  const senderMPK = new Uint8Array(32).fill(0x22)
  const receiverAddressData = {
    masterPublicKey: new Uint8Array(32).fill(0x11),
    viewingPublicKey: new Uint8Array(32),
  }
  const senderAddressData = {
    masterPublicKey: senderMPK,
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = TransactNote.fromCommitment(
    TEST_RANDOM,
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    receiverAddressData,
    senderAddressData
  )

  assert.ok(transactNote.senderAddressData, 'should set senderAddressData')
  assert.deepEqual(
    transactNote.senderAddressData!.masterPublicKey,
    senderMPK,
    'should preserve sender masterPublicKey'
  )
})

test('TransactNote.isLegacy', () => {
  assert.equal(
    TransactNote.isLegacy({ encryptedRandom: ['abc', 'def'] }),
    true,
    'should detect legacy format with encryptedRandom'
  )

  assert.equal(
    TransactNote.isLegacy({ random: 'abc123' }),
    false,
    'should detect modern format without encryptedRandom'
  )

  assert.equal(TransactNote.isLegacy({}), false, 'should return false for empty object')
})

test('TransactNote.ciphertextToEncryptedRandomData', () => {
  const ciphertext = {
    iv: 'aabbccdd11223344',
    tag: 'eeff00112233aabb',
    data: ['deadbeef12345678'],
  }

  const result = TransactNote.ciphertextToEncryptedRandomData(ciphertext)

  assert.equal(
    result[0],
    'aabbccdd11223344eeff00112233aabb',
    'ivTag should be iv + tag concatenated'
  )
  assert.equal(result[1], 'deadbeef12345678', 'data should be first element')
})

test('TransactNote.ciphertextToEncryptedRandomData empty data', () => {
  const ciphertext = {
    iv: 'aabbccdd11223344',
    tag: 'eeff00112233aabb',
    data: [] as string[],
  }

  const result = TransactNote.ciphertextToEncryptedRandomData(ciphertext)

  assert.equal(
    result[0],
    'aabbccdd11223344eeff00112233aabb',
    'ivTag should be iv + tag'
  )
  assert.equal(result[1], '', 'data should be empty string when no data')
})

test('TransactNote.encryptedDataToCiphertext', () => {
  // ivTag is 32 chars, so slice(0,32) gets full ivTag as iv, slice(32) gets empty tag
  const encryptedData: [string, string] = [
    'aabbccdd11223344eeff00112233aabb',
    'deadbeef12345678',
  ]

  const result = TransactNote.encryptedDataToCiphertext(encryptedData)

  // With 32-char ivTag: iv = slice(0,32), tag = slice(32) = ''
  assert.equal(
    result.iv,
    'aabbccdd11223344eeff00112233aabb',
    'iv should be first 32 chars of ivTag'
  )
  assert.equal(result.tag, '', 'tag should be remaining chars of ivTag')
  assert.equal(result.data[0], 'deadbeef12345678', 'data should be preserved')
})

test('TransactNote.ciphertextToEncryptedRandomData / encryptedDataToCiphertext roundtrip', () => {
  const originalCiphertext = {
    iv: 'aabbccdd11223344aabbccdd11223344',
    tag: 'eeff00112233aabbeeff00112233aabb',
    data: ['deadbeef12345678deadbeef12345678'],
  }

  const encrypted = TransactNote.ciphertextToEncryptedRandomData(originalCiphertext)
  const restored = TransactNote.encryptedDataToCiphertext(encrypted)

  assert.equal(restored.iv, originalCiphertext.iv, 'iv should roundtrip')
  assert.equal(restored.tag, originalCiphertext.tag, 'tag should roundtrip')
  assert.equal(restored.data[0], originalCiphertext.data[0], 'data should roundtrip')
})

test('transact-note - serializeLegacy and deserializeLegacy roundtrip', async () => {
  // Legacy format uses viewing private key directly as AES key (no ECDH)
  const viewingPrivateKey = randomBytes(32)

  const hash = 99999999999999999999n
  const receiverAddressData = {
    masterPublicKey: randomBytes(32),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = new TransactNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    hash,
    receiverAddressData,
    memoText: 'legacy memo',
    blockNumber: 100,
  })

  // Serialize with viewing private key directly
  const serialized = transactNote.serializeLegacy(viewingPrivateKey)
  assert.ok(
    serialized instanceof Uint8Array,
    'serializeLegacy should return Uint8Array'
  )

  // Deserialize with the same viewing private key
  const deserialized = TransactNote.deserializeLegacy(
    serialized,
    viewingPrivateKey
  )

  assert.ok(deserialized, 'should deserialize to TransactNote')
  assert.equal(deserialized!.value, TEST_VALUE, 'should preserve value')
  // deserializeLegacy returns random with 0x prefix via bytesToHex
  assert.equal(
    deserialized!.random,
    '0x' + TEST_RANDOM,
    'should preserve random through encryption'
  )
  assert.equal(deserialized!.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
  assert.equal(deserialized!.memoText, 'legacy memo', 'should preserve memoText')
  assert.equal(deserialized!.blockNumber, 100, 'should preserve blockNumber')
  assert.deepEqual(
    deserialized!.receiverAddressData.masterPublicKey,
    receiverAddressData.masterPublicKey,
    'should preserve receiver masterPublicKey through bech32 roundtrip'
  )
})

test('transact-note - deserializeLegacy returns null for wrong viewing key', async () => {
  const correctKey = randomBytes(32)
  const wrongKey = randomBytes(32)

  const receiverAddressData = {
    masterPublicKey: randomBytes(32),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = new TransactNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    hash: 99999999999999999999n,
    receiverAddressData,
  })

  const serialized = transactNote.serializeLegacy(correctKey)
  const result = TransactNote.deserializeLegacy(serialized, wrongKey)

  assert.equal(result, null, 'should return null when decryption fails with wrong key')
})

test('transact-note - deserializeLegacy with malformed data returns null', async () => {
  const result = TransactNote.deserializeLegacy(new Uint8Array(100), randomBytes(32))
  assert.equal(result, null, 'should return null for garbage data')
})

test('transact-note - fromCommitment hash matches Note.getHash', async () => {
  const receiverAddressData = {
    masterPublicKey: randomBytes(32),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = TransactNote.fromCommitment(
    TEST_RANDOM,
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    receiverAddressData
  )

  const npkBytes = hexToBytes(TEST_NPK)
  const tokenHashBytes = hexToBytes(computeTokenHash(ERC20_TOKEN_DATA))
  const expectedHash = bytesToBigInt(Note.getHash(npkBytes, tokenHashBytes, TEST_VALUE))

  assert.equal(transactNote.hash, expectedHash, 'fromCommitment hash should match Note.getHash')
})
