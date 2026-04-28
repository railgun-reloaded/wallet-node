import { randomBytes } from '@noble/hashes/utils'
import { bytesToBigInt, hexToBytes, hexlify } from '@railgun-reloaded/bytes'
import { hook, test } from 'brittle'

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
    const cleanHash = hexlify(tokenHash)
    const addressHex = cleanHash.slice(24) // last 20 bytes
    return {
      tokenType: 0,
      tokenAddress: hexToBytes(addressHex),
      tokenSubID: new Uint8Array(32),
    }
  }
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

test('transact-note - create TransactNote', async (t) => {
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

  t.ok(
    transactNote instanceof TransactNote,
    'should create TransactNote instance'
  )
  t.is(transactNote.value, TEST_VALUE, 'should set value correctly')
  t.is(transactNote.hash, hash, 'should set hash correctly')
  t.ok(transactNote.receiverAddressData, 'should set receiverAddressData')
  t.is(
    transactNote.tokenHash,
    computeTokenHash(ERC20_TOKEN_DATA),
    'should compute token hash'
  )
})

test('transact-note - serialize and deserialize', async (t) => {
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

  t.ok(serialized instanceof Uint8Array, 'should serialize to Uint8Array')

  const deserialized = await TransactNote.deserialize(
    serialized,
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    mockTokenDataGetter
  )

  t.ok(
    deserialized instanceof TransactNote,
    'should deserialize to TransactNote'
  )
  t.is(deserialized.value, TEST_VALUE, 'should preserve value')
  t.is(deserialized.random, TEST_RANDOM, 'should preserve random')
  t.is(deserialized.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
  t.is(
    deserialized.tokenData.tokenType,
    ERC20_TOKEN_DATA.tokenType,
    'should preserve tokenType'
  )
  t.alike(
    deserialized.receiverAddressData.masterPublicKey,
    receiverAddressData.masterPublicKey,
    'should preserve receiver masterPublicKey'
  )
  t.is(
    deserialized.senderAddressData,
    undefined,
    'senderAddressData should be undefined when not set'
  )
})

test('transact-note - serialize and deserialize with all optional fields', async (t) => {
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

  t.is(deserialized.value, TEST_VALUE, 'should preserve value')
  t.is(deserialized.random, TEST_RANDOM, 'should preserve random')
  t.alike(
    deserialized.receiverAddressData.masterPublicKey,
    receiverAddressData.masterPublicKey,
    'should preserve receiver masterPublicKey'
  )
  t.ok(deserialized.senderAddressData, 'should preserve senderAddressData')
  t.alike(
    deserialized.senderAddressData!.masterPublicKey,
    senderAddressData.masterPublicKey,
    'should preserve sender masterPublicKey'
  )
  t.is(deserialized.outputType, 1, 'should preserve outputType')
  t.is(
    deserialized.walletSource,
    'test-wallet',
    'should preserve walletSource'
  )
  t.is(
    deserialized.senderRandom,
    'aabbccdd11223344aabbccdd11223344',
    'should preserve senderRandom'
  )
  t.is(deserialized.memoText, 'Hello memo', 'should preserve memoText')
  t.is(deserialized.shieldFee, '1000', 'should preserve shieldFee')
  t.is(deserialized.blockNumber, 42, 'should preserve blockNumber')
})

test('transact-note - fromCommitment', async (t) => {
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

  t.ok(
    transactNote instanceof TransactNote,
    'should create TransactNote from commitment'
  )
  t.is(transactNote.value, TEST_VALUE, 'should set value')
  t.is(transactNote.random, TEST_RANDOM, 'should set random')
  t.is(transactNote.notePublicKey, TEST_NPK, 'should set npk')

  // The hash should be computed via Note.getHash
  t.is(typeof transactNote.hash, 'bigint', 'should compute hash as bigint')
  t.ok(transactNote.hash > 0n, 'hash should be positive')
})

test('transact-note - fromCommitment with senderAddressData', async (t) => {
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

  t.ok(transactNote.senderAddressData, 'should set senderAddressData')
  t.alike(
    transactNote.senderAddressData!.masterPublicKey,
    senderMPK,
    'should preserve sender masterPublicKey'
  )
})

test('TransactNote.isLegacy', (t) => {
  t.is(
    TransactNote.isLegacy({ encryptedRandom: ['abc', 'def'] }),
    true,
    'should detect legacy format with encryptedRandom'
  )

  t.is(
    TransactNote.isLegacy({ random: 'abc123' }),
    false,
    'should detect modern format without encryptedRandom'
  )

  t.is(TransactNote.isLegacy({}), false, 'should return false for empty object')
})

test('TransactNote.ciphertextToEncryptedRandomData', (t) => {
  const ciphertext = {
    iv: 'aabbccdd11223344',
    tag: 'eeff00112233aabb',
    data: ['deadbeef12345678'],
  }

  const result = TransactNote.ciphertextToEncryptedRandomData(ciphertext)

  t.is(
    result[0],
    'aabbccdd11223344eeff00112233aabb',
    'ivTag should be iv + tag concatenated'
  )
  t.is(result[1], 'deadbeef12345678', 'data should be first element')
})

test('TransactNote.ciphertextToEncryptedRandomData empty data', (t) => {
  const ciphertext = {
    iv: 'aabbccdd11223344',
    tag: 'eeff00112233aabb',
    data: [] as string[],
  }

  const result = TransactNote.ciphertextToEncryptedRandomData(ciphertext)

  t.is(
    result[0],
    'aabbccdd11223344eeff00112233aabb',
    'ivTag should be iv + tag'
  )
  t.is(result[1], '', 'data should be empty string when no data')
})

test('TransactNote.encryptedDataToCiphertext', (t) => {
  // ivTag is 32 chars, so slice(0,32) gets full ivTag as iv, slice(32) gets empty tag
  const encryptedData: [string, string] = [
    'aabbccdd11223344eeff00112233aabb',
    'deadbeef12345678',
  ]

  const result = TransactNote.encryptedDataToCiphertext(encryptedData)

  // With 32-char ivTag: iv = slice(0,32), tag = slice(32) = ''
  t.is(
    result.iv,
    'aabbccdd11223344eeff00112233aabb',
    'iv should be first 32 chars of ivTag'
  )
  t.is(result.tag, '', 'tag should be remaining chars of ivTag')
  t.is(result.data[0], 'deadbeef12345678', 'data should be preserved')
})

test('TransactNote.ciphertextToEncryptedRandomData / encryptedDataToCiphertext roundtrip', (t) => {
  const originalCiphertext = {
    iv: 'aabbccdd11223344aabbccdd11223344',
    tag: 'eeff00112233aabbeeff00112233aabb',
    data: ['deadbeef12345678deadbeef12345678'],
  }

  const encrypted = TransactNote.ciphertextToEncryptedRandomData(originalCiphertext)
  const restored = TransactNote.encryptedDataToCiphertext(encrypted)

  t.is(restored.iv, originalCiphertext.iv, 'iv should roundtrip')
  t.is(restored.tag, originalCiphertext.tag, 'tag should roundtrip')
  t.is(restored.data[0], originalCiphertext.data[0], 'data should roundtrip')
})

test('transact-note - serializeLegacy and deserializeLegacy roundtrip', async (t) => {
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
  t.ok(
    serialized instanceof Uint8Array,
    'serializeLegacy should return Uint8Array'
  )

  // Deserialize with the same viewing private key
  const deserialized = TransactNote.deserializeLegacy(
    serialized,
    viewingPrivateKey
  )

  t.ok(deserialized, 'should deserialize to TransactNote')
  t.is(deserialized!.value, TEST_VALUE, 'should preserve value')
  // deserializeLegacy returns random with 0x prefix via bytesToHex
  t.is(
    deserialized!.random,
    '0x' + TEST_RANDOM,
    'should preserve random through encryption'
  )
  t.is(deserialized!.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
  t.is(deserialized!.memoText, 'legacy memo', 'should preserve memoText')
  t.is(deserialized!.blockNumber, 100, 'should preserve blockNumber')
  t.alike(
    deserialized!.receiverAddressData.masterPublicKey,
    receiverAddressData.masterPublicKey,
    'should preserve receiver masterPublicKey through bech32 roundtrip'
  )
})

test('transact-note - deserializeLegacy returns null for wrong viewing key', async (t) => {
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

  t.is(result, null, 'should return null when decryption fails with wrong key')
})

test('transact-note - deserializeLegacy with malformed data returns null', async (t) => {
  const result = TransactNote.deserializeLegacy(new Uint8Array(100), randomBytes(32))
  t.is(result, null, 'should return null for garbage data')
})

test('transact-note - fromCommitment hash matches Note.getHash', async (t) => {
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

  t.is(transactNote.hash, expectedHash, 'fromCommitment hash should match Note.getHash')
})
