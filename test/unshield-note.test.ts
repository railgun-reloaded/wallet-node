import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { hexToBytes } from '@railgun-reloaded/bytes'
import { ActionType } from '@railgun-reloaded/scanner'

import { initializeCryptographyLibs } from '../src/keys'
import { UnshieldNote } from '../src/notes/unshield-note'

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

test('unshield-note - create UnshieldNote', async () => {
  const toAddress = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'
  const hash = 99999999999999999999n

  const unshieldNote = new UnshieldNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    toAddress,
    hash,
    allowOverride: false,
  })

  assert.ok(
    unshieldNote instanceof UnshieldNote,
    'should create UnshieldNote instance'
  )
  assert.equal(unshieldNote.value, TEST_VALUE, 'should set value correctly')
  assert.equal(unshieldNote.toAddress, toAddress, 'should set toAddress correctly')
  assert.equal(unshieldNote.hash, hash, 'should set hash correctly')
  assert.equal(unshieldNote.allowOverride, false, 'should set allowOverride correctly')
})

test('unshield-note - serialize and deserialize', async () => {
  const toAddress = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'
  const hash = 99999999999999999999n

  const unshieldNote = new UnshieldNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    toAddress,
    hash,
    allowOverride: true,
  })
  const serialized = unshieldNote.serialize()

  assert.ok(serialized instanceof Uint8Array, 'should serialize to Uint8Array')

  const deserialized = UnshieldNote.deserialize(serialized)

  assert.ok(
    deserialized instanceof UnshieldNote,
    'should deserialize to UnshieldNote'
  )
  assert.equal(deserialized.value, TEST_VALUE, 'should preserve value')
  assert.equal(deserialized.toAddress, toAddress, 'should preserve toAddress')
  assert.equal(deserialized.hash, hash, 'should preserve hash')
  assert.equal(deserialized.allowOverride, true, 'should preserve allowOverride')
  assert.equal(deserialized.random, TEST_RANDOM, 'should preserve random')
  assert.equal(deserialized.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
})

test('unshield-note - fromUnshield ERC20', async () => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToBytes('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      id: new Uint8Array(32),
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenType: 'ERC20',
      tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
    },
    amount: TEST_VALUE,
    fee: 100n,
    eventLogIndex: 0,
  }

  const unshieldNote = UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)

  assert.ok(
    unshieldNote instanceof UnshieldNote,
    'should create UnshieldNote from unshield data'
  )
  assert.equal(unshieldNote.value, TEST_VALUE, 'should set value from amount')
  assert.equal(
    unshieldNote.tokenData.tokenType,
    0,
    'should convert ERC20 string to enum'
  )
  assert.equal(
    unshieldNote.allowOverride,
    false,
    'should default allowOverride to false'
  )
  assert.ok(unshieldNote.hash > 0n, 'should compute hash')

  // Hash should include amount + fee (not just amount)
  const noFeeData = { ...unshieldData, fee: 0n }
  const noFeeNote = UnshieldNote.fromUnshield(noFeeData, TEST_RANDOM)
  assert.notEqual(unshieldNote.hash, noFeeNote.hash, 'hash should differ when fee is included')
})

test('unshield-note - fromUnshield ERC721', async () => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToBytes('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      id: new Uint8Array(32),
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenType: 'ERC721',
      tokenSubID: hexToBytes(
        '0x0000000000000000000000000000000000000000000000000000000000000001'
      ),
    },
    amount: 1n,
    fee: 0n,
    eventLogIndex: 0,
  }

  const unshieldNote = UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)

  assert.equal(
    unshieldNote.tokenData.tokenType,
    1,
    'should convert ERC721 string to enum'
  )
})

test('unshield-note - fromUnshield ERC1155', async () => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToBytes('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      id: new Uint8Array(32),
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenType: 'ERC1155',
      tokenSubID: hexToBytes(
        '0x0000000000000000000000000000000000000000000000000000000000000005'
      ),
    },
    amount: 50n,
    fee: 5n,
    eventLogIndex: 0,
  }

  const unshieldNote = UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)

  assert.equal(
    unshieldNote.tokenData.tokenType,
    2,
    'should convert ERC1155 string to enum'
  )
})

test('unshield-note - fromUnshield invalid tokenType throws', async () => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToBytes('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      id: new Uint8Array(32),
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenType: 'INVALID',
      tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
    },
    amount: TEST_VALUE,
    fee: 0n,
    eventLogIndex: 0,
  }

  assert.throws(() => {
    UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)
  }, 'should throw for invalid token type string')
})

test('unshield-note - getAmountFeeFromValue', () => {
  const { amount, fee } = UnshieldNote.getAmountFeeFromValue(10000n, 25n)
  assert.equal(fee, 25n, 'should compute fee as 0.25% of value')
  assert.equal(amount, 9975n, 'should compute amount as value minus fee')
  assert.equal(amount + fee, 10000n, 'amount + fee should equal original value')

  const zeroFee = UnshieldNote.getAmountFeeFromValue(10000n, 0n)
  assert.equal(zeroFee.fee, 0n, 'should return zero fee for zero basis points')
  assert.equal(zeroFee.amount, 10000n, 'should return full amount for zero basis points')
})

test('unshield-note - serialize and deserialize ERC721', async () => {
  const erc721TokenData = {
    tokenType: 1,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000001'),
  }

  const unshieldNote = new UnshieldNote({
    notePublicKey: TEST_NPK,
    value: 1n,
    tokenData: erc721TokenData,
    random: TEST_RANDOM,
    toAddress: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
    hash: 12345n,
    allowOverride: false,
  })

  const serialized = unshieldNote.serialize()
  const deserialized = UnshieldNote.deserialize(serialized)

  assert.equal(deserialized.tokenData.tokenType, 1, 'should preserve ERC721 tokenType')
  assert.deepEqual(deserialized.tokenData.tokenSubID, erc721TokenData.tokenSubID, 'should preserve tokenSubID')
  assert.equal(deserialized.value, 1n, 'should preserve value')
})

test('unshield-note - fromUnshield with zero amount and fee', async () => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToBytes('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      id: new Uint8Array(32),
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenType: 'ERC20',
      tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
    },
    amount: 0n,
    fee: 0n,
    eventLogIndex: 0,
  }

  const note = UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)
  assert.equal(note.value, 0n, 'should handle zero amount')
  assert.ok(note.hash >= 0n, 'should compute valid hash')
})

test('unshield-note - getAmountFeeFromValue zero value', () => {
  const { amount, fee } = UnshieldNote.getAmountFeeFromValue(0n, 25n)
  assert.equal(fee, 0n, 'fee of zero value is zero')
  assert.equal(amount, 0n, 'amount of zero value is zero')
})

test('unshield-note - getAmountFeeFromValue 100% fee', () => {
  const { amount, fee } = UnshieldNote.getAmountFeeFromValue(10000n, 10000n)
  assert.equal(fee, 10000n, 'fee should equal full value')
  assert.equal(amount, 0n, 'amount should be zero')
})

test('unshield-note - getAmountFeeFromValue over 100% fee', () => {
  const { amount, fee } = UnshieldNote.getAmountFeeFromValue(10000n, 15000n)
  assert.equal(fee, 15000n, 'fee exceeds value')
  assert.equal(amount, -5000n, 'amount goes negative')
})

test('unshield-note - getAmountFeeFromValue boundary thresholds', () => {
  const below1 = UnshieldNote.getAmountFeeFromValue(100n, 25n)
  assert.equal(below1.fee, 0n, 'fee rounds to 0 for small values')
  assert.equal(below1.amount, 100n, 'full amount preserved below threshold')

  const below2 = UnshieldNote.getAmountFeeFromValue(399n, 25n)
  assert.equal(below2.fee, 0n, 'fee still 0 at 399')
  assert.equal(below2.amount, 399n, 'full amount at 399')

  const atThreshold = UnshieldNote.getAmountFeeFromValue(400n, 25n)
  assert.equal(atThreshold.fee, 1n, 'fee becomes 1 at 400')
  assert.equal(atThreshold.amount, 399n, 'amount is 399 at threshold')

  const above = UnshieldNote.getAmountFeeFromValue(10001n, 25n)
  assert.equal(above.fee, 25n, 'fee is 25 for 10001')
  assert.equal(above.amount, 9976n, 'amount is 9976 for 10001')
})
