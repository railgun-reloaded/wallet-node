import { ActionType } from '@railgun-reloaded/scanner'
import { hook, test } from 'brittle'

import { hexToUint8Array } from '../src/encoding'
import { initializeCryptographyLibs } from '../src/keys'
import { UnshieldNote } from '../src/notes/unshield-note'

const TEST_TOKEN_ADDRESS = hexToUint8Array('0x1234567890123456789012345678901234567890')
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

test('unshield-note - create UnshieldNote', async (t) => {
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

  t.ok(
    unshieldNote instanceof UnshieldNote,
    'should create UnshieldNote instance'
  )
  t.is(unshieldNote.value, TEST_VALUE, 'should set value correctly')
  t.is(unshieldNote.toAddress, toAddress, 'should set toAddress correctly')
  t.is(unshieldNote.hash, hash, 'should set hash correctly')
  t.is(unshieldNote.allowOverride, false, 'should set allowOverride correctly')
})

test('unshield-note - serialize and deserialize', async (t) => {
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

  t.ok(serialized instanceof Uint8Array, 'should serialize to Uint8Array')

  const deserialized = UnshieldNote.deserialize(serialized)

  t.ok(
    deserialized instanceof UnshieldNote,
    'should deserialize to UnshieldNote'
  )
  t.is(deserialized.value, TEST_VALUE, 'should preserve value')
  t.is(deserialized.toAddress, toAddress, 'should preserve toAddress')
  t.is(deserialized.hash, hash, 'should preserve hash')
  t.is(deserialized.allowOverride, true, 'should preserve allowOverride')
  t.is(deserialized.random, TEST_RANDOM, 'should preserve random')
  t.is(deserialized.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
})

test('unshield-note - fromUnshield ERC20', async (t) => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
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

  t.ok(
    unshieldNote instanceof UnshieldNote,
    'should create UnshieldNote from unshield data'
  )
  t.is(unshieldNote.value, TEST_VALUE, 'should set value from amount')
  t.is(
    unshieldNote.tokenData.tokenType,
    0,
    'should convert ERC20 string to enum'
  )
  t.is(
    unshieldNote.allowOverride,
    false,
    'should default allowOverride to false'
  )
  t.ok(unshieldNote.hash > 0n, 'should compute hash')

  // Hash should include amount + fee (not just amount)
  const noFeeData = { ...unshieldData, fee: 0n }
  const noFeeNote = UnshieldNote.fromUnshield(noFeeData, TEST_RANDOM)
  t.not(unshieldNote.hash, noFeeNote.hash, 'hash should differ when fee is included')
})

test('unshield-note - fromUnshield ERC721', async (t) => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      id: new Uint8Array(32),
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenType: 'ERC721',
      tokenSubID: hexToUint8Array(
        '0x0000000000000000000000000000000000000000000000000000000000000001'
      ),
    },
    amount: 1n,
    fee: 0n,
    eventLogIndex: 0,
  }

  const unshieldNote = UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)

  t.is(
    unshieldNote.tokenData.tokenType,
    1,
    'should convert ERC721 string to enum'
  )
})

test('unshield-note - fromUnshield ERC1155', async (t) => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      id: new Uint8Array(32),
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenType: 'ERC1155',
      tokenSubID: hexToUint8Array(
        '0x0000000000000000000000000000000000000000000000000000000000000005'
      ),
    },
    amount: 50n,
    fee: 5n,
    eventLogIndex: 0,
  }

  const unshieldNote = UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)

  t.is(
    unshieldNote.tokenData.tokenType,
    2,
    'should convert ERC1155 string to enum'
  )
})

test('unshield-note - fromUnshield invalid tokenType throws', async (t) => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
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

  t.exception(() => {
    UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)
  }, 'should throw for invalid token type string')
})

test('unshield-note - getAmountFeeFromValue', (t) => {
  const { amount, fee } = UnshieldNote.getAmountFeeFromValue(10000n, 25n)
  t.is(fee, 25n, 'should compute fee as 0.25% of value')
  t.is(amount, 9975n, 'should compute amount as value minus fee')
  t.is(amount + fee, 10000n, 'amount + fee should equal original value')

  const zeroFee = UnshieldNote.getAmountFeeFromValue(10000n, 0n)
  t.is(zeroFee.fee, 0n, 'should return zero fee for zero basis points')
  t.is(zeroFee.amount, 10000n, 'should return full amount for zero basis points')
})

test('unshield-note - serialize and deserialize ERC721', async (t) => {
  const erc721TokenData = {
    tokenType: 1,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: hexToUint8Array('0x0000000000000000000000000000000000000000000000000000000000000001'),
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

  t.is(deserialized.tokenData.tokenType, 1, 'should preserve ERC721 tokenType')
  t.alike(deserialized.tokenData.tokenSubID, erc721TokenData.tokenSubID, 'should preserve tokenSubID')
  t.is(deserialized.value, 1n, 'should preserve value')
})

test('unshield-note - fromUnshield with zero amount and fee', async (t) => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
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
  t.is(note.value, 0n, 'should handle zero amount')
  t.ok(note.hash >= 0n, 'should compute valid hash')
})

test('unshield-note - getAmountFeeFromValue zero value', (t) => {
  const { amount, fee } = UnshieldNote.getAmountFeeFromValue(0n, 25n)
  t.is(fee, 0n, 'fee of zero value is zero')
  t.is(amount, 0n, 'amount of zero value is zero')
})

test('unshield-note - getAmountFeeFromValue 100% fee', (t) => {
  const { amount, fee } = UnshieldNote.getAmountFeeFromValue(10000n, 10000n)
  t.is(fee, 10000n, 'fee should equal full value')
  t.is(amount, 0n, 'amount should be zero')
})

test('unshield-note - getAmountFeeFromValue over 100% fee', (t) => {
  const { amount, fee } = UnshieldNote.getAmountFeeFromValue(10000n, 15000n)
  t.is(fee, 15000n, 'fee exceeds value')
  t.is(amount, -5000n, 'amount goes negative')
})

test('unshield-note - getAmountFeeFromValue boundary thresholds', (t) => {
  const below1 = UnshieldNote.getAmountFeeFromValue(100n, 25n)
  t.is(below1.fee, 0n, 'fee rounds to 0 for small values')
  t.is(below1.amount, 100n, 'full amount preserved below threshold')

  const below2 = UnshieldNote.getAmountFeeFromValue(399n, 25n)
  t.is(below2.fee, 0n, 'fee still 0 at 399')
  t.is(below2.amount, 399n, 'full amount at 399')

  const atThreshold = UnshieldNote.getAmountFeeFromValue(400n, 25n)
  t.is(atThreshold.fee, 1n, 'fee becomes 1 at 400')
  t.is(atThreshold.amount, 399n, 'amount is 399 at threshold')

  const above = UnshieldNote.getAmountFeeFromValue(10001n, 25n)
  t.is(above.fee, 25n, 'fee is 25 for 10001')
  t.is(above.amount, 9976n, 'amount is 9976 for 10001')
})
