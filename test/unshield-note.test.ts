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
