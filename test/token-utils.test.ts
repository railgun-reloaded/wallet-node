import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { bytesToBigInt, hexToBytes } from '@railgun-reloaded/bytes'

import { initializeCryptographyLibs } from '../src/keys.js'
import {
  assertValidNoteToken,
  computeTokenHash,
  computeTokenHashERC20,
  computeTokenHashNFT,
  deserializeTokenData,
  getReadableTokenAddress,
  getTokenDataERC20,
  serializeTokenData,
} from '../src/notes/token-utils.js'

const TEST_TOKEN_ADDRESS = hexToBytes('0x1234567890123456789012345678901234567890')
const TEST_VALUE = 1000000000000000000n // 1 ETH

const ERC20_TOKEN_DATA = {
  tokenType: 0,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: new Uint8Array(32),
}

const ERC721_TOKEN_DATA = {
  tokenType: 1,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000001'),
}

const ERC1155_TOKEN_DATA = {
  tokenType: 2,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000005'),
}

before(async () => {
  await initializeCryptographyLibs()
  assert.ok(true, 'cryptography libraries initialized')
})

test('token-utils - computeTokenHash known vectors', () => {
  assert.equal(
    computeTokenHash(ERC20_TOKEN_DATA),
    '0000000000000000000000001234567890123456789012345678901234567890',
    'ERC20 hash should be zero-padded address'
  )
  assert.equal(
    computeTokenHash(ERC721_TOKEN_DATA),
    '075b737079de804169d5e006add4da4942063ab4fce32268c469c49460e52be0',
    'ERC721 hash should match known vector'
  )
  assert.equal(
    computeTokenHash(ERC1155_TOKEN_DATA),
    '03b8bfbf662863b2da6422aa0d1f021639ca87ae10d85bdf48069c2e98c72d6a',
    'ERC1155 hash should match known vector'
  )
})

test('token-utils - computeTokenHash invalid token type', () => {
  const tokenData = {
    tokenType: 99,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: new Uint8Array(32),
  }

  assert.throws(() => {
    computeTokenHash(tokenData)
  }, 'should throw error for invalid token type')
})

test('token-utils - computeTokenHashERC20 direct', () => {
  assert.equal(
    computeTokenHashERC20(TEST_TOKEN_ADDRESS),
    '0000000000000000000000001234567890123456789012345678901234567890',
    'should zero-pad address to 32 bytes'
  )
})

test('token-utils - computeTokenHashNFT different subIDs', () => {
  const hash1 = computeTokenHashNFT(ERC721_TOKEN_DATA)
  const hash2 = computeTokenHashNFT({
    ...ERC721_TOKEN_DATA,
    tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000002'),
  })

  assert.notEqual(hash1, hash2, 'different subIDs should produce different hashes')
})

test('token-utils - getReadableTokenAddress ERC20 known vector', () => {
  const readable = getReadableTokenAddress(ERC20_TOKEN_DATA)

  assert.equal(
    readable,
    '0x1234567890123456789012345678901234567890',
    'ERC20 readable should be trimmed 20-byte address'
  )
})

test('token-utils - getReadableTokenAddress NFT known vector', () => {
  const readable = getReadableTokenAddress(ERC721_TOKEN_DATA)

  assert.equal(
    readable,
    '0x1234567890123456789012345678901234567890 (0x0000000000000000000000000000000000000000000000000000000000000001)',
    'NFT readable should include address and subID'
  )
})

test('token-utils - getReadableTokenAddress invalid type', () => {
  assert.throws(() => {
    getReadableTokenAddress({
      tokenType: 99 as any,
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenSubID: new Uint8Array(32),
    })
  }, 'should throw for invalid token type')
})

test('token-utils - serializeTokenData roundtrip', () => {
  for (const tokenData of [ERC20_TOKEN_DATA, ERC721_TOKEN_DATA, ERC1155_TOKEN_DATA]) {
    const serialized = serializeTokenData(tokenData.tokenAddress, tokenData.tokenType, tokenData.tokenSubID)
    const deserialized = deserializeTokenData(serialized)

    assert.equal(deserialized.tokenType, tokenData.tokenType, `should preserve tokenType for type ${tokenData.tokenType}`)
    assert.deepEqual(deserialized.tokenAddress, tokenData.tokenAddress, `should preserve tokenAddress for type ${tokenData.tokenType}`)
    assert.deepEqual(deserialized.tokenSubID, tokenData.tokenSubID, `should preserve tokenSubID for type ${tokenData.tokenType}`)
  }
})

test('token-utils - assertValidNoteToken ERC20 valid', () => {
  assert.doesNotThrow(() => {
    assertValidNoteToken(ERC20_TOKEN_DATA, TEST_VALUE)
  }, 'should not throw for valid ERC20')
})

test('token-utils - assertValidNoteToken rejects 32-byte address', () => {
  const tokenData = {
    tokenType: 0,
    tokenAddress: hexToBytes('0x' + '12'.repeat(32)),
    tokenSubID: new Uint8Array(32),
  }
  assert.throws(() => {
    assertValidNoteToken(tokenData, TEST_VALUE)
  }, 'should throw for 32-byte address')
})

test('token-utils - assertValidNoteToken ERC20 invalid address length', () => {
  const tokenData = {
    tokenType: 0,
    tokenAddress: hexToBytes('0x1234'),
    tokenSubID: new Uint8Array(32),
  }
  assert.throws(() => {
    assertValidNoteToken(tokenData, TEST_VALUE)
  }, 'should throw for invalid ERC20 address length')
})

test('token-utils - assertValidNoteToken ERC20 non-zero subID', () => {
  const nonZeroSubID = new Uint8Array(32)
  nonZeroSubID[31] = 1
  const tokenData = {
    tokenType: 0,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: nonZeroSubID,
  }
  assert.throws(() => {
    assertValidNoteToken(tokenData, TEST_VALUE)
  }, 'should throw for ERC20 with non-zero subID')
})

test('token-utils - assertValidNoteToken ERC721 valid', () => {
  const tokenData = {
    tokenType: 1,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000001'),
  }
  assert.doesNotThrow(() => {
    assertValidNoteToken(tokenData, 1n)
  }, 'should not throw for valid ERC721')
})

test('token-utils - assertValidNoteToken ERC721 missing subID', () => {
  const tokenData = {
    tokenType: 1,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: new Uint8Array(0),
  }
  assert.throws(() => {
    assertValidNoteToken(tokenData, 1n)
  }, 'should throw for ERC721 without subID')
})

test('token-utils - assertValidNoteToken ERC721 wrong value', () => {
  const tokenData = {
    tokenType: 1,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000001'),
  }
  assert.throws(() => {
    assertValidNoteToken(tokenData, 2n)
  }, 'should throw for ERC721 with value != 1')
})

test('token-utils - assertValidNoteToken ERC721 invalid address length', () => {
  const tokenData = {
    tokenType: 1,
    tokenAddress: hexToBytes('0x' + '12'.repeat(32)),
    tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000001'),
  }
  assert.throws(() => {
    assertValidNoteToken(tokenData, 1n)
  }, 'should throw for ERC721 with non-20-byte address')
})

test('token-utils - assertValidNoteToken ERC1155 valid', () => {
  const tokenData = {
    tokenType: 2,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000005'),
  }
  assert.doesNotThrow(() => {
    assertValidNoteToken(tokenData, 100n)
  }, 'should not throw for valid ERC1155')
})

test('token-utils - assertValidNoteToken ERC1155 missing subID', () => {
  const tokenData = {
    tokenType: 2,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: new Uint8Array(0),
  }
  assert.throws(() => {
    assertValidNoteToken(tokenData, 100n)
  }, 'should throw for ERC1155 without subID')
})

test('token-utils - assertValidNoteToken invalid token type', () => {
  const tokenData = {
    tokenType: 99,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: new Uint8Array(32),
  }
  assert.throws(() => {
    assertValidNoteToken(tokenData, TEST_VALUE)
  }, 'should throw for invalid token type')
})

test('token-utils - computeTokenHash NFT properties', () => {
  const erc721Hash = computeTokenHash(ERC721_TOKEN_DATA)

  // Hash should be less than SNARK_PRIME (result of mod operation)
  const SNARK_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
  const hashBigInt = bytesToBigInt(hexToBytes(erc721Hash))
  assert.ok(hashBigInt < SNARK_PRIME, 'NFT hash should be less than SNARK_PRIME')

  // computeTokenHashNFT directly should match computeTokenHash
  const directHash = computeTokenHashNFT(ERC721_TOKEN_DATA)
  assert.equal(directHash, erc721Hash, 'computeTokenHashNFT should match computeTokenHash for ERC721')
})

test('token-utils - deserializeTokenData null input', () => {
  assert.throws(() => {
    deserializeTokenData(null)
  }, 'should throw for null')
})

test('token-utils - deserializeTokenData undefined input', () => {
  assert.throws(() => {
    deserializeTokenData(undefined)
  }, 'should throw for undefined')
})

test('token-utils - deserializeTokenData missing fields', () => {
  assert.throws(() => {
    deserializeTokenData({ tokenType: 0, tokenSubID: new Uint8Array(32) })
  }, 'should throw for missing tokenAddress')
})

test('token-utils - deserializeTokenData invalid tokenType', () => {
  assert.throws(() => {
    deserializeTokenData({ tokenAddress: TEST_TOKEN_ADDRESS, tokenType: -1, tokenSubID: new Uint8Array(32) })
  }, 'should throw for negative tokenType')

  assert.throws(() => {
    deserializeTokenData({ tokenAddress: TEST_TOKEN_ADDRESS, tokenType: 3, tokenSubID: new Uint8Array(32) })
  }, 'should throw for tokenType 3')
})

test('token-utils - deserializeTokenData legacy string format', () => {
  const data = {
    tokenAddress: '0x1234567890123456789012345678901234567890',
    tokenType: 0,
    tokenSubID: '0',
  }
  const result = deserializeTokenData(data)
  assert.equal(result.tokenType, 0, 'should parse tokenType')
  assert.deepEqual(result.tokenAddress, TEST_TOKEN_ADDRESS, 'should convert string address to Uint8Array')
  assert.deepEqual(result.tokenSubID, new Uint8Array(32), 'should convert string subID to Uint8Array')
})

test('token-utils - getTokenDataERC20 with 20-byte address', () => {
  const result = getTokenDataERC20('0x1234567890123456789012345678901234567890')
  assert.equal(result.tokenType, 0, 'should be ERC20')
  assert.deepEqual(result.tokenAddress, TEST_TOKEN_ADDRESS, 'should preserve 20-byte address')
  assert.deepEqual(result.tokenSubID, new Uint8Array(32), 'should have zero subID')
})

test('token-utils - getTokenDataERC20 extracts last 20 bytes from 32-byte hash', () => {
  const hash = '0x0000000000000000000000001234567890123456789012345678901234567890'
  const result = getTokenDataERC20(hash)
  assert.deepEqual(result.tokenAddress, TEST_TOKEN_ADDRESS, 'should extract last 20 bytes')
})

test('token-utils - assertValidNoteToken 19-byte address', () => {
  assert.throws(() => {
    assertValidNoteToken({ tokenType: 0, tokenAddress: new Uint8Array(19), tokenSubID: new Uint8Array(32) }, 100n)
  }, 'should throw for 19-byte address')
})

test('token-utils - assertValidNoteToken 21-byte address', () => {
  assert.throws(() => {
    assertValidNoteToken({ tokenType: 0, tokenAddress: new Uint8Array(21), tokenSubID: new Uint8Array(32) }, 100n)
  }, 'should throw for 21-byte address')
})

test('token-utils - assertValidNoteToken ERC721 value zero', () => {
  assert.throws(() => {
    assertValidNoteToken({
      tokenType: 1,
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000001'),
    }, 0n)
  }, 'should throw for ERC721 with value 0')
})

test('token-utils - assertValidNoteToken ERC1155 value zero passes', () => {
  assert.doesNotThrow(() => {
    assertValidNoteToken({
      tokenType: 2,
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenSubID: hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000005'),
    }, 0n)
  }, 'should not throw for ERC1155 with value 0')
})

test('token-utils - serializeTokenData bigint subID', () => {
  const result = serializeTokenData(TEST_TOKEN_ADDRESS, 0, 0n)
  assert.deepEqual(result.tokenSubID, new Uint8Array(32), 'bigint 0n produces 32 zero bytes')
})

test('token-utils - serializeTokenData short address padded', () => {
  const short = hexToBytes('0xabcd')
  const result = serializeTokenData(short, 0, new Uint8Array(32))
  assert.equal(result.tokenAddress.length, 20, 'should pad to 20 bytes')
  assert.equal(result.tokenAddress[18], 0xab, 'should left-pad correctly')
  assert.equal(result.tokenAddress[19], 0xcd, 'should left-pad correctly')
})
