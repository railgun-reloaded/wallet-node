import { hook, test } from 'brittle'

import {
  hexToUint8Array,
  uint8ArrayToBigInt,
} from '../src/encoding'
import { initializeCryptographyLibs } from '../src/keys'
import {
  assertValidNoteToken,
  computeTokenHash,
  computeTokenHashERC20,
  computeTokenHashNFT,
  deserializeTokenData,
  getReadableTokenAddress,
  serializeTokenData,
} from '../src/notes/token-utils'

const TEST_TOKEN_ADDRESS = '0x1234567890123456789012345678901234567890'
const TEST_TOKEN_SUB_ID_ZERO =
  '0x0000000000000000000000000000000000000000000000000000000000000000'
const TEST_VALUE = BigInt('1000000000000000000') // 1 ETH

const ERC20_TOKEN_DATA = {
  tokenType: 0,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
}

const ERC721_TOKEN_DATA = {
  tokenType: 1,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID:
    '0x0000000000000000000000000000000000000000000000000000000000000001',
}

const ERC1155_TOKEN_DATA = {
  tokenType: 2,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID:
    '0x0000000000000000000000000000000000000000000000000000000000000005',
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

test('token-utils - computeTokenHash known vectors', (t) => {
  t.is(
    computeTokenHash(ERC20_TOKEN_DATA),
    '0x0000000000000000000000001234567890123456789012345678901234567890',
    'ERC20 hash should be zero-padded address'
  )
  t.is(
    computeTokenHash(ERC721_TOKEN_DATA),
    '0x075b737079de804169d5e006add4da4942063ab4fce32268c469c49460e52be0',
    'ERC721 hash should match known vector'
  )
  t.is(
    computeTokenHash(ERC1155_TOKEN_DATA),
    '0x03b8bfbf662863b2da6422aa0d1f021639ca87ae10d85bdf48069c2e98c72d6a',
    'ERC1155 hash should match known vector'
  )
})

test('token-utils - computeTokenHash invalid token type', (t) => {
  const tokenData = {
    tokenType: 99,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
  }

  t.exception(() => {
    computeTokenHash(tokenData)
  }, 'should throw error for invalid token type')
})

test('token-utils - computeTokenHashERC20 direct', (t) => {
  t.is(
    computeTokenHashERC20(TEST_TOKEN_ADDRESS),
    '0x0000000000000000000000001234567890123456789012345678901234567890',
    'should zero-pad address to 32 bytes'
  )
  t.is(
    computeTokenHashERC20('1234567890123456789012345678901234567890'),
    '0x0000000000000000000000001234567890123456789012345678901234567890',
    'should handle address without 0x prefix'
  )
})

test('token-utils - computeTokenHashNFT different subIDs', (t) => {
  const hash1 = computeTokenHashNFT(ERC721_TOKEN_DATA)
  const hash2 = computeTokenHashNFT({
    ...ERC721_TOKEN_DATA,
    tokenSubID:
      '0x0000000000000000000000000000000000000000000000000000000000000002',
  })

  t.not(hash1, hash2, 'different subIDs should produce different hashes')
})

test('token-utils - getReadableTokenAddress ERC20 known vector', (t) => {
  const readable = getReadableTokenAddress(ERC20_TOKEN_DATA)

  t.is(
    readable,
    '0x1234567890123456789012345678901234567890',
    'ERC20 readable should be trimmed 20-byte address'
  )
})

test('token-utils - getReadableTokenAddress NFT known vector', (t) => {
  const readable = getReadableTokenAddress(ERC721_TOKEN_DATA)

  t.is(
    readable,
    '0x1234567890123456789012345678901234567890 (0x0000000000000000000000000000000000000000000000000000000000000001)',
    'NFT readable should include address and subID'
  )
})

test('token-utils - getReadableTokenAddress invalid type', (t) => {
  t.exception(() => {
    getReadableTokenAddress({
      tokenType: 99 as any,
      tokenAddress: TEST_TOKEN_ADDRESS,
      tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
    })
  }, 'should throw for invalid token type')
})

test('token-utils - serializeTokenData roundtrip', (t) => {
  for (const tokenData of [ERC20_TOKEN_DATA, ERC721_TOKEN_DATA, ERC1155_TOKEN_DATA]) {
    const serialized = serializeTokenData(tokenData.tokenAddress, tokenData.tokenType, tokenData.tokenSubID)
    const deserialized = deserializeTokenData(serialized)

    t.is(deserialized.tokenType, tokenData.tokenType, `should preserve tokenType for type ${tokenData.tokenType}`)
    t.is(deserialized.tokenAddress, tokenData.tokenAddress, `should preserve tokenAddress for type ${tokenData.tokenType}`)
    t.is(deserialized.tokenSubID, tokenData.tokenSubID, `should preserve tokenSubID for type ${tokenData.tokenType}`)
  }
})

test('token-utils - assertValidNoteToken ERC20 valid', (t) => {
  t.execution(() => {
    assertValidNoteToken(ERC20_TOKEN_DATA, TEST_VALUE)
  }, 'should not throw for valid ERC20')
})

test('token-utils - assertValidNoteToken ERC20 valid 64-char address', (t) => {
  const tokenData = {
    tokenType: 0,
    tokenAddress: '0x' + '12'.repeat(32),
    tokenSubID: '0x0',
  }
  t.execution(() => {
    assertValidNoteToken(tokenData, TEST_VALUE)
  }, 'should accept 64-char (32-byte) ERC20 address')
})

test('token-utils - assertValidNoteToken ERC20 invalid address length', (t) => {
  const tokenData = {
    tokenType: 0,
    tokenAddress: '0x1234', // too short
    tokenSubID: '0x0',
  }
  t.exception(() => {
    assertValidNoteToken(tokenData, TEST_VALUE)
  }, 'should throw for invalid ERC20 address length')
})

test('token-utils - assertValidNoteToken ERC20 non-zero subID', (t) => {
  const tokenData = {
    tokenType: 0,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: '0x1',
  }
  t.exception(() => {
    assertValidNoteToken(tokenData, TEST_VALUE)
  }, 'should throw for ERC20 with non-zero subID')
})

test('token-utils - assertValidNoteToken ERC721 valid', (t) => {
  const tokenData = {
    tokenType: 1,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: '0x1',
  }
  t.execution(() => {
    assertValidNoteToken(tokenData, 1n)
  }, 'should not throw for valid ERC721')
})

test('token-utils - assertValidNoteToken ERC721 missing subID', (t) => {
  const tokenData = {
    tokenType: 1,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: '0x0',
  }
  t.exception(() => {
    assertValidNoteToken(tokenData, 1n)
  }, 'should throw for ERC721 without subID')
})

test('token-utils - assertValidNoteToken ERC721 wrong value', (t) => {
  const tokenData = {
    tokenType: 1,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: '0x1',
  }
  t.exception(() => {
    assertValidNoteToken(tokenData, 2n)
  }, 'should throw for ERC721 with value != 1')
})

test('token-utils - assertValidNoteToken ERC721 invalid address length', (t) => {
  const tokenData = {
    tokenType: 1,
    tokenAddress: '0x' + '12'.repeat(32), // 64 chars, not 40
    tokenSubID: '0x1',
  }
  t.exception(() => {
    assertValidNoteToken(tokenData, 1n)
  }, 'should throw for ERC721 with non-20-byte address')
})

test('token-utils - assertValidNoteToken ERC1155 valid', (t) => {
  const tokenData = {
    tokenType: 2,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: '0x5',
  }
  t.execution(() => {
    assertValidNoteToken(tokenData, 100n)
  }, 'should not throw for valid ERC1155')
})

test('token-utils - assertValidNoteToken ERC1155 missing subID', (t) => {
  const tokenData = {
    tokenType: 2,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: '0x0',
  }
  t.exception(() => {
    assertValidNoteToken(tokenData, 100n)
  }, 'should throw for ERC1155 without subID')
})

test('token-utils - assertValidNoteToken invalid token type', (t) => {
  const tokenData = {
    tokenType: 99,
    tokenAddress: TEST_TOKEN_ADDRESS,
    tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
  }
  t.exception(() => {
    assertValidNoteToken(tokenData, TEST_VALUE)
  }, 'should throw for invalid token type')
})

test('token-utils - computeTokenHash NFT properties', (t) => {
  const erc721Hash = computeTokenHash(ERC721_TOKEN_DATA)

  // Hash should be less than SNARK_PRIME (result of mod operation)
  const SNARK_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
  const hashBigInt = uint8ArrayToBigInt(hexToUint8Array(erc721Hash))
  t.ok(hashBigInt < SNARK_PRIME, 'NFT hash should be less than SNARK_PRIME')

  // computeTokenHashNFT directly should match computeTokenHash
  const directHash = computeTokenHashNFT(ERC721_TOKEN_DATA)
  t.is(directHash, erc721Hash, 'computeTokenHashNFT should match computeTokenHash for ERC721')
})
