import { randomBytes } from '@noble/hashes/utils'
import { AES } from '@railgun-reloaded/cryptography'
import { test } from 'brittle'

import {
  bigintToUint8Array,
  hexToUint8Array,
  uint8ArrayToHex,
} from '../src/hash'
import {
  getNoteBlindingKeys,
  getPublicViewingKey,
  getSharedSymmetricKey,
  initializeCryptographyLibs,
} from '../src/keys'
import {
  decryptCommitment,
  decryptCommitmentAsReceiverOrSender,
} from '../src/notes/decrypt-commitment'
import { assertValidNoteRandom, getNoteHash } from '../src/notes/note-utils'
import { ShieldNote } from '../src/notes/shield-note'
import {
  assertValidNoteToken,
  computeTokenHash,
  computeTokenHashERC20,
  computeTokenHashNFT,
  deserializeTokenData,
  getReadableTokenAddress,
  serializeTokenData,
} from '../src/notes/token-utils'
import {
  TransactNote,
  ciphertextToEncryptedRandomData,
  encryptedDataToCiphertext,
  isLegacyTransactNote,
} from '../src/notes/transact-note'
import { UnshieldNote } from '../src/notes/unshield-note'

const TEST_TOKEN_ADDRESS = '0x1234567890123456789012345678901234567890'
const TEST_TOKEN_SUB_ID_ZERO =
  '0x0000000000000000000000000000000000000000000000000000000000000000'
const TEST_NPK =
  '0x1234567890123456789012345678901234567890123456789012345678901234'
const TEST_RANDOM = '12345678901234567890123456789012'
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

test('token-utils - computeTokenHash ERC20 known vector', (t) => {
  const hash = computeTokenHash(ERC20_TOKEN_DATA)

  // ERC20 hash is the address zero-padded to 32 bytes
  t.is(
    hash,
    '0x0000000000000000000000001234567890123456789012345678901234567890',
    'ERC20 hash should be zero-padded address'
  )
})

test('token-utils - computeTokenHash ERC721 known vector', (t) => {
  const hash = computeTokenHash(ERC721_TOKEN_DATA)

  // Known keccak256-based hash for this token data, mod SNARK_PRIME
  t.is(
    hash,
    '0x075b737079de804169d5e006add4da4942063ab4fce32268c469c49460e52be0',
    'ERC721 hash should match known vector'
  )
})

test('token-utils - computeTokenHash ERC1155 known vector', (t) => {
  const hash = computeTokenHash(ERC1155_TOKEN_DATA)

  t.is(
    hash,
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

test('token-utils - computeTokenHash deterministic', (t) => {
  const hash1 = computeTokenHash(ERC20_TOKEN_DATA)
  const hash2 = computeTokenHash(ERC20_TOKEN_DATA)

  t.is(hash1, hash2, 'should generate same hash for same token data')
})

test('token-utils - computeTokenHashERC20 direct', (t) => {
  const hash = computeTokenHashERC20(TEST_TOKEN_ADDRESS)

  t.is(
    hash,
    '0x0000000000000000000000001234567890123456789012345678901234567890',
    'should zero-pad address to 32 bytes'
  )
})

test('token-utils - computeTokenHashERC20 without 0x prefix', (t) => {
  const hash = computeTokenHashERC20(
    '1234567890123456789012345678901234567890'
  )

  t.is(
    hash,
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

test('token-utils - serializeTokenData roundtrip ERC20', (t) => {
  const serialized = serializeTokenData(ERC20_TOKEN_DATA)
  const deserialized = deserializeTokenData(serialized)

  t.is(
    deserialized.tokenType,
    ERC20_TOKEN_DATA.tokenType,
    'should preserve tokenType'
  )
  t.is(
    deserialized.tokenAddress,
    ERC20_TOKEN_DATA.tokenAddress,
    'should preserve tokenAddress'
  )
  t.is(
    deserialized.tokenSubID,
    ERC20_TOKEN_DATA.tokenSubID,
    'should preserve tokenSubID'
  )
})

test('token-utils - serializeTokenData roundtrip ERC721', (t) => {
  const serialized = serializeTokenData(ERC721_TOKEN_DATA)
  const deserialized = deserializeTokenData(serialized)

  t.is(
    deserialized.tokenType,
    ERC721_TOKEN_DATA.tokenType,
    'should preserve tokenType'
  )
  t.is(
    deserialized.tokenAddress,
    ERC721_TOKEN_DATA.tokenAddress,
    'should preserve tokenAddress'
  )
  t.is(
    deserialized.tokenSubID,
    ERC721_TOKEN_DATA.tokenSubID,
    'should preserve tokenSubID'
  )
})

test('token-utils - serializeTokenData roundtrip ERC1155', (t) => {
  const serialized = serializeTokenData(ERC1155_TOKEN_DATA)
  const deserialized = deserializeTokenData(serialized)

  t.is(
    deserialized.tokenType,
    ERC1155_TOKEN_DATA.tokenType,
    'should preserve tokenType'
  )
  t.is(
    deserialized.tokenAddress,
    ERC1155_TOKEN_DATA.tokenAddress,
    'should preserve tokenAddress'
  )
  t.is(
    deserialized.tokenSubID,
    ERC1155_TOKEN_DATA.tokenSubID,
    'should preserve tokenSubID'
  )
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

test('note-utils - assertValidNoteRandom valid', (t) => {
  t.execution(() => {
    assertValidNoteRandom(TEST_RANDOM)
  }, 'should not throw for valid random')

  t.execution(() => {
    assertValidNoteRandom('0x' + TEST_RANDOM)
  }, 'should not throw for valid random with 0x prefix')
})

test('note-utils - assertValidNoteRandom invalid length', (t) => {
  t.exception(() => {
    assertValidNoteRandom('0x12345678')
  }, 'should throw for short random')

  t.exception(() => {
    assertValidNoteRandom('0x' + '12'.repeat(100))
  }, 'should throw for long random')
})

test('note-utils - getNoteHash known vector', async (t) => {
  await initializeCryptographyLibs()

  const hash = getNoteHash(
    TEST_NPK,
    ERC20_TOKEN_DATA,
    BigInt('1000000000000000000')
  )

  t.is(
    hash,
    7822264150748016131168246751038092891550418438611309934403065338118898163274n,
    'should match known poseidon hash'
  )
})

test('note-utils - getNoteHash deterministic', async (t) => {
  await initializeCryptographyLibs()

  const hash1 = getNoteHash(TEST_NPK, ERC20_TOKEN_DATA, TEST_VALUE)
  const hash2 = getNoteHash(TEST_NPK, ERC20_TOKEN_DATA, TEST_VALUE)

  t.is(hash1, hash2, 'should generate same hash for same inputs')
})

test('note-utils - getNoteHash different values produce different hashes', async (t) => {
  await initializeCryptographyLibs()

  const hash1 = getNoteHash(
    TEST_NPK,
    ERC20_TOKEN_DATA,
    BigInt('1000000000000000000')
  )
  const hash2 = getNoteHash(
    TEST_NPK,
    ERC20_TOKEN_DATA,
    BigInt('2000000000000000000')
  )

  t.is(
    hash1,
    7822264150748016131168246751038092891550418438611309934403065338118898163274n,
    'hash1 should match known vector'
  )
  t.is(
    hash2,
    6490590858878968097404251785480759231009497191854530268680734263829621455840n,
    'hash2 should match known vector'
  )
  t.not(hash1, hash2, 'should generate different hashes for different values')
})

test('note-utils - getNoteHash different addresses produce different hashes', async (t) => {
  await initializeCryptographyLibs()

  const address2 =
    '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd'
  const hash1 = getNoteHash(TEST_NPK, ERC20_TOKEN_DATA, TEST_VALUE)
  const hash2 = getNoteHash(address2, ERC20_TOKEN_DATA, TEST_VALUE)

  t.is(
    hash2,
    5736106082853618600278509422750779697540890231038988902514807784802527031326n,
    'hash2 should match known vector'
  )
  t.not(
    hash1,
    hash2,
    'should generate different hashes for different addresses'
  )
})

test('shield-note - create ShieldNote', async (t) => {
  await initializeCryptographyLibs()

  const masterPublicKey = BigInt('123456789012345678901234567890')
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
  await initializeCryptographyLibs()

  const masterPublicKey = BigInt('123456789012345678901234567890')
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

test('shield-note - getTokenHash matches computeTokenHash', async (t) => {
  await initializeCryptographyLibs()

  const masterPublicKey = BigInt('123456789012345678901234567890')
  const shieldNote = new ShieldNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    masterPublicKey
  )

  t.is(
    shieldNote.getTokenHash(),
    computeTokenHash(ERC20_TOKEN_DATA),
    'getTokenHash should match computeTokenHash'
  )
})

test('shield-note - fromCommitment with GeneratedCommitment', async (t) => {
  await initializeCryptographyLibs()

  const masterPublicKey = BigInt('999888777666555444333222111')
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC20',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  const shieldNote = ShieldNote.fromCommitment(commitment, masterPublicKey)

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

test('shield-note - fromCommitment with ShieldCommitment', async (t) => {
  await initializeCryptographyLibs()

  const shieldKeyBytes = bigintToUint8Array(BigInt('112233445566778899'), 32)
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 7777n,
      token: {
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC721',
        tokenSubID: hexToUint8Array(
          '0x0000000000000000000000000000000000000000000000000000000000000001'
        ),
      },
    },
    encryptedBundle: [hexToUint8Array('0x' + 'ef'.repeat(16))],
    shieldKey: shieldKeyBytes,
  }

  const shieldNote = ShieldNote.fromCommitment(commitment)

  t.ok(
    shieldNote instanceof ShieldNote,
    'should create ShieldNote from ShieldCommitment'
  )
  t.is(shieldNote.value, 7777n, 'should set value')
  t.is(
    shieldNote.masterPublicKey,
    BigInt('112233445566778899'),
    'should extract masterPublicKey from shieldKey'
  )
  t.is(
    shieldNote.tokenData.tokenType,
    1,
    'should convert ERC721 string to enum'
  )
})

test('shield-note - fromCommitment ERC1155 token type conversion', async (t) => {
  await initializeCryptographyLibs()

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 100n,
      token: {
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC1155',
        tokenSubID: hexToUint8Array(
          '0x0000000000000000000000000000000000000000000000000000000000000005'
        ),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  const shieldNote = ShieldNote.fromCommitment(commitment, 1n)

  t.is(
    shieldNote.tokenData.tokenType,
    2,
    'should convert ERC1155 string to enum'
  )
})

test('shield-note - fromCommitment missing random throws', async (t) => {
  await initializeCryptographyLibs()

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC20',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [] as Uint8Array[],
  }

  t.exception(() => {
    ShieldNote.fromCommitment(commitment, 1n)
  }, 'should throw when random data is missing')
})

test('shield-note - fromCommitment missing masterPublicKey throws', async (t) => {
  await initializeCryptographyLibs()

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC20',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  t.exception(() => {
    // No masterPublicKey param and no shieldKey in commitment
    ShieldNote.fromCommitment(commitment)
  }, 'should throw when masterPublicKey is missing for GeneratedCommitment')
})

test('shield-note - fromCommitment invalid tokenType throws', async (t) => {
  await initializeCryptographyLibs()

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'INVALID',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  t.exception(() => {
    ShieldNote.fromCommitment(commitment, 1n)
  }, 'should throw for invalid token type string')
})

test('transact-note - create TransactNote', async (t) => {
  await initializeCryptographyLibs()

  const hash = BigInt('99999999999999999999')
  const receiverAddressData = {
    masterPublicKey: BigInt('123456789012345678901234567890'),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = new TransactNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    hash,
    receiverAddressData
  )

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
  await initializeCryptographyLibs()

  const hash = BigInt('99999999999999999999')
  const receiverAddressData = {
    masterPublicKey: BigInt('123456789012345678901234567890'),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = new TransactNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    hash,
    receiverAddressData
  )
  const serialized = transactNote.serialize()

  t.ok(serialized instanceof Uint8Array, 'should serialize to Uint8Array')

  const deserialized = TransactNote.deserialize(serialized)

  t.ok(
    deserialized instanceof TransactNote,
    'should deserialize to TransactNote'
  )
  t.is(deserialized.value, TEST_VALUE, 'should preserve value')
  t.is(deserialized.hash, hash, 'should preserve hash')
  t.is(deserialized.random, TEST_RANDOM, 'should preserve random')
  t.is(deserialized.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
  t.is(
    deserialized.tokenData.tokenType,
    ERC20_TOKEN_DATA.tokenType,
    'should preserve tokenType'
  )
  t.is(
    deserialized.receiverAddressData.masterPublicKey,
    receiverAddressData.masterPublicKey,
    'should preserve receiver masterPublicKey'
  )
})

test('transact-note - serialize and deserialize with all optional fields', async (t) => {
  await initializeCryptographyLibs()

  const hash = BigInt('99999999999999999999')
  const receiverAddressData = {
    masterPublicKey: BigInt('123456789012345678901234567890'),
    viewingPublicKey: new Uint8Array(32).fill(0xaa),
  }
  const senderAddressData = {
    masterPublicKey: BigInt('987654321098765432109876543210'),
    viewingPublicKey: new Uint8Array(32).fill(0xbb),
  }

  const transactNote = new TransactNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    hash,
    receiverAddressData,
    senderAddressData,
    1, // outputType (BroadcasterFee)
    'test-wallet', // walletSource
    'aabbccdd11223344aabbccdd11223344', // senderRandom
    'Hello memo', // memoText
    '1000', // shieldFee
    42 // blockNumber
  )

  const serialized = transactNote.serialize()
  const deserialized = TransactNote.deserialize(serialized)

  t.is(deserialized.value, TEST_VALUE, 'should preserve value')
  t.is(deserialized.hash, hash, 'should preserve hash')
  t.is(deserialized.random, TEST_RANDOM, 'should preserve random')
  t.is(
    deserialized.receiverAddressData.masterPublicKey,
    receiverAddressData.masterPublicKey,
    'should preserve receiver masterPublicKey'
  )
  t.ok(deserialized.senderAddressData, 'should preserve senderAddressData')
  t.is(
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

test('transact-note - serialize and deserialize with no senderAddressData', async (t) => {
  await initializeCryptographyLibs()

  const hash = BigInt('99999999999999999999')
  const receiverAddressData = {
    masterPublicKey: BigInt('123456789012345678901234567890'),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = new TransactNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    hash,
    receiverAddressData
  )
  const serialized = transactNote.serialize()
  const deserialized = TransactNote.deserialize(serialized)

  t.is(
    deserialized.senderAddressData,
    undefined,
    'senderAddressData should be undefined when not set'
  )
})

test('transact-note - with memo text survives serialization', async (t) => {
  await initializeCryptographyLibs()

  const hash = BigInt('99999999999999999999')
  const receiverAddressData = {
    masterPublicKey: BigInt('123456789012345678901234567890'),
    viewingPublicKey: new Uint8Array(32),
  }
  const memoText = 'Test memo with special chars: !@#$%'

  const transactNote = new TransactNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    hash,
    receiverAddressData,
    undefined,
    undefined,
    undefined,
    undefined,
    memoText
  )

  const serialized = transactNote.serialize()
  const deserialized = TransactNote.deserialize(serialized)

  t.is(
    deserialized.memoText,
    memoText,
    'memo text should survive serialization roundtrip'
  )
})

test('transact-note - getTokenHash matches computeTokenHash', async (t) => {
  await initializeCryptographyLibs()

  const hash = BigInt('99999999999999999999')
  const receiverAddressData = {
    masterPublicKey: BigInt('123456789012345678901234567890'),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = new TransactNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    hash,
    receiverAddressData
  )

  t.is(
    transactNote.getTokenHash(),
    computeTokenHash(ERC20_TOKEN_DATA),
    'getTokenHash should match computeTokenHash'
  )
})

test('transact-note - fromCommitment', async (t) => {
  await initializeCryptographyLibs()

  const commitment = {
    hash: new Uint8Array(32),
    ciphertext: {
      iv: new Uint8Array(16),
      tag: new Uint8Array(16),
      data: [] as Uint8Array[],
    },
    blindedSenderViewingKey: new Uint8Array(32),
    blindedReceiverViewingKey: new Uint8Array(32),
    annotationData: new Uint8Array(0),
    memo: [],
    treeNumber: 0,
    treePosition: 0,
  }

  const random = TEST_RANDOM
  const npk = TEST_NPK
  const value = TEST_VALUE
  const receiverAddressData = {
    masterPublicKey: BigInt('123456789012345678901234567890'),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = TransactNote.fromCommitment(
    commitment,
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
  // The hash should be computed via getNoteHash
  t.is(typeof transactNote.hash, 'bigint', 'should compute hash as bigint')
  t.ok(transactNote.hash > 0n, 'hash should be positive')
})

test('transact-note - fromCommitment with senderAddressData', async (t) => {
  await initializeCryptographyLibs()

  const commitment = {
    hash: new Uint8Array(32),
    ciphertext: {
      iv: new Uint8Array(16),
      tag: new Uint8Array(16),
      data: [] as Uint8Array[],
    },
    blindedSenderViewingKey: new Uint8Array(32),
    blindedReceiverViewingKey: new Uint8Array(32),
    annotationData: new Uint8Array(0),
    memo: [],
    treeNumber: 0,
    treePosition: 0,
  }

  const receiverAddressData = {
    masterPublicKey: BigInt('111'),
    viewingPublicKey: new Uint8Array(32),
  }
  const senderAddressData = {
    masterPublicKey: BigInt('222'),
    viewingPublicKey: new Uint8Array(32),
  }

  const transactNote = TransactNote.fromCommitment(
    commitment,
    TEST_RANDOM,
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    receiverAddressData,
    senderAddressData
  )

  t.ok(transactNote.senderAddressData, 'should set senderAddressData')
  t.is(
    transactNote.senderAddressData!.masterPublicKey,
    BigInt('222'),
    'should preserve sender masterPublicKey'
  )
})

test('transact-note - isLegacyTransactNote', (t) => {
  t.is(
    isLegacyTransactNote({ encryptedRandom: ['abc', 'def'] }),
    true,
    'should detect legacy format with encryptedRandom'
  )

  t.is(
    isLegacyTransactNote({ random: 'abc123' }),
    false,
    'should detect modern format without encryptedRandom'
  )

  t.is(isLegacyTransactNote({}), false, 'should return false for empty object')
})

test('transact-note - ciphertextToEncryptedRandomData', (t) => {
  const ciphertext = {
    iv: 'aabbccdd11223344',
    tag: 'eeff00112233aabb',
    data: ['deadbeef12345678'],
  }

  const result = ciphertextToEncryptedRandomData(ciphertext)

  t.is(
    result[0],
    'aabbccdd11223344eeff00112233aabb',
    'ivTag should be iv + tag concatenated'
  )
  t.is(result[1], 'deadbeef12345678', 'data should be first element')
})

test('transact-note - ciphertextToEncryptedRandomData empty data', (t) => {
  const ciphertext = {
    iv: 'aabbccdd11223344',
    tag: 'eeff00112233aabb',
    data: [] as string[],
  }

  const result = ciphertextToEncryptedRandomData(ciphertext)

  t.is(
    result[0],
    'aabbccdd11223344eeff00112233aabb',
    'ivTag should be iv + tag'
  )
  t.is(result[1], '', 'data should be empty string when no data')
})

test('transact-note - encryptedDataToCiphertext', (t) => {
  // ivTag is 32 chars, so slice(0,32) gets full ivTag as iv, slice(32) gets empty tag
  const encryptedData: [string, string] = [
    'aabbccdd11223344eeff00112233aabb',
    'deadbeef12345678',
  ]

  const result = encryptedDataToCiphertext(encryptedData)

  // With 32-char ivTag: iv = slice(0,32), tag = slice(32) = ''
  t.is(
    result.iv,
    'aabbccdd11223344eeff00112233aabb',
    'iv should be first 32 chars of ivTag'
  )
  t.is(result.tag, '', 'tag should be remaining chars of ivTag')
  t.is(result.data[0], 'deadbeef12345678', 'data should be preserved')
})

test('transact-note - ciphertextToEncryptedRandomData / encryptedDataToCiphertext roundtrip', (t) => {
  const originalCiphertext = {
    iv: 'aabbccdd11223344aabbccdd11223344',
    tag: 'eeff00112233aabbeeff00112233aabb',
    data: ['deadbeef12345678deadbeef12345678'],
  }

  const encrypted = ciphertextToEncryptedRandomData(originalCiphertext)
  const restored = encryptedDataToCiphertext(encrypted)

  t.is(restored.iv, originalCiphertext.iv, 'iv should roundtrip')
  t.is(restored.tag, originalCiphertext.tag, 'tag should roundtrip')
  t.is(restored.data[0], originalCiphertext.data[0], 'data should roundtrip')
})

test('transact-note - serializeLegacy and deserializeLegacy roundtrip', async (t) => {
  await initializeCryptographyLibs()

  // Generate real key pairs for encryption/decryption
  const senderPrivateKey = randomBytes(32)
  const senderPublicKey = getPublicViewingKey(senderPrivateKey)
  const receiverPrivateKey = randomBytes(32)
  const receiverPublicKey = getPublicViewingKey(receiverPrivateKey)

  const hash = BigInt('99999999999999999999')
  const receiverAddressData = {
    masterPublicKey: BigInt('123456789012345678901234567890'),
    viewingPublicKey: receiverPublicKey,
  }

  const transactNote = new TransactNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    hash,
    receiverAddressData,
    undefined,
    undefined,
    undefined,
    undefined,
    'legacy memo',
    undefined,
    100
  )

  // Serialize with sender's private key and receiver's public key
  const serialized = await transactNote.serializeLegacy(
    senderPrivateKey,
    receiverPublicKey
  )
  t.ok(
    serialized instanceof Uint8Array,
    'serializeLegacy should return Uint8Array'
  )

  // Deserialize with receiver's private key and sender's public key
  const deserialized = await TransactNote.deserializeLegacy(
    serialized,
    receiverPrivateKey,
    senderPublicKey
  )

  t.ok(
    deserialized instanceof TransactNote,
    'should deserialize to TransactNote'
  )
  t.is(deserialized.value, TEST_VALUE, 'should preserve value')
  // deserializeLegacy returns random with 0x prefix via uint8ArrayToHex
  t.is(
    deserialized.random,
    '0x' + TEST_RANDOM,
    'should preserve random through encryption'
  )
  t.is(deserialized.notePublicKey, TEST_NPK, 'should preserve notePublicKey')
  t.is(deserialized.memoText, 'legacy memo', 'should preserve memoText')
  t.is(deserialized.blockNumber, 100, 'should preserve blockNumber')
})

test('unshield-note - create UnshieldNote', async (t) => {
  await initializeCryptographyLibs()

  const toAddress = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'
  const hash = BigInt('99999999999999999999')

  const unshieldNote = new UnshieldNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    toAddress,
    hash,
    false
  )

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
  await initializeCryptographyLibs()

  const toAddress = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'
  const hash = BigInt('99999999999999999999')

  const unshieldNote = new UnshieldNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    toAddress,
    hash,
    true
  )
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

test('unshield-note - getTokenHash matches computeTokenHash', async (t) => {
  await initializeCryptographyLibs()

  const toAddress = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'
  const hash = BigInt('99999999999999999999')

  const unshieldNote = new UnshieldNote(
    TEST_NPK,
    TEST_VALUE,
    ERC20_TOKEN_DATA,
    TEST_RANDOM,
    toAddress,
    hash,
    false
  )

  t.is(
    unshieldNote.getTokenHash(),
    computeTokenHash(ERC20_TOKEN_DATA),
    'getTokenHash should match computeTokenHash'
  )
})

test('unshield-note - fromUnshield ERC20', async (t) => {
  await initializeCryptographyLibs()

  const unshieldData = {
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
      tokenType: 'ERC20',
      tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
    },
    amount: TEST_VALUE,
    fee: 100n,
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
})

test('unshield-note - fromUnshield ERC721', async (t) => {
  await initializeCryptographyLibs()

  const unshieldData = {
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
      tokenType: 'ERC721',
      tokenSubID: hexToUint8Array(
        '0x0000000000000000000000000000000000000000000000000000000000000001'
      ),
    },
    amount: 1n,
    fee: 0n,
  }

  const unshieldNote = UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)

  t.is(
    unshieldNote.tokenData.tokenType,
    1,
    'should convert ERC721 string to enum'
  )
})

test('unshield-note - fromUnshield ERC1155', async (t) => {
  await initializeCryptographyLibs()

  const unshieldData = {
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
      tokenType: 'ERC1155',
      tokenSubID: hexToUint8Array(
        '0x0000000000000000000000000000000000000000000000000000000000000005'
      ),
    },
    amount: 50n,
    fee: 5n,
  }

  const unshieldNote = UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)

  t.is(
    unshieldNote.tokenData.tokenType,
    2,
    'should convert ERC1155 string to enum'
  )
})

test('unshield-note - fromUnshield invalid tokenType throws', async (t) => {
  await initializeCryptographyLibs()

  const unshieldData = {
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
      tokenType: 'INVALID',
      tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
    },
    amount: TEST_VALUE,
    fee: 0n,
  }

  t.exception(() => {
    UnshieldNote.fromUnshield(unshieldData, TEST_RANDOM)
  }, 'should throw for invalid token type string')
})

test('decrypt-commitment - decryptCommitment with invalid key returns null', async (t) => {
  await initializeCryptographyLibs()

  const ciphertext = {
    iv: randomBytes(16),
    tag: randomBytes(16),
    data: [randomBytes(100)],
  }
  const blindedViewingKey = randomBytes(32)
  const viewingPrivateKey = randomBytes(32)

  const result = await decryptCommitment(
    ciphertext,
    blindedViewingKey,
    viewingPrivateKey
  )

  t.is(result, null, 'should return null for invalid decryption')
})

test('decrypt-commitment - decryptCommitmentAsReceiverOrSender with invalid keys returns null', async (t) => {
  await initializeCryptographyLibs()

  const ciphertext = {
    iv: randomBytes(16),
    tag: randomBytes(16),
    data: [randomBytes(100)],
  }
  const blindedReceiverKey = randomBytes(32)
  const blindedSenderKey = randomBytes(32)
  const viewingPrivateKey = randomBytes(32)

  const result = await decryptCommitmentAsReceiverOrSender(
    ciphertext,
    blindedReceiverKey,
    blindedSenderKey,
    viewingPrivateKey
  )

  t.is(result, null, 'should return null when unable to decrypt')
})

test('decrypt-commitment - decryptCommitment successful roundtrip', async (t) => {
  await initializeCryptographyLibs()

  // Generate real key pairs
  const viewingPrivateKey = randomBytes(32)
  const viewingPublicKey = getPublicViewingKey(viewingPrivateKey)

  // Create the blinded key using a known random
  const sharedRandom = randomBytes(32)
  const senderRandom = new Uint8Array(32) // zero sender random for simplicity

  const senderPrivateKey = randomBytes(32)
  const senderPublicKey = getPublicViewingKey(senderPrivateKey)

  const { blindedReceiverViewingKey } = getNoteBlindingKeys(
    senderPublicKey,
    viewingPublicKey,
    sharedRandom,
    senderRandom
  )

  // Build plaintext data matching the format expected by decryptCommitment:
  // random (16) + npk (32) + value (32) + tokenAddress (20) + tokenType (1) + tokenSubID (32) = 133 bytes
  const noteRandom = randomBytes(16)
  const npk = randomBytes(32)
  const value = bigintToUint8Array(TEST_VALUE, 32)
  const tokenAddress = hexToUint8Array(TEST_TOKEN_ADDRESS)
  const tokenType = new Uint8Array([0]) // ERC20
  const tokenSubID = new Uint8Array(32) // zero

  const plaintext = new Uint8Array(133)
  plaintext.set(noteRandom, 0)
  plaintext.set(npk, 16)
  plaintext.set(value, 48)
  plaintext.set(tokenAddress, 80)
  plaintext.set(tokenType, 100)
  plaintext.set(tokenSubID, 101)

  // Encrypt using the shared key derived from viewingPrivateKey + blindedReceiverViewingKey
  const sharedKey = await getSharedSymmetricKey(
    viewingPrivateKey,
    blindedReceiverViewingKey
  )
  t.ok(sharedKey, 'should generate shared key')

  const ciphertext = AES.encryptGCM([plaintext], sharedKey!)

  // Now decrypt using the same viewingPrivateKey + blindedReceiverViewingKey
  const result = await decryptCommitment(
    ciphertext,
    blindedReceiverViewingKey,
    viewingPrivateKey
  )

  t.ok(result !== null, 'should successfully decrypt')
  t.is(result!.random, uint8ArrayToHex(noteRandom), 'should recover random')
  t.is(result!.npk, uint8ArrayToHex(npk), 'should recover npk')
  t.is(result!.value, TEST_VALUE, 'should recover value')
  t.is(result!.tokenData.tokenType, 0, 'should recover tokenType')
  t.is(
    result!.tokenData.tokenAddress,
    uint8ArrayToHex(tokenAddress),
    'should recover tokenAddress'
  )
})

test('decrypt-commitment - decryptCommitmentAsReceiverOrSender identifies receiver', async (t) => {
  await initializeCryptographyLibs()

  const viewingPrivateKey = randomBytes(32)
  const viewingPublicKey = getPublicViewingKey(viewingPrivateKey)

  const sharedRandom = randomBytes(32)
  const senderRandom = new Uint8Array(32)

  const senderPrivateKey = randomBytes(32)
  const senderPublicKey = getPublicViewingKey(senderPrivateKey)

  const { blindedReceiverViewingKey } = getNoteBlindingKeys(
    senderPublicKey,
    viewingPublicKey,
    sharedRandom,
    senderRandom
  )

  // Build plaintext
  const plaintext = new Uint8Array(133)
  plaintext.set(randomBytes(16), 0) // random
  plaintext.set(randomBytes(32), 16) // npk
  plaintext.set(bigintToUint8Array(TEST_VALUE, 32), 48) // value
  plaintext.set(hexToUint8Array(TEST_TOKEN_ADDRESS), 80) // tokenAddress
  plaintext.set(new Uint8Array([0]), 100) // tokenType
  plaintext.set(new Uint8Array(32), 101) // tokenSubID

  // Encrypt with receiver's shared key
  const sharedKey = await getSharedSymmetricKey(
    viewingPrivateKey,
    blindedReceiverViewingKey
  )
  const ciphertext = AES.encryptGCM([plaintext], sharedKey!)

  // Use a different key for the sender blinded key so only receiver path works
  const fakeBlindedSenderKey = getPublicViewingKey(randomBytes(32))

  const result = await decryptCommitmentAsReceiverOrSender(
    ciphertext,
    blindedReceiverViewingKey,
    fakeBlindedSenderKey,
    viewingPrivateKey
  )

  t.ok(result !== null, 'should successfully decrypt')
  t.is(result!.isReceiver, true, 'should identify as receiver')
  t.is(result!.data.value, TEST_VALUE, 'should recover value')
})
