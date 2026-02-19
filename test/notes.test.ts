import { randomBytes } from '@noble/hashes/utils'
import { AES } from '@railgun-reloaded/cryptography'
import { ActionType } from '@railgun-reloaded/scanner'
import { hook, test } from 'brittle'

import {
  bigintToUint8Array,
  hexToUint8Array,
  uint8ArrayToBigInt,
  uint8ArrayToHex,
} from '../src/encoding'
import {
  getNoteBlindingKeys,
  getPublicViewingKey,
  getSharedSymmetricKey,
  initializeCryptographyLibs,
} from '../src/keys'
import {
  decryptCommitment,
  decryptCommitmentAsReceiverOrSender,
  formatCommitmentCiphertext,
} from '../src/notes/commitment'
import type { CommitmentCiphertextStruct, TokenDataGetter } from '../src/notes/definitions'
import { ChainType, OutputType, TXIDVersion } from '../src/notes/definitions'
import { Memo } from '../src/notes/memo'
import { Note } from '../src/notes/note'
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
import { TransactNote } from '../src/notes/transact-note'
import { UnshieldNote } from '../src/notes/unshield-note'

const TEST_CHAIN = { type: ChainType.EVM, id: 1 }

/**
 * Mock TokenDataGetter for tests.
 * Assumes all token hashes are ERC20 (address zero-padded to 32 bytes).
 */
const mockTokenDataGetter: TokenDataGetter = {
  /**
   * Resolves a token hash to ERC20 token data.
   * Only handles ERC20 (txidVersion and chain are needed for NFT lookups in real implementations).
   * @param _txidVersion - The TXID version (used for NFT contract selection)
   * @param _chain - The chain (used for NFT contract lookup)
   * @param tokenHash - The token hash to resolve
   * @returns ERC20 token data with address extracted from hash
   */
  async getTokenDataFromHash (_txidVersion, _chain, tokenHash) {
    const cleanHash = tokenHash.startsWith('0x') ? tokenHash.slice(2) : tokenHash
    const address = '0x' + cleanHash.slice(24) // last 20 bytes
    return {
      tokenType: 0,
      tokenAddress: address,
      tokenSubID: '0x0000000000000000000000000000000000000000000000000000000000000000',
    }
  }
}

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

test('Note.assertValidRandom valid', (t) => {
  t.execution(() => {
    Note.assertValidRandom(TEST_RANDOM)
  }, 'should not throw for valid random')

  t.execution(() => {
    Note.assertValidRandom('0x' + TEST_RANDOM)
  }, 'should not throw for valid random with 0x prefix')
})

test('Note.assertValidRandom invalid length', (t) => {
  t.exception(() => {
    Note.assertValidRandom('0x12345678')
  }, 'should throw for short random')

  t.exception(() => {
    Note.assertValidRandom('0x' + '12'.repeat(100))
  }, 'should throw for long random')
})

test('Note.getHash - known vector and properties', async (t) => {
  const npkBytes = hexToUint8Array(TEST_NPK)
  const tokenHashBytes = hexToUint8Array(computeTokenHash(ERC20_TOKEN_DATA))

  const hash1 = Note.getHash(npkBytes, tokenHashBytes, BigInt('1000000000000000000'))
  t.is(
    uint8ArrayToBigInt(hash1),
    7822264150748016131168246751038092891550418438611309934403065338118898163274n,
    'should match known poseidon hash'
  )

  // Different value produces different hash
  const hash2 = Note.getHash(npkBytes, tokenHashBytes, BigInt('2000000000000000000'))
  t.not(uint8ArrayToHex(hash1), uint8ArrayToHex(hash2), 'different values should produce different hashes')

  // Different address produces different hash
  const address2 = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd'
  const hash3 = Note.getHash(hexToUint8Array(address2), tokenHashBytes, BigInt('1000000000000000000'))
  t.not(uint8ArrayToHex(hash1), uint8ArrayToHex(hash3), 'different addresses should produce different hashes')
})

test('shield-note - create ShieldNote', async (t) => {
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

test('shield-note - fromGeneratedCommitment with GeneratedCommitment', async (t) => {
  const masterPublicKey = BigInt('999888777666555444333222111')
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC20',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  const shieldNote = ShieldNote.fromGeneratedCommitment(commitment, masterPublicKey)

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

test('shield-note - fromShieldCommitment with ShieldCommitment', async (t) => {
  // Shielder's key pair
  const shieldPrivateKey = randomBytes(32)
  const shieldKey = getPublicViewingKey(shieldPrivateKey)

  // Receiver's key pair
  const viewingPrivateKey = randomBytes(32)
  const receiverViewingPublicKey = getPublicViewingKey(viewingPrivateKey)

  // Build plaintext: random (16 bytes) + padding (16 bytes) = block0 (32 bytes), block1 (32 bytes)
  const noteRandom = hexToUint8Array('0x' + 'ef'.repeat(16))
  const block0 = new Uint8Array(32)
  block0.set(noteRandom, 0)
  const block1 = new Uint8Array(32)

  // Shielder encrypts: ECDH(shieldPrivateKey, receiverViewingPublicKey)
  const sharedKey = await getSharedSymmetricKey(shieldPrivateKey, receiverViewingPublicKey)
  t.ok(sharedKey, 'should derive shared key')
  const ciphertext = AES.encryptGCM([block0, block1], sharedKey!)

  // Pack into bundle format: [data0, data1, ivTag]
  const ivTag = new Uint8Array(32)
  ivTag.set(ciphertext.iv, 0)
  ivTag.set(ciphertext.tag, 16)

  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 1n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC721',
        tokenSubID: hexToUint8Array(
          '0x0000000000000000000000000000000000000000000000000000000000000001'
        ),
      },
    },
    encryptedBundle: [ciphertext.data[0]!, ciphertext.data[1]!, ivTag],
    shieldKey,
  }

  const masterPublicKey = 12345n
  const shieldNote = await ShieldNote.fromShieldCommitment(commitment, viewingPrivateKey, masterPublicKey)

  t.ok(
    shieldNote instanceof ShieldNote,
    'should create ShieldNote from ShieldCommitment'
  )
  t.is(shieldNote!.value, 1n, 'should set value')
  t.is(
    shieldNote!.random,
    uint8ArrayToHex(noteRandom),
    'should decrypt random correctly'
  )
  t.is(
    shieldNote!.tokenData.tokenType,
    1,
    'should convert ERC721 string to enum'
  )
  t.is(
    shieldNote!.masterPublicKey,
    masterPublicKey,
    'should set masterPublicKey from parameter, not shieldKey'
  )
})

test('shield-note - fromShieldCommitment returns null for wrong key', async (t) => {
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
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC20',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedBundle: [ciphertext.data[0]!, ciphertext.data[1]!, ivTag],
    shieldKey,
  }

  // Try to decrypt with a different private key
  const wrongPrivateKey = randomBytes(32)
  const result = await ShieldNote.fromShieldCommitment(commitment, wrongPrivateKey, 99999n)

  t.is(result, null, 'should return null when decryption fails')
})

test('shield-note - fromGeneratedCommitment ERC1155 token type conversion', async (t) => {
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 100n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC1155',
        tokenSubID: hexToUint8Array(
          '0x0000000000000000000000000000000000000000000000000000000000000005'
        ),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  const shieldNote = ShieldNote.fromGeneratedCommitment(commitment, 1n)

  t.is(
    shieldNote.tokenData.tokenType,
    2,
    'should convert ERC1155 string to enum'
  )
})

test('shield-note - fromGeneratedCommitment missing random throws', async (t) => {
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'ERC20',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [] as Uint8Array[],
  }

  t.exception(() => {
    ShieldNote.fromGeneratedCommitment(commitment, 1n)
  }, 'should throw when random data is missing')
})

test('shield-note - fromGeneratedCommitment invalid tokenType throws', async (t) => {
  const commitment = {
    hash: new Uint8Array(32),
    treeNumber: 0,
    treePosition: 0,
    preimage: {
      npk: hexToUint8Array('0x' + 'ab'.repeat(32)),
      value: 5000n,
      token: {
        id: new Uint8Array(32),
        tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
        tokenType: 'INVALID',
        tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
      },
    },
    encryptedRandom: [hexToUint8Array('0x' + 'cd'.repeat(16))],
  }

  t.exception(() => {
    ShieldNote.fromGeneratedCommitment(commitment, 1n)
  }, 'should throw for invalid token type string')
})

test('transact-note - create TransactNote', async (t) => {
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
  t.is(
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
  const deserialized = await TransactNote.deserialize(
    serialized,
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    mockTokenDataGetter
  )

  t.is(deserialized.value, TEST_VALUE, 'should preserve value')
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

test('transact-note - fromCommitment', async (t) => {
  const random = TEST_RANDOM
  const npk = TEST_NPK
  const value = TEST_VALUE
  const receiverAddressData = {
    masterPublicKey: BigInt('123456789012345678901234567890'),
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
  const receiverAddressData = {
    masterPublicKey: BigInt('111'),
    viewingPublicKey: new Uint8Array(32),
  }
  const senderAddressData = {
    masterPublicKey: BigInt('222'),
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
  t.is(
    transactNote.senderAddressData!.masterPublicKey,
    BigInt('222'),
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
    receiverAddressData,
    undefined,
    undefined,
    undefined,
    undefined,
    'legacy memo',
    undefined,
    100
  )

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
  t.is(
    deserialized.receiverAddressData.masterPublicKey,
    receiverAddressData.masterPublicKey,
    'should preserve receiver masterPublicKey through bech32 roundtrip'
  )
})

test('unshield-note - create UnshieldNote', async (t) => {
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

test('unshield-note - fromUnshield ERC20', async (t) => {
  const unshieldData = {
    actionType: ActionType.Unshield,
    to: hexToUint8Array('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'),
    token: {
      id: new Uint8Array(32),
      tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
      tokenType: 'ERC20',
      tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
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
      tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
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
      tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
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
      tokenAddress: hexToUint8Array(TEST_TOKEN_ADDRESS),
      tokenType: 'INVALID',
      tokenSubID: hexToUint8Array(TEST_TOKEN_SUB_ID_ZERO),
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

test('decrypt-commitment - decryptCommitment with invalid key returns null', async (t) => {
  const ciphertext = {
    iv: randomBytes(16),
    tag: randomBytes(16),
    data: [randomBytes(100)],
  }
  const blindedViewingKey = randomBytes(32)
  const viewingPrivateKey = randomBytes(32)

  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedViewingKey,
    viewingPrivateKey,
    mockTokenDataGetter
  )

  t.is(result, null, 'should return null for invalid decryption')
})

test('decrypt-commitment - decryptCommitmentAsReceiverOrSender with invalid keys returns null', async (t) => {
  const ciphertext = {
    iv: randomBytes(16),
    tag: randomBytes(16),
    data: [randomBytes(100)],
  }
  const blindedReceiverKey = randomBytes(32)
  const blindedSenderKey = randomBytes(32)
  const viewingPrivateKey = randomBytes(32)

  const result = await decryptCommitmentAsReceiverOrSender(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverKey,
    blindedSenderKey,
    viewingPrivateKey,
    mockTokenDataGetter
  )

  t.is(result.receiverData, null, 'should return null receiver data when unable to decrypt')
  t.is(result.senderData, null, 'should return null sender data when unable to decrypt')
})

test('decrypt-commitment - decryptCommitment successful roundtrip', async (t) => {
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

  // Build plaintext data:
  //   [0]: Encoded Master Public Key
  //   [1]: Token hash
  //   [2]: Random (16 bytes) + Value (16 bytes)
  const encodedMPK = randomBytes(32)
  const tokenHash = randomBytes(32)
  const noteRandom = randomBytes(16)
  const value = bigintToUint8Array(TEST_VALUE, 16)

  const randomValue = new Uint8Array(32)
  randomValue.set(noteRandom, 0)
  randomValue.set(value, 16)

  // Encrypt using the shared key derived from viewingPrivateKey + blindedReceiverViewingKey
  const sharedKey = await getSharedSymmetricKey(
    viewingPrivateKey,
    blindedReceiverViewingKey
  )
  t.ok(sharedKey, 'should generate shared key')

  const ciphertext = AES.encryptGCM([encodedMPK, tokenHash, randomValue], sharedKey!)

  // Now decrypt using the same viewingPrivateKey + blindedReceiverViewingKey
  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverViewingKey,
    viewingPrivateKey,
    mockTokenDataGetter
  )

  t.ok(result !== null, 'should successfully decrypt')
  t.is(result!.random, uint8ArrayToHex(noteRandom), 'should recover random')
  t.is(result!.encodedMPK, uint8ArrayToHex(encodedMPK), 'should recover encodedMPK')
  t.is(result!.value, TEST_VALUE, 'should recover value')
  t.ok(result!.tokenData, 'should have tokenData')
})

test('decrypt-commitment - decryptCommitmentAsReceiverOrSender identifies receiver', async (t) => {
  // Receiver's key pair
  const viewingPrivateKey = randomBytes(32)
  const viewingPublicKey = getPublicViewingKey(viewingPrivateKey)

  // Sender's key pair
  const senderPrivateKey = randomBytes(32)
  const senderPublicKey = getPublicViewingKey(senderPrivateKey)

  const sharedRandom = randomBytes(32)
  const senderRandom = new Uint8Array(32)

  const { blindedReceiverViewingKey, blindedSenderViewingKey } = getNoteBlindingKeys(
    senderPublicKey,
    viewingPublicKey,
    sharedRandom,
    senderRandom
  )

  const mpk = randomBytes(32)
  const tHash = randomBytes(32)
  const randomValue = new Uint8Array(32)
  randomValue.set(randomBytes(16), 0) // random
  randomValue.set(bigintToUint8Array(TEST_VALUE, 16), 16) // value

  // Sender encrypts using their private key + the receiver's blinded key
  const senderSharedKey = await getSharedSymmetricKey(
    senderPrivateKey,
    blindedReceiverViewingKey
  )
  const ciphertext = AES.encryptGCM([mpk, tHash, randomValue], senderSharedKey!)

  // Receiver decrypts: ECDH uses the sender's blinded key to derive the same shared secret
  const result = await decryptCommitmentAsReceiverOrSender(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverViewingKey,
    blindedSenderViewingKey,
    viewingPrivateKey,
    mockTokenDataGetter
  )

  t.ok(result.receiverData !== null, 'should decrypt as receiver')
  t.is(result.senderData, null, 'should not decrypt as sender')
  t.is(result.receiverData!.value, TEST_VALUE, 'should recover value')
})

test('memo - annotation data roundtrip for all output types', async (t) => {
  const viewingPrivateKey = randomBytes(32)
  const senderRandom = '112233445566778899aabbccddeeff' // 15 bytes = 30 hex chars

  for (const outputType of [OutputType.Transfer, OutputType.BroadcasterFee, OutputType.Change]) {
    const encrypted = Memo.encryptAnnotationData(
      outputType,
      senderRandom,
      'test',
      viewingPrivateKey
    )
    const decrypted = Memo.decryptAnnotationData(encrypted, viewingPrivateKey)
    t.ok(decrypted !== undefined, `should decrypt outputType ${outputType}`)
    t.is(decrypted!.outputType, outputType, `should recover outputType ${outputType}`)
  }
})

test('decrypt-commitment - real-world two-party encrypt/decrypt', async (t) => {
  // Simulate a real transact commitment:
  // Sender creates a note for the receiver with known token data

  // Sender's key pair
  const senderPrivateKey = randomBytes(32)
  const senderPublicKey = getPublicViewingKey(senderPrivateKey)

  // Receiver's key pair
  const receiverPrivateKey = randomBytes(32)
  const receiverPublicKey = getPublicViewingKey(receiverPrivateKey)

  // Blinding keys (created during transaction)
  const sharedRandom = randomBytes(32)
  const senderRandom = randomBytes(32)
  const { blindedSenderViewingKey, blindedReceiverViewingKey } = getNoteBlindingKeys(
    senderPublicKey,
    receiverPublicKey,
    sharedRandom,
    senderRandom
  )

  // Note data
  const masterPublicKey = randomBytes(32)
  const tokenHash = hexToUint8Array(computeTokenHash(ERC20_TOKEN_DATA))
  const noteRandom = randomBytes(16)
  const noteValue = 500000000n

  // Build the 3-element plaintext per engine format:
  //   [0]: Encoded Master Public Key (32 bytes)
  //   [1]: Token hash (32 bytes)
  //   [2]: Random (16 bytes) + Value (16 bytes)
  const randomValueBlock = new Uint8Array(32)
  randomValueBlock.set(noteRandom, 0)
  randomValueBlock.set(bigintToUint8Array(noteValue, 16), 16)

  // Sender encrypts for receiver: ECDH(senderPrivateKey, blindedReceiverViewingKey)
  const senderSharedKey = await getSharedSymmetricKey(senderPrivateKey, blindedReceiverViewingKey)
  t.ok(senderSharedKey, 'sender should derive shared key')
  const ciphertext = AES.encryptGCM(
    [masterPublicKey, tokenHash, randomValueBlock],
    senderSharedKey!
  )

  // Receiver decrypts: ECDH(receiverPrivateKey, blindedSenderViewingKey)
  // These produce the same shared secret due to ECDH commutativity
  const receiverResult = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedSenderViewingKey,
    receiverPrivateKey,
    mockTokenDataGetter
  )

  t.ok(receiverResult !== null, 'receiver should decrypt successfully')
  t.is(receiverResult!.encodedMPK, uint8ArrayToHex(masterPublicKey), 'should recover MPK')
  t.ok(receiverResult!.tokenData, 'should recover token data')
  t.is(receiverResult!.random, uint8ArrayToHex(noteRandom), 'should recover random')
  t.is(receiverResult!.value, noteValue, 'should recover value')

  // Sender can also decrypt using receiver's blinded key
  const senderResult = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverViewingKey,
    senderPrivateKey,
    mockTokenDataGetter
  )
  t.ok(senderResult !== null, 'sender should also decrypt successfully')
  t.is(senderResult!.value, noteValue, 'sender should recover same value')

  // A third party with a different key should NOT be able to decrypt
  const thirdPartyKey = randomBytes(32)
  const thirdPartyResult = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedSenderViewingKey,
    thirdPartyKey,
    mockTokenDataGetter
  )
  t.is(thirdPartyResult, null, 'third party should not decrypt')

  // Full decryptCommitmentAsReceiverOrSender from receiver's perspective
  const fullResult = await decryptCommitmentAsReceiverOrSender(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverViewingKey,
    blindedSenderViewingKey,
    receiverPrivateKey,
    mockTokenDataGetter
  )
  t.ok(fullResult.receiverData !== null, 'receiver data should be present')
  t.is(fullResult.receiverData!.value, noteValue, 'receiver should recover value via full function')
  t.is(fullResult.senderData, null, 'receiver should not appear as sender')
})

test('decrypt-commitment - full pipeline from hex struct through formatCommitmentCiphertext', async (t) => {
  // Sender's key pair
  const senderPrivateKey = randomBytes(32)
  const senderPublicKey = getPublicViewingKey(senderPrivateKey)

  // Receiver's key pair
  const receiverPrivateKey = randomBytes(32)
  const receiverPublicKey = getPublicViewingKey(receiverPrivateKey)

  // Blinding keys
  const sharedRandom = randomBytes(32)
  const senderRandom = randomBytes(32)
  const { blindedSenderViewingKey, blindedReceiverViewingKey } = getNoteBlindingKeys(
    senderPublicKey,
    receiverPublicKey,
    sharedRandom,
    senderRandom
  )

  // Note data
  const masterPublicKey = randomBytes(32)
  const tokenHash = hexToUint8Array(computeTokenHash(ERC20_TOKEN_DATA))
  const noteRandom = randomBytes(16)
  const noteValue = 1000000n

  const randomValueBlock = new Uint8Array(32)
  randomValueBlock.set(noteRandom, 0)
  randomValueBlock.set(bigintToUint8Array(noteValue, 16), 16)

  // Sender encrypts
  const senderSharedKey = await getSharedSymmetricKey(senderPrivateKey, blindedReceiverViewingKey)
  t.ok(senderSharedKey, 'should derive shared key')
  const ciphertext = AES.encryptGCM([masterPublicKey, tokenHash, randomValueBlock], senderSharedKey!)

  // Convert to on-chain hex format (simulating raw TransactionStructV2 data)
  const ivTagHex = uint8ArrayToHex(ciphertext.iv, false) + uint8ArrayToHex(ciphertext.tag, false)
  const struct: CommitmentCiphertextStruct = {
    ciphertext: [
      '0x' + ivTagHex.padStart(64, '0'),
      ...ciphertext.data.map(d => uint8ArrayToHex(d)),
    ],
    blindedSenderViewingKey: uint8ArrayToHex(blindedSenderViewingKey),
    blindedReceiverViewingKey: uint8ArrayToHex(blindedReceiverViewingKey),
    annotationData: '0x',
    memo: '0x',
  }

  // Convert through formatCommitmentCiphertext (hex struct → Uint8Array ciphertext)
  const formatted = formatCommitmentCiphertext(struct)

  // Decrypt using receiver's private key
  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    formatted.ciphertext,
    formatted.blindedSenderViewingKey,
    receiverPrivateKey,
    mockTokenDataGetter
  )

  t.ok(result !== null, 'should decrypt successfully through full pipeline')
  t.is(result!.encodedMPK, uint8ArrayToHex(masterPublicKey), 'should recover MPK')
  t.is(result!.random, uint8ArrayToHex(noteRandom), 'should recover random')
  t.is(result!.value, noteValue, 'should recover value')
  t.ok(result!.tokenData, 'should have tokenData')

  // Also test decryptCommitmentAsReceiverOrSender through the full pipeline
  const fullResult = await decryptCommitmentAsReceiverOrSender(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    formatted.ciphertext,
    formatted.blindedReceiverViewingKey,
    formatted.blindedSenderViewingKey,
    receiverPrivateKey,
    mockTokenDataGetter
  )

  t.ok(fullResult.receiverData !== null, 'receiver should decrypt via full pipeline')
  t.is(fullResult.receiverData!.value, noteValue, 'should recover value via full pipeline')
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
