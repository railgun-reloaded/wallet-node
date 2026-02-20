import { randomBytes } from '@noble/hashes/utils'
import { AES } from '@railgun-reloaded/cryptography'
import { hook, test } from 'brittle'

import {
  bigintToUint8Array,
  hexToUint8Array,
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
import { ChainType, TXIDVersion } from '../src/notes/definitions'
import { computeTokenHash } from '../src/notes/token-utils'

const TEST_CHAIN = { type: ChainType.EVM, id: 1 }
const TEST_VALUE = 1000000000000000000n // 1 ETH

const TEST_TOKEN_ADDRESS = '0x1234567890123456789012345678901234567890'
const TEST_TOKEN_SUB_ID_ZERO =
  '0x0000000000000000000000000000000000000000000000000000000000000000'

const ERC20_TOKEN_DATA = {
  tokenType: 0,
  tokenAddress: TEST_TOKEN_ADDRESS,
  tokenSubID: TEST_TOKEN_SUB_ID_ZERO,
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
    const cleanHash = tokenHash.startsWith('0x') ? tokenHash.slice(2) : tokenHash
    const address = '0x' + cleanHash.slice(24) // last 20 bytes
    return {
      tokenType: 0,
      tokenAddress: address,
      tokenSubID: '0x0000000000000000000000000000000000000000000000000000000000000000',
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

test('commitment - formatCommitmentCiphertext parses V2 ciphertext', (t) => {
  const struct: CommitmentCiphertextStruct = {
    ciphertext: [
      '0xba002e1e01f1d63d7fa06c83880b2bef23063903d3f4a2b8f7eb800f6c45491c',
      '0x8687c2941bddfc807aa3512ebef36e889a82f3885383877e55b7f86e488b6360',
      '0x40521d04c766273db030a1ee070706493383f26b8fd677cb51acf0fd30682a37',
      '0x6588e860594d6709193c391b4e79de12cecdaed31eef71a2894af5729c0209f7',
    ],
    blindedSenderViewingKey:
      '0x2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc',
    blindedReceiverViewingKey:
      '0x2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc',
    annotationData:
      '0x3f5ff6e7bab3653afd46501dac3d55bd72b33355e41bfc02fcd63a78fe9d5da550957fabde36c9ded90126755f80a3fa3cdd0d84be4686c4192e920d85dd',
    memo: '0x',
  }

  const result = formatCommitmentCiphertext(struct)

  // iv = first 16 bytes of ciphertext[0]
  t.is(
    uint8ArrayToHex(result.ciphertext.iv, false),
    'ba002e1e01f1d63d7fa06c83880b2bef',
    'iv should be first 16 bytes of ciphertext[0]'
  )

  // tag = last 16 bytes of ciphertext[0]
  t.is(
    uint8ArrayToHex(result.ciphertext.tag, false),
    '23063903d3f4a2b8f7eb800f6c45491c',
    'tag should be last 16 bytes of ciphertext[0]'
  )

  // data = remaining ciphertext elements
  t.is(result.ciphertext.data.length, 3, 'should have 3 data blocks')
  t.is(
    uint8ArrayToHex(result.ciphertext.data[0]!, false),
    '8687c2941bddfc807aa3512ebef36e889a82f3885383877e55b7f86e488b6360',
    'data[0] should match ciphertext[1]'
  )
  t.is(
    uint8ArrayToHex(result.ciphertext.data[1]!, false),
    '40521d04c766273db030a1ee070706493383f26b8fd677cb51acf0fd30682a37',
    'data[1] should match ciphertext[2]'
  )
  t.is(
    uint8ArrayToHex(result.ciphertext.data[2]!, false),
    '6588e860594d6709193c391b4e79de12cecdaed31eef71a2894af5729c0209f7',
    'data[2] should match ciphertext[3]'
  )

  // blinded keys
  t.is(
    uint8ArrayToHex(result.blindedSenderViewingKey, false),
    '2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc',
    'should parse blinded sender viewing key'
  )
  t.is(
    uint8ArrayToHex(result.blindedReceiverViewingKey, false),
    '2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc',
    'should parse blinded receiver viewing key'
  )

  // annotation data preserved
  t.is(
    uint8ArrayToHex(result.annotationData, false),
    '3f5ff6e7bab3653afd46501dac3d55bd72b33355e41bfc02fcd63a78fe9d5da550957fabde36c9ded90126755f80a3fa3cdd0d84be4686c4192e920d85dd',
    'should preserve annotation data'
  )

  // empty memo
  t.is(result.memo.length, 0, 'empty memo should produce empty Uint8Array')
})

test('commitment - formatCommitmentCiphertext throws on empty ciphertext', (t) => {
  const struct: CommitmentCiphertextStruct = {
    ciphertext: [],
    blindedSenderViewingKey: '0x00',
    blindedReceiverViewingKey: '0x00',
    annotationData: '0x',
    memo: '0x',
  }

  t.exception(() => {
    formatCommitmentCiphertext(struct)
  }, 'should throw when ciphertext array is empty')
})

test('commitment - formatCommitmentCiphertext pads short hex values', (t) => {
  const struct: CommitmentCiphertextStruct = {
    ciphertext: [
      '0xaabb',
      '0xccdd',
    ],
    blindedSenderViewingKey: '0xff',
    blindedReceiverViewingKey: '0xee',
    annotationData: '0x',
    memo: '0x',
  }

  const result = formatCommitmentCiphertext(struct)

  // Short ciphertext[0] should be left-padded to 32 bytes
  t.is(result.ciphertext.iv.length, 16, 'iv should be 16 bytes')
  t.is(result.ciphertext.tag.length, 16, 'tag should be 16 bytes')

  // Short blinded keys should be left-padded to 32 bytes
  t.is(result.blindedSenderViewingKey.length, 32, 'blinded sender key should be 32 bytes')
  t.is(result.blindedReceiverViewingKey.length, 32, 'blinded receiver key should be 32 bytes')
})

test('commitment - decryptCommitment with invalid key returns null', async (t) => {
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

test('commitment - decryptCommitmentAsReceiverOrSender with invalid keys returns null', async (t) => {
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

test('commitment - decryptCommitment successful roundtrip', async (t) => {
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

test('commitment - decryptCommitmentAsReceiverOrSender identifies receiver', async (t) => {
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

test('commitment - real-world two-party encrypt/decrypt', async (t) => {
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
  const tokenHash = computeTokenHash(ERC20_TOKEN_DATA)
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

  const tokenHashBytes = hexToUint8Array(tokenHash)
  const ciphertext = AES.encryptGCM(
    [masterPublicKey, tokenHashBytes, randomValueBlock],
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

test('commitment - full pipeline from hex struct through formatCommitmentCiphertext', async (t) => {
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
