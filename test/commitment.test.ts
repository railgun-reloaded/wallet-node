import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { randomBytes } from '@noble/hashes/utils.js'
import { bigIntToBytes, bytesToHex, hexToBytes, stripHexPrefix } from '@railgun-reloaded/bytes'
import { AES } from '@railgun-reloaded/cryptography'

import {
  getNoteBlindingKeys,
  getPublicViewingKey,
  getSharedSymmetricKey,
  initializeCryptographyLibs,
} from '../src/keys.js'
import {
  decryptCommitment,
  decryptCommitmentAsReceiverOrSender,
} from '../src/notes/commitment.js'
import type { TokenDataGetter } from '../src/notes/definitions.js'
import { ChainType, TXIDVersion } from '../src/notes/definitions.js'
import { computeTokenHash } from '../src/notes/token-utils.js'

const TEST_CHAIN = { type: ChainType.EVM, id: 1 }
const TEST_VALUE = 1000000000000000000n // 1 ETH
const EMPTY_MEMO = new Uint8Array(0)

const TEST_TOKEN_ADDRESS = hexToBytes('0x1234567890123456789012345678901234567890')

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

test('commitment - decryptCommitment with invalid key returns null', async () => {
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
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.equal(result, null, 'should return null for invalid decryption')
})

test('commitment - decryptCommitmentAsReceiverOrSender with invalid keys returns null', async () => {
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
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.equal(result.receiverData, null, 'should return null receiver data when unable to decrypt')
  assert.equal(result.senderData, null, 'should return null sender data when unable to decrypt')
})

test('commitment - decryptCommitment successful roundtrip', async () => {
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
  const value = bigIntToBytes(TEST_VALUE, 16)

  const randomValue = new Uint8Array(32)
  randomValue.set(noteRandom, 0)
  randomValue.set(value, 16)

  // Encrypt using the shared key derived from viewingPrivateKey + blindedReceiverViewingKey
  const sharedKey = await getSharedSymmetricKey(
    viewingPrivateKey,
    blindedReceiverViewingKey
  )
  assert.ok(sharedKey, 'should generate shared key')

  const ciphertext = AES.encryptGCM([encodedMPK, tokenHash, randomValue], sharedKey!)

  // Now decrypt using the same viewingPrivateKey + blindedReceiverViewingKey
  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverViewingKey,
    viewingPrivateKey,
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.ok(result !== null, 'should successfully decrypt')
  assert.equal(result!.random, bytesToHex(noteRandom, { prefix: true }), 'should recover random')
  assert.equal(result!.encodedMPK, bytesToHex(encodedMPK, { prefix: true }), 'should recover encodedMPK')
  assert.equal(result!.value, TEST_VALUE, 'should recover value')
  assert.ok(result!.tokenData, 'should have tokenData')
})

test('commitment - decryptCommitmentAsReceiverOrSender identifies receiver', async () => {
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
  randomValue.set(bigIntToBytes(TEST_VALUE, 16), 16) // value

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
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.ok(result.receiverData !== null, 'should decrypt as receiver')
  assert.equal(result.senderData, null, 'should not decrypt as sender')
  assert.equal(result.receiverData!.value, TEST_VALUE, 'should recover value')
})

test('commitment - real-world two-party encrypt/decrypt', async () => {
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
  randomValueBlock.set(bigIntToBytes(noteValue, 16), 16)

  // Sender encrypts for receiver: ECDH(senderPrivateKey, blindedReceiverViewingKey)
  const senderSharedKey = await getSharedSymmetricKey(senderPrivateKey, blindedReceiverViewingKey)
  assert.ok(senderSharedKey, 'sender should derive shared key')

  const tokenHashBytes = hexToBytes(tokenHash)
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
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.ok(receiverResult !== null, 'receiver should decrypt successfully')
  assert.equal(receiverResult!.encodedMPK, bytesToHex(masterPublicKey, { prefix: true }), 'should recover MPK')
  assert.ok(receiverResult!.tokenData, 'should recover token data')
  assert.equal(receiverResult!.random, bytesToHex(noteRandom, { prefix: true }), 'should recover random')
  assert.equal(receiverResult!.value, noteValue, 'should recover value')

  // Sender can also decrypt using receiver's blinded key
  const senderResult = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverViewingKey,
    senderPrivateKey,
    EMPTY_MEMO,
    mockTokenDataGetter
  )
  assert.ok(senderResult !== null, 'sender should also decrypt successfully')
  assert.equal(senderResult!.value, noteValue, 'sender should recover same value')

  // A third party with a different key should NOT be able to decrypt
  const thirdPartyKey = randomBytes(32)
  const thirdPartyResult = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedSenderViewingKey,
    thirdPartyKey,
    EMPTY_MEMO,
    mockTokenDataGetter
  )
  assert.equal(thirdPartyResult, null, 'third party should not decrypt')

  // Full decryptCommitmentAsReceiverOrSender from receiver's perspective
  const fullResult = await decryptCommitmentAsReceiverOrSender(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverViewingKey,
    blindedSenderViewingKey,
    receiverPrivateKey,
    EMPTY_MEMO,
    mockTokenDataGetter
  )
  assert.ok(fullResult.receiverData !== null, 'receiver data should be present')
  assert.equal(fullResult.receiverData!.value, noteValue, 'receiver should recover value via full function')
  assert.equal(fullResult.senderData, null, 'receiver should not appear as sender')
})

test('commitment - decryptCommitment with ciphertext data < 3 blocks returns null', async () => {
  const viewingPrivateKey = randomBytes(32)
  const viewingPublicKey = getPublicViewingKey(viewingPrivateKey)

  const senderPrivateKey = randomBytes(32)
  const senderPublicKey = getPublicViewingKey(senderPrivateKey)

  const sharedRandom = randomBytes(32)
  const senderRandom = new Uint8Array(32)

  const { blindedReceiverViewingKey } = getNoteBlindingKeys(
    senderPublicKey,
    viewingPublicKey,
    sharedRandom,
    senderRandom
  )

  const sharedKey = await getSharedSymmetricKey(senderPrivateKey, blindedReceiverViewingKey)
  assert.ok(sharedKey, 'should derive shared key')

  const ciphertext = AES.encryptGCM([randomBytes(32), randomBytes(32)], sharedKey!)

  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverViewingKey,
    viewingPrivateKey,
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.equal(result, null, 'should return null when ciphertext has < 3 data blocks')
})

test('commitment - decryptCommitment with randomValue block < 32 bytes returns null', async () => {
  const viewingPrivateKey = randomBytes(32)
  const viewingPublicKey = getPublicViewingKey(viewingPrivateKey)

  const senderPrivateKey = randomBytes(32)
  const senderPublicKey = getPublicViewingKey(senderPrivateKey)

  const sharedRandom = randomBytes(32)
  const senderRandom = new Uint8Array(32)

  const { blindedReceiverViewingKey } = getNoteBlindingKeys(
    senderPublicKey,
    viewingPublicKey,
    sharedRandom,
    senderRandom
  )

  const sharedKey = await getSharedSymmetricKey(senderPrivateKey, blindedReceiverViewingKey)
  assert.ok(sharedKey, 'should derive shared key')

  const ciphertext = AES.encryptGCM(
    [randomBytes(32), randomBytes(32), randomBytes(16)],
    sharedKey!
  )

  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedReceiverViewingKey,
    viewingPrivateKey,
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.equal(result, null, 'should return null when randomValue block is < 32 bytes')
})

test('commitment - decryptCommitmentAsReceiverOrSender with empty blinded receiver key', async () => {
  const ciphertext = {
    iv: randomBytes(16),
    tag: randomBytes(16),
    data: [randomBytes(100)],
  }

  const result = await decryptCommitmentAsReceiverOrSender(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    new Uint8Array(0),
    randomBytes(32),
    randomBytes(32),
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.equal(result.senderData, null, 'sender data should be null with empty receiver key')
})

test('commitment - decryptCommitmentAsReceiverOrSender with empty blinded sender key', async () => {
  const ciphertext = {
    iv: randomBytes(16),
    tag: randomBytes(16),
    data: [randomBytes(100)],
  }

  const result = await decryptCommitmentAsReceiverOrSender(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    randomBytes(32),
    new Uint8Array(0),
    randomBytes(32),
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.equal(result.receiverData, null, 'receiver data should be null with empty sender key')
})

test('commitment - decryptCommitmentAsReceiverOrSender with both keys empty', async () => {
  const ciphertext = {
    iv: randomBytes(16),
    tag: randomBytes(16),
    data: [randomBytes(100)],
  }

  const result = await decryptCommitmentAsReceiverOrSender(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    new Uint8Array(0),
    new Uint8Array(0),
    randomBytes(32),
    EMPTY_MEMO,
    mockTokenDataGetter
  )

  assert.equal(result.receiverData, null, 'receiver data should be null')
  assert.equal(result.senderData, null, 'sender data should be null')
})
