import { randomBytes } from '@noble/hashes/utils'
import { AES } from '@railgun-reloaded/cryptography'
import { hook, test } from 'brittle'

import {
  bigintToUint8Array,
  hexToUint8Array,
  hexlify,
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
} from '../src/notes/commitment'
import type { TokenDataGetter } from '../src/notes/definitions'
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
    const cleanHash = hexlify(tokenHash)
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
