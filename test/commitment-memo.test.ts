import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { randomBytes } from '@noble/hashes/utils'
import { bigIntToBytes, hexToBytes, stripHexPrefix } from '@railgun-reloaded/bytes'
import { AES } from '@railgun-reloaded/cryptography'

import {
  getNoteBlindingKeys,
  getPublicViewingKey,
  getSharedSymmetricKey,
  initializeCryptographyLibs,
} from '../src/keys.js'
import { decryptCommitment } from '../src/notes/commitment.js'
import type { TokenDataGetter } from '../src/notes/definitions.js'
import { ChainType, TXIDVersion } from '../src/notes/definitions.js'

const TEST_CHAIN = { type: ChainType.EVM, id: 11155111 }
const EMPTY_MEMO = new Uint8Array(0)

const mockTokenDataGetter: TokenDataGetter = {
  /**
   * Resolves token data from a token hash by treating its last 20 bytes as an ERC20 address.
   * @param _txidVersion - Unused TXID version (test stub).
   * @param _chain - Unused chain identifier (test stub).
   * @param tokenHash - Hex token hash whose trailing 20 bytes form the token address.
   * @returns The resolved token data for the hash.
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
})

/**
 * Builds a V2 commitment ciphertext for the given memo, splitting the memo block
 * off the wire data while keeping it under the shared GCM tag.
 * @param memoPlaintext - Memo bytes to include; an empty array omits the memo.
 * @returns The ciphertext, the separated wire memo, and the keys needed to decrypt it.
 */
async function buildCiphertextWithOptionalMemo (memoPlaintext: Uint8Array): Promise<{
  ciphertext: { iv: Uint8Array, tag: Uint8Array, data: Uint8Array[] }
  wireMemo: Uint8Array
  blindedSenderViewingKey: Uint8Array
  receiverPrivateKey: Uint8Array
}> {
  const senderPrivateKey = randomBytes(32)
  const senderPublicKey = getPublicViewingKey(senderPrivateKey)
  const receiverPrivateKey = randomBytes(32)
  const receiverPublicKey = getPublicViewingKey(receiverPrivateKey)

  const { blindedReceiverViewingKey, blindedSenderViewingKey } = getNoteBlindingKeys(
    senderPublicKey,
    receiverPublicKey,
    randomBytes(32),
    new Uint8Array(32)
  )

  const mpk = randomBytes(32)
  const tokenHash = randomBytes(32)
  const randomValue = new Uint8Array(32)
  randomValue.set(randomBytes(16), 0)
  randomValue.set(bigIntToBytes(123456789n, 16), 16)

  const sharedKey = await getSharedSymmetricKey(senderPrivateKey, blindedReceiverViewingKey)
  assert.ok(sharedKey)

  // The contract V2 layout: sender computes one GCM tag over
  // (mpk, tokenHash, randomValue [+memo when provided]); the wire stores the memo block
  // separately from `ciphertext.data` but as ciphertext bytes (CTR-encrypted, sharing the
  // same tag). Receiver re-appends those ciphertext bytes before decrypting.
  const fullPlaintext = memoPlaintext.length > 0
    ? [mpk, tokenHash, randomValue, memoPlaintext]
    : [mpk, tokenHash, randomValue]
  const fullCiphertext = AES.encryptGCM(fullPlaintext, sharedKey!)
  const trimmedData = memoPlaintext.length > 0 ? fullCiphertext.data.slice(0, 3) : fullCiphertext.data
  const wireMemo = memoPlaintext.length > 0
    ? (fullCiphertext.data[3] as Uint8Array)
    : new Uint8Array(0)
  const ciphertext = { iv: fullCiphertext.iv, tag: fullCiphertext.tag, data: trimmedData }

  return { ciphertext, wireMemo, blindedSenderViewingKey, receiverPrivateKey }
}

test('decryptCommitment succeeds when memo append matches sender-tagged memo', async () => {
  const memoPlaintext = new Uint8Array([0x7a])
  const { ciphertext, wireMemo, blindedSenderViewingKey, receiverPrivateKey } =
    await buildCiphertextWithOptionalMemo(memoPlaintext)

  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedSenderViewingKey,
    receiverPrivateKey,
    wireMemo,
    mockTokenDataGetter
  )
  assert.ok(result !== null, 'memo-aware decrypt should succeed for memo-tagged ciphertext')
})

test('decryptCommitment returns null when memo is omitted but sender tagged with one', async () => {
  const memoPlaintext = new Uint8Array([0x7a])
  const { ciphertext, blindedSenderViewingKey, receiverPrivateKey } =
    await buildCiphertextWithOptionalMemo(memoPlaintext)

  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedSenderViewingKey,
    receiverPrivateKey,
    EMPTY_MEMO,
    mockTokenDataGetter
  )
  assert.equal(result, null, 'omitting memo append should fail GCM auth')
})

test('decryptCommitment succeeds when memo is empty and sender tagged without one', async () => {
  // Contract emits a "no memo" sentinel that the scanner flattens to empty.
  // Sender never appended memo bytes to the GCM input, so receiver must not either.
  const { ciphertext, blindedSenderViewingKey, receiverPrivateKey } =
    await buildCiphertextWithOptionalMemo(EMPTY_MEMO)

  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedSenderViewingKey,
    receiverPrivateKey,
    EMPTY_MEMO,
    mockTokenDataGetter
  )
  assert.ok(result !== null, 'empty-memo decrypt should succeed for memoless ciphertext')
})

test('decryptCommitment returns null when memo append is wrong length', async () => {
  const memoPlaintext = new Uint8Array([0x7a])
  const { ciphertext, blindedSenderViewingKey, receiverPrivateKey } =
    await buildCiphertextWithOptionalMemo(memoPlaintext)

  const wrongMemo = new Uint8Array([0x7a, 0x00])
  const result = await decryptCommitment(
    TXIDVersion.V2_PoseidonMerkle,
    TEST_CHAIN,
    ciphertext,
    blindedSenderViewingKey,
    receiverPrivateKey,
    wrongMemo,
    mockTokenDataGetter
  )
  assert.equal(result, null, 'wrong memo bytes should fail GCM auth')
})
