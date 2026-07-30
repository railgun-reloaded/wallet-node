import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { randomBytes } from '@noble/hashes/utils.js'
import { bytesToHex, hexToBytes } from '@railgun-reloaded/bytes'
import { AES } from '@railgun-reloaded/cryptography'

import {
  getPublicViewingKey,
  initializeCryptographyLibs,
} from '../src/keys.js'
import { ShieldNote } from '../src/notes/shield-note.js'
import type { ShieldRequest } from '../src/notes/shield-request.js'
import { buildShieldRequest } from '../src/notes/shield-request.js'

const TEST_TOKEN_ADDRESS = hexToBytes('0x1234567890123456789012345678901234567890')
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
 * Maps a numeric token type back to the string form used by ShieldCommitment.
 * @param tokenType - The numeric token type (0 = ERC20, 1 = ERC721).
 * @returns The equivalent token type string.
 */
const tokenTypeToString = (tokenType: number): string =>
  tokenType === 1 ? 'ERC721' : 'ERC20'

/**
 * Returns a fixed all-zero IV so encryption is deterministic for the fixture.
 * @returns A 16-byte zero IV.
 */
const pinnedIV = (): Uint8Array => new Uint8Array(16)

/**
 * Wraps a shield request as the ShieldCommitment shape consumed by the decrypt
 * path, so a built request can be round-tripped back through fromShieldCommitment.
 * @param request - The shield request to wrap.
 * @returns A ShieldCommitment-compatible object.
 */
const toShieldCommitment = (request: ShieldRequest) => ({
  hash: new Uint8Array(32),
  treeNumber: 0,
  treePosition: 0,
  preimage: {
    npk: request.preimage.npk,
    value: request.preimage.value,
    token: {
      id: new Uint8Array(32),
      tokenAddress: request.preimage.token.tokenAddress,
      tokenType: tokenTypeToString(request.preimage.token.tokenType),
      tokenSubID: request.preimage.token.tokenSubID,
    },
  },
  encryptedBundle: request.ciphertext.encryptedBundle,
  shieldKey: request.ciphertext.shieldKey,
})

before(async () => {
  await initializeCryptographyLibs()
})

test('buildShieldRequest - round-trips through fromShieldCommitment', async () => {
  const shieldPrivateKey = randomBytes(32)
  const receiverViewingPrivateKey = randomBytes(32)
  const receiverViewingPublicKey = getPublicViewingKey(receiverViewingPrivateKey)
  const masterPublicKey = randomBytes(32)

  const note = new ShieldNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    masterPublicKey,
  })

  const request = await buildShieldRequest(note, shieldPrivateKey, receiverViewingPublicKey)
  const recovered = await ShieldNote.fromShieldCommitment(
    toShieldCommitment(request),
    receiverViewingPrivateKey,
    masterPublicKey
  )

  assert.ok(recovered instanceof ShieldNote, 'should recover a ShieldNote')
  assert.equal(
    recovered!.random,
    bytesToHex(hexToBytes(TEST_RANDOM), { prefix: true }),
    'should recover the original random'
  )
  assert.equal(recovered!.value, TEST_VALUE, 'should recover the original value')
  assert.equal(recovered!.notePublicKey, TEST_NPK, 'should recover the original npk')
  assert.equal(recovered!.tokenData.tokenType, 0, 'should recover the token type')
  assert.deepEqual(
    recovered!.tokenData.tokenAddress,
    TEST_TOKEN_ADDRESS,
    'should recover the token address'
  )
})

test('buildShieldRequest - encrypts the receiver key into bundle[2]', async () => {
  const shieldPrivateKey = randomBytes(32)
  const receiverViewingPrivateKey = randomBytes(32)
  const receiverViewingPublicKey = getPublicViewingKey(receiverViewingPrivateKey)

  const note = new ShieldNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    masterPublicKey: randomBytes(32),
  })

  const request = await buildShieldRequest(note, shieldPrivateKey, receiverViewingPublicKey)

  // bundle[1] = encrypted random (16) + CTR iv (16); bundle[2] = CTR encrypted receiver key (32)
  const ctrIv = request.ciphertext.encryptedBundle[1].slice(16, 32)
  const ctrData = request.ciphertext.encryptedBundle[2]
  const [decrypted] = AES.decryptCTR({ iv: ctrIv, data: [ctrData] }, shieldPrivateKey)

  assert.deepEqual(
    decrypted,
    receiverViewingPublicKey,
    'bundle[2] should decrypt to the receiver viewing public key under the shield private key'
  )
})

test('buildShieldRequest - non-recipient recovers null', async () => {
  const shieldPrivateKey = randomBytes(32)
  const receiverViewingPrivateKey = randomBytes(32)
  const receiverViewingPublicKey = getPublicViewingKey(receiverViewingPrivateKey)

  const note = new ShieldNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: TEST_RANDOM,
    masterPublicKey: randomBytes(32),
  })

  const request = await buildShieldRequest(note, shieldPrivateKey, receiverViewingPublicKey)

  const wrongViewingPrivateKey = randomBytes(32)
  const recovered = await ShieldNote.fromShieldCommitment(
    toShieldCommitment(request),
    wrongViewingPrivateKey,
    randomBytes(32)
  )

  assert.equal(recovered, null, 'should return null for a non-recipient without throwing')
})

// Golden fixture: byte-identical to a node:crypto AES-256 reference with a pinned
// (all-zero) IV. Regenerate by running, from the wallet-node directory, a script
// that: derives receiverViewingPublicKey = getPublicViewingKey('0x'+'22'*32),
// sharedKey = getSharedSymmetricKey('0x'+'11'*32, receiverViewingPublicKey), and
// shieldKey = getPublicViewingKey('0x'+'11'*32); then, with IV = 16 zero bytes,
// AES-256-GCM encrypts the random '0x'+'ab'*16 under sharedKey and AES-256-CTR
// encrypts receiverViewingPublicKey under '0x'+'11'*32; packing
// bundle[0]=iv+tag, bundle[1]=gcmData+iv, bundle[2]=ctrData.
const FIXTURE_SHIELD_PRIVATE_KEY = hexToBytes('0x' + '11'.repeat(32))
const FIXTURE_RECEIVER_VIEWING_PRIVATE_KEY = hexToBytes('0x' + '22'.repeat(32))
const FIXTURE_RANDOM = 'ab'.repeat(16)
const FIXTURE_SHIELD_KEY =
  '0xd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737'
const FIXTURE_BUNDLE_0 =
  '0x000000000000000000000000000000001e1ef675b414e84642060882d902a4a0'
const FIXTURE_BUNDLE_1 =
  '0x01c508af11e64256c5b3d28ce329f6c900000000000000000000000000000000'
const FIXTURE_BUNDLE_2 =
  '0x8076aa3c636376c0899ca99054492321e0393a2bb86f88023a68112ba2d5bfa5'

test('buildShieldRequest - matches node:crypto golden fixture with pinned IV', async () => {
  const receiverViewingPublicKey = getPublicViewingKey(FIXTURE_RECEIVER_VIEWING_PRIVATE_KEY)

  const note = new ShieldNote({
    notePublicKey: TEST_NPK,
    value: TEST_VALUE,
    tokenData: ERC20_TOKEN_DATA,
    random: FIXTURE_RANDOM,
    masterPublicKey: randomBytes(32),
  })

  const originalGetRandomIV = AES.getRandomIV
  AES.getRandomIV = pinnedIV
  let request: ShieldRequest
  try {
    request = await buildShieldRequest(
      note,
      FIXTURE_SHIELD_PRIVATE_KEY,
      receiverViewingPublicKey
    )
  } finally {
    AES.getRandomIV = originalGetRandomIV
  }

  assert.equal(
    bytesToHex(request.ciphertext.shieldKey, { prefix: true }),
    FIXTURE_SHIELD_KEY,
    'shieldKey should match fixture'
  )
  assert.equal(
    bytesToHex(request.ciphertext.encryptedBundle[0], { prefix: true }),
    FIXTURE_BUNDLE_0,
    'bundle[0] should match fixture'
  )
  assert.equal(
    bytesToHex(request.ciphertext.encryptedBundle[1], { prefix: true }),
    FIXTURE_BUNDLE_1,
    'bundle[1] should match fixture'
  )
  assert.equal(
    bytesToHex(request.ciphertext.encryptedBundle[2], { prefix: true }),
    FIXTURE_BUNDLE_2,
    'bundle[2] should match fixture'
  )
})
