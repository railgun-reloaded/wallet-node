import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { bytesToHex, hexToBytes } from '@railgun-reloaded/bytes'

import {
  adjustBytes25519,
  getBlindingScalar,
  getNoteBlindingKeys,
  getPrivateScalarFromPrivateKey,
  getPublicSpendingKey,
  getPublicViewingKey,
  getRandomScalar,
  getSharedSymmetricKey,
  initializeCryptographyLibs,
  seedToScalar,
  unblindNoteKey,
} from '../src/keys.js'

before(async () => {
  await initializeCryptographyLibs()
  assert.ok(true, 'cryptography libraries initialized')
})

test('keys - getPublicSpendingKey', async () => {
  const privateKey = new Uint8Array(32)
  privateKey.fill(1)

  const publicKey = getPublicSpendingKey(privateKey)

  assert.ok(Array.isArray(publicKey), 'should return an array')
  assert.equal(publicKey.length, 2, 'should return array with 2 elements')
  assert.ok(publicKey[0] instanceof Uint8Array, 'first element should be Uint8Array')
  assert.ok(publicKey[1] instanceof Uint8Array, 'second element should be Uint8Array')
})

test('keys - getPublicSpendingKey error on invalid length', async () => {
  const invalidKey = new Uint8Array(16) // Wrong length

  assert.throws(() => {
    getPublicSpendingKey(invalidKey)
  }, 'should throw error for invalid private key length')
})

test('keys - getPublicViewingKey', async () => {
  const privateViewingKey = new Uint8Array(32)
  privateViewingKey.fill(2)

  const publicViewingKey = getPublicViewingKey(privateViewingKey)

  assert.ok(publicViewingKey instanceof Uint8Array, 'should return Uint8Array')
  assert.equal(publicViewingKey.length, 32, 'should return 32 bytes')
})

test('keys - adjustBytes25519 little endian', async () => {
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    bytes[i] = i
  }

  const adjusted: Uint8Array = adjustBytes25519(bytes, 'le')

  assert.ok(adjusted instanceof Uint8Array, 'should return Uint8Array')
  assert.equal(adjusted.length, 32, 'should return 32 bytes')
  assert.equal(adjusted[0]! & 0b00000111, 0, 'should clear last 3 bits of first byte')
  assert.equal(adjusted[31]! & 0b10000000, 0, 'should clear first bit of last byte')
  assert.equal(adjusted[31]! & 0b01000000, 0b01000000, 'should set second bit of last byte')
})

test('keys - adjustBytes25519 big endian', async () => {
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    bytes[i] = i
  }

  const adjusted: Uint8Array = adjustBytes25519(bytes, 'be')

  assert.ok(adjusted instanceof Uint8Array, 'should return Uint8Array')
  assert.equal(adjusted.length, 32, 'should return 32 bytes')
  assert.equal(adjusted[31]! & 0b00000111, 0, 'should clear last 3 bits of last byte')
  assert.equal(adjusted[0]! & 0b10000000, 0, 'should clear first bit of first byte')
  assert.equal(adjusted[0]! & 0b01000000, 0b01000000, 'should set second bit of first byte')
})

test('keys - adjustBytes25519 error on invalid input', async () => {
  assert.throws(() => {
    adjustBytes25519(new Uint8Array(16), 'le')
  }, 'should throw error for invalid byte length')
})

test('keys - getPrivateScalarFromPrivateKey', async () => {
  const privateKey = new Uint8Array(32)
  privateKey.fill(5)

  const scalar = await getPrivateScalarFromPrivateKey(privateKey)

  assert.ok(scalar instanceof Uint8Array, 'should return Uint8Array')
  assert.equal(scalar.length, 32, 'should return 32 bytes')
})

test('keys - getPrivateScalarFromPrivateKey error on invalid length', async () => {
  await assert.rejects(async () => {
    await getPrivateScalarFromPrivateKey(new Uint8Array(16))
  }, 'should throw error for invalid private key length')
})

test('keys - getRandomScalar', async () => {
  const scalar1 = getRandomScalar()
  const scalar2 = getRandomScalar()

  assert.ok(scalar1 instanceof Uint8Array, 'should return Uint8Array')
  assert.ok(scalar2 instanceof Uint8Array, 'should return Uint8Array')
  assert.notEqual(scalar1, scalar2, 'should generate different random scalars')
})

test('keys - seedToScalar', async () => {
  const seed = new Uint8Array(32)
  seed.fill(10)

  const scalar = seedToScalar(seed)

  assert.ok(scalar instanceof Uint8Array, 'should return Uint8Array')
  assert.equal(scalar.length, 32, 'should return 32 bytes')
})

test('keys - getBlindingScalar', async () => {
  const sharedRandom = new Uint8Array(32)
  sharedRandom.fill(1)

  const senderRandom = new Uint8Array(32)
  senderRandom.fill(2)

  const blindingScalar = getBlindingScalar(sharedRandom, senderRandom)

  assert.equal(typeof blindingScalar, 'bigint', 'should return bigint')
  assert.ok(blindingScalar > 0n, 'should return positive bigint')
})

test('keys - getNoteBlindingKeys', async () => {
  const senderViewingPublicKey = new Uint8Array(32)
  senderViewingPublicKey.fill(1)
  const senderPublicKey = getPublicViewingKey(senderViewingPublicKey)

  const receiverViewingPublicKey = new Uint8Array(32)
  receiverViewingPublicKey.fill(2)
  const receiverPublicKey = getPublicViewingKey(receiverViewingPublicKey)

  const sharedRandom = new Uint8Array(32)
  sharedRandom.fill(3)

  const senderRandom = new Uint8Array(32)
  senderRandom.fill(4)

  const result = getNoteBlindingKeys(
    senderPublicKey,
    receiverPublicKey,
    sharedRandom,
    senderRandom
  )

  assert.ok(result.blindedSenderViewingKey instanceof Uint8Array, 'should return blinded sender key')
  assert.ok(result.blindedReceiverViewingKey instanceof Uint8Array, 'should return blinded receiver key')
  assert.equal(result.blindedSenderViewingKey.length, 32, 'blinded sender key should be 32 bytes')
  assert.equal(result.blindedReceiverViewingKey.length, 32, 'blinded receiver key should be 32 bytes')
})

test('keys - unblindNoteKey', async () => {
  // Create test keys
  const privateKey = new Uint8Array(32)
  privateKey.fill(1)
  const publicKey = getPublicViewingKey(privateKey)

  const sharedRandom = new Uint8Array(32)
  sharedRandom.fill(3)

  const senderRandom = new Uint8Array(32)
  senderRandom.fill(4)

  // Blind the key
  const privateKey2 = new Uint8Array(32)
  privateKey2.fill(2)
  const publicKey2 = getPublicViewingKey(privateKey2)

  const { blindedReceiverViewingKey } = getNoteBlindingKeys(
    publicKey,
    publicKey2,
    sharedRandom,
    senderRandom
  )

  // Unblind it
  const unblinded = unblindNoteKey(blindedReceiverViewingKey, sharedRandom, senderRandom)

  assert.ok(unblinded instanceof Uint8Array || unblinded === null, 'should return Uint8Array or null')
  if (unblinded) {
    assert.equal(unblinded.length, 32, 'unblinded key should be 32 bytes')
  }
})

test('keys - getSharedSymmetricKey', async () => {
  const privateKeyA = new Uint8Array(32)
  privateKeyA.fill(1)

  const privateKeyB = new Uint8Array(32)
  privateKeyB.fill(2)
  const publicKeyB = getPublicViewingKey(privateKeyB)

  const sharedKey = await getSharedSymmetricKey(privateKeyA, publicKeyB)

  assert.ok(sharedKey instanceof Uint8Array || sharedKey === null, 'should return Uint8Array or null')
  if (sharedKey) {
    assert.equal(sharedKey.length, 32, 'shared key should be 32 bytes')
  }
})

test('keys - initializeCryptographyLibs double-init is idempotent', async () => {
  await initializeCryptographyLibs()
  assert.ok(true, 'second init should not throw')
})

test('keys - getSharedSymmetricKey with invalid public key returns null', async () => {
  const privateKey = new Uint8Array(32).fill(1)
  const invalidPublicKey = new Uint8Array(32).fill(0xff)

  const result = await getSharedSymmetricKey(privateKey, invalidPublicKey)
  assert.equal(result, null, 'should return null for invalid public key')
})

test('keys - unblindNoteKey with invalid point returns null', async () => {
  const invalidPoint = new Uint8Array(32).fill(0xff)
  const sharedRandom = new Uint8Array(32).fill(1)
  const senderRandom = new Uint8Array(32).fill(2)

  const result = unblindNoteKey(invalidPoint, sharedRandom, senderRandom)
  assert.equal(result, null, 'should return null for invalid point')
})

test('keys - getNoteBlindingKeys with same sender/receiver key', async () => {
  const privateKey = new Uint8Array(32).fill(5)
  const publicKey = getPublicViewingKey(privateKey)

  const sharedRandom = new Uint8Array(32).fill(3)
  const senderRandom = new Uint8Array(32).fill(4)

  const result = getNoteBlindingKeys(publicKey, publicKey, sharedRandom, senderRandom)

  assert.ok(result.blindedSenderViewingKey instanceof Uint8Array, 'should return blinded sender key')
  assert.ok(result.blindedReceiverViewingKey instanceof Uint8Array, 'should return blinded receiver key')
  assert.deepEqual(
    result.blindedSenderViewingKey,
    result.blindedReceiverViewingKey,
    'blinded keys should be equal when sender and receiver are the same'
  )
})

test('keys - ECDH shared key commutativity', async () => {
  const { randomBytes } = await import('@noble/hashes/utils')

  const sender = randomBytes(32)
  const senderPublic = getPublicViewingKey(sender)

  const receiver = randomBytes(32)
  const receiverPublic = getPublicViewingKey(receiver)

  const sharedRandom = randomBytes(32)
  const senderRandom = new Uint8Array(32)

  const { blindedSenderViewingKey, blindedReceiverViewingKey } = getNoteBlindingKeys(
    senderPublic,
    receiverPublic,
    sharedRandom,
    senderRandom
  )

  const k1 = await getSharedSymmetricKey(receiver, blindedSenderViewingKey)
  const k2 = await getSharedSymmetricKey(sender, blindedReceiverViewingKey)

  assert.ok(k1, 'receiver should derive shared key')
  assert.ok(k2, 'sender should derive shared key')
  assert.deepEqual(k1, k2, 'ECDH(receiver, blindedSender) should equal ECDH(sender, blindedReceiver)')
})

test('keys - unblind note keys roundtrip', async () => {
  const { randomBytes } = await import('@noble/hashes/utils')

  const sender = randomBytes(32)
  const senderPublic = getPublicViewingKey(sender)

  const receiver = randomBytes(32)
  const receiverPublic = getPublicViewingKey(receiver)

  const sharedRandom = randomBytes(32)
  const senderRandom = new Uint8Array(32)

  const { blindedSenderViewingKey, blindedReceiverViewingKey } = getNoteBlindingKeys(
    senderPublic,
    receiverPublic,
    sharedRandom,
    senderRandom
  )

  const senderUnblinded = unblindNoteKey(blindedSenderViewingKey, sharedRandom, senderRandom)
  const receiverUnblinded = unblindNoteKey(blindedReceiverViewingKey, sharedRandom, senderRandom)

  assert.deepEqual(senderUnblinded, senderPublic, 'unblinded sender key should match original')
  assert.deepEqual(receiverUnblinded, receiverPublic, 'unblinded receiver key should match original')
})

test('keys - sender random blinding distinction', async () => {
  const { randomBytes } = await import('@noble/hashes/utils')

  const sender = randomBytes(32)
  const senderPublic = getPublicViewingKey(sender)

  const receiver = randomBytes(32)
  const receiverPublic = getPublicViewingKey(receiver)

  const sharedRandom = randomBytes(32)
  const senderRandom = randomBytes(32)

  const { blindedSenderViewingKey, blindedReceiverViewingKey } = getNoteBlindingKeys(
    senderPublic,
    receiverPublic,
    sharedRandom,
    senderRandom
  )

  const senderUnblindedWrongRandom = unblindNoteKey(
    blindedSenderViewingKey,
    sharedRandom,
    new Uint8Array(32)
  )
  const senderUnblindedCorrectRandom = unblindNoteKey(
    blindedSenderViewingKey,
    sharedRandom,
    senderRandom
  )
  const receiverUnblindedWrongRandom = unblindNoteKey(
    blindedReceiverViewingKey,
    sharedRandom,
    new Uint8Array(32)
  )
  const receiverUnblindedCorrectRandom = unblindNoteKey(
    blindedReceiverViewingKey,
    sharedRandom,
    senderRandom
  )

  assert.notEqual(senderUnblindedWrongRandom, null, 'wrong random still produces a key')
  assert.notDeepEqual(senderUnblindedWrongRandom, senderPublic, 'wrong random should not recover sender key')
  assert.deepEqual(senderUnblindedCorrectRandom, senderPublic, 'correct random should recover sender key')
  assert.notDeepEqual(receiverUnblindedWrongRandom, receiverPublic, 'wrong random should not recover receiver key')
  assert.deepEqual(receiverUnblindedCorrectRandom, receiverPublic, 'correct random should recover receiver key')
})

test('keys - getSharedSymmetricKey known vector', async () => {
  const privateKeyA = hexToBytes('0123456789012345678901234567890123456789012345678901234567891234')
  const blindedPubKeyB = hexToBytes('0987654321098765432109876543210987654321098765432109876543210987')

  const result = await getSharedSymmetricKey(privateKeyA, blindedPubKeyB)
  assert.ok(result, 'should produce a shared key')
  assert.equal(
    bytesToHex(result!),
    'fbb71adfede43b8a756939500c810d85b16cfbead66d126065639c0cec1fea56',
    'shared key should match known vector'
  )
})
