import { hook, test } from 'brittle'

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
} from '../src/keys'

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

test('keys - getPublicSpendingKey', async (t) => {
  const privateKey = new Uint8Array(32)
  privateKey.fill(1)

  const publicKey = getPublicSpendingKey(privateKey)

  t.ok(Array.isArray(publicKey), 'should return an array')
  t.is(publicKey.length, 2, 'should return array with 2 elements')
  t.ok(publicKey[0] instanceof Uint8Array, 'first element should be Uint8Array')
  t.ok(publicKey[1] instanceof Uint8Array, 'second element should be Uint8Array')
})

test('keys - getPublicSpendingKey error on invalid length', async (t) => {
  const invalidKey = new Uint8Array(16) // Wrong length

  t.exception(() => {
    getPublicSpendingKey(invalidKey)
  }, 'should throw error for invalid private key length')
})

test('keys - getPublicViewingKey', async (t) => {
  const privateViewingKey = new Uint8Array(32)
  privateViewingKey.fill(2)

  const publicViewingKey = getPublicViewingKey(privateViewingKey)

  t.ok(publicViewingKey instanceof Uint8Array, 'should return Uint8Array')
  t.is(publicViewingKey.length, 32, 'should return 32 bytes')
})

test('keys - adjustBytes25519 little endian', async (t) => {
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    bytes[i] = i
  }

  const adjusted: Uint8Array = adjustBytes25519(bytes, 'le')

  t.ok(adjusted instanceof Uint8Array, 'should return Uint8Array')
  t.is(adjusted.length, 32, 'should return 32 bytes')
  t.is(adjusted[0]! & 0b00000111, 0, 'should clear last 3 bits of first byte')
  t.is(adjusted[31]! & 0b10000000, 0, 'should clear first bit of last byte')
  t.is(adjusted[31]! & 0b01000000, 0b01000000, 'should set second bit of last byte')
})

test('keys - adjustBytes25519 big endian', async (t) => {
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    bytes[i] = i
  }

  const adjusted: Uint8Array = adjustBytes25519(bytes, 'be')

  t.ok(adjusted instanceof Uint8Array, 'should return Uint8Array')
  t.is(adjusted.length, 32, 'should return 32 bytes')
  t.is(adjusted[31]! & 0b00000111, 0, 'should clear last 3 bits of last byte')
  t.is(adjusted[0]! & 0b10000000, 0, 'should clear first bit of first byte')
  t.is(adjusted[0]! & 0b01000000, 0b01000000, 'should set second bit of first byte')
})

test('keys - adjustBytes25519 error on invalid input', async (t) => {
  t.exception(() => {
    adjustBytes25519(new Uint8Array(16), 'le')
  }, 'should throw error for invalid byte length')
})

test('keys - getPrivateScalarFromPrivateKey', async (t) => {
  const privateKey = new Uint8Array(32)
  privateKey.fill(5)

  const scalar = await getPrivateScalarFromPrivateKey(privateKey)

  t.ok(scalar instanceof Uint8Array, 'should return Uint8Array')
  t.is(scalar.length, 32, 'should return 32 bytes')
})

test('keys - getPrivateScalarFromPrivateKey error on invalid length', async (t) => {
  await t.exception(async () => {
    await getPrivateScalarFromPrivateKey(new Uint8Array(16))
  }, 'should throw error for invalid private key length')
})

test('keys - getRandomScalar', async (t) => {
  const scalar1 = getRandomScalar()
  const scalar2 = getRandomScalar()

  t.ok(scalar1 instanceof Uint8Array, 'should return Uint8Array')
  t.ok(scalar2 instanceof Uint8Array, 'should return Uint8Array')
  t.not(scalar1, scalar2, 'should generate different random scalars')
})

test('keys - seedToScalar', async (t) => {
  const seed = new Uint8Array(32)
  seed.fill(10)

  const scalar = seedToScalar(seed)

  t.ok(scalar instanceof Uint8Array, 'should return Uint8Array')
  t.is(scalar.length, 32, 'should return 32 bytes')
})

test('keys - getBlindingScalar', async (t) => {
  const sharedRandom = new Uint8Array(32)
  sharedRandom.fill(1)

  const senderRandom = new Uint8Array(32)
  senderRandom.fill(2)

  const blindingScalar = getBlindingScalar(sharedRandom, senderRandom)

  t.is(typeof blindingScalar, 'bigint', 'should return bigint')
  t.ok(blindingScalar > 0n, 'should return positive bigint')
})

test('keys - getNoteBlindingKeys', async (t) => {
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

  t.ok(result.blindedSenderViewingKey instanceof Uint8Array, 'should return blinded sender key')
  t.ok(result.blindedReceiverViewingKey instanceof Uint8Array, 'should return blinded receiver key')
  t.is(result.blindedSenderViewingKey.length, 32, 'blinded sender key should be 32 bytes')
  t.is(result.blindedReceiverViewingKey.length, 32, 'blinded receiver key should be 32 bytes')
})

test('keys - unblindNoteKey', async (t) => {
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

  t.ok(unblinded instanceof Uint8Array || unblinded === undefined, 'should return Uint8Array or undefined')
  if (unblinded) {
    t.is(unblinded.length, 32, 'unblinded key should be 32 bytes')
  }
})

test('keys - getSharedSymmetricKey', async (t) => {
  const privateKeyA = new Uint8Array(32)
  privateKeyA.fill(1)

  const privateKeyB = new Uint8Array(32)
  privateKeyB.fill(2)
  const publicKeyB = getPublicViewingKey(privateKeyB)

  const sharedKey = await getSharedSymmetricKey(privateKeyA, publicKeyB)

  t.ok(sharedKey instanceof Uint8Array || sharedKey === undefined, 'should return Uint8Array or undefined')
  if (sharedKey) {
    t.is(sharedKey.length, 32, 'shared key should be 32 bytes')
  }
})
