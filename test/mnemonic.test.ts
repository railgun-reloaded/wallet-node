import { test } from 'brittle'

import { Mnemonic } from '../src/mnemonic'
import { childKeyDerivationHardened, getMasterKeyFromSeed, getPathSegments } from '../src/wallet/bip32'

test('bip39 - Mnemonic.generate', (t) => {
  const mnemonic128 = Mnemonic.generate(128)
  t.is(typeof mnemonic128, 'string', 'should return a string')
  t.is(mnemonic128.split(' ').length, 12, 'should generate 12 words for 128-bit entropy')

  const mnemonic192 = Mnemonic.generate(192)
  t.is(mnemonic192.split(' ').length, 18, 'should generate 18 words for 192-bit entropy')

  const mnemonic256 = Mnemonic.generate(256)
  t.is(mnemonic256.split(' ').length, 24, 'should generate 24 words for 256-bit entropy')
})

test('bip39 - Mnemonic.validate', (t) => {
  const validMnemonic = 'test test test test test test test test test test test junk'
  t.ok(Mnemonic.validate(validMnemonic), 'should validate correct mnemonic')

  const invalidMnemonic = 'invalid mnemonic phrase that should not work'
  t.absent(Mnemonic.validate(invalidMnemonic), 'should not validate incorrect mnemonic')

  const emptyMnemonic = ''
  t.absent(Mnemonic.validate(emptyMnemonic), 'should not validate empty string')
})

test('bip39 - Mnemonic.toSeed', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const seed = Mnemonic.toSeed(mnemonic)

  t.ok(seed instanceof Uint8Array, 'should return Uint8Array')
  t.is(seed.length, 64, 'should return 64 bytes')

  // Test with password
  const seedWithPassword = Mnemonic.toSeed(mnemonic, 'password123')
  t.ok(seedWithPassword instanceof Uint8Array, 'should return Uint8Array with password')
  t.not(seed, seedWithPassword, 'should generate different seed with password')
})

test('bip39 - Mnemonic.toSeed deterministic', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const seed1 = Mnemonic.toSeed(mnemonic)
  const seed2 = Mnemonic.toSeed(mnemonic)

  t.alike(seed1, seed2, 'should generate same seed from same mnemonic')
})

test('bip39 - Mnemonic.toEntropy and fromEntropy', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const entropy = Mnemonic.toEntropy(mnemonic)

  t.ok(entropy instanceof Uint8Array, 'should return Uint8Array')
  t.ok(entropy.length >= 16, 'entropy should be at least 16 bytes')

  const recoveredMnemonic = Mnemonic.fromEntropy(entropy)
  t.is(recoveredMnemonic, mnemonic, 'should recover same mnemonic from entropy')
})

test('bip39 - Mnemonic.to0xPrivateKey', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const privateKey = Mnemonic.to0xPrivateKey(mnemonic)

  t.ok(privateKey instanceof Uint8Array, 'should return Uint8Array')
  t.is(privateKey.length, 32, 'should return 32 bytes')
})

test('bip39 - Mnemonic.to0xPrivateKey with derivation index', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const privateKey0 = Mnemonic.to0xPrivateKey(mnemonic, 0)
  const privateKey1 = Mnemonic.to0xPrivateKey(mnemonic, 1)

  t.not(privateKey0, privateKey1, 'should generate different keys for different indices')
})

test('bip39 - Mnemonic.to0xPrivateKey deterministic', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const privateKey1 = Mnemonic.to0xPrivateKey(mnemonic, 0)
  const privateKey2 = Mnemonic.to0xPrivateKey(mnemonic, 0)

  t.alike(privateKey1, privateKey2, 'should generate same key from same mnemonic and index')
})

test('bip32 - getPathSegments', (t) => {
  const path1 = "m/44'/0'/0'"
  const segments1 = getPathSegments(path1)
  t.alike(segments1, [44, 0, 0], 'should parse simple path correctly')

  const path2 = "m/44'/1984'/0'/0'/5'"
  const segments2 = getPathSegments(path2)
  t.alike(segments2, [44, 1984, 0, 0, 5], 'should parse complex path correctly')
})

test('bip32 - getPathSegments invalid path', (t) => {
  t.exception(() => {
    getPathSegments('invalid/path')
  }, 'should throw error for invalid path')

  t.exception(() => {
    getPathSegments('m/44/0/0')
  }, 'should throw error for non-hardened path')
})

test('bip32 - getMasterKeyFromSeed', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const seed = Mnemonic.toSeed(mnemonic)
  const masterKey = getMasterKeyFromSeed(seed)

  t.ok(masterKey.chainKey instanceof Uint8Array, 'should return chainKey as Uint8Array')
  t.ok(masterKey.chainCode instanceof Uint8Array, 'should return chainCode as Uint8Array')
  t.is(masterKey.chainKey.length, 32, 'chainKey should be 32 bytes')
  t.is(masterKey.chainCode.length, 32, 'chainCode should be 32 bytes')
})

test('bip32 - getMasterKeyFromSeed deterministic', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const seed = Mnemonic.toSeed(mnemonic)
  const masterKey1 = getMasterKeyFromSeed(seed)
  const masterKey2 = getMasterKeyFromSeed(seed)

  t.alike(masterKey1.chainKey, masterKey2.chainKey, 'should generate same chainKey')
  t.alike(masterKey1.chainCode, masterKey2.chainCode, 'should generate same chainCode')
})

test('bip32 - childKeyDerivationHardened', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const seed = Mnemonic.toSeed(mnemonic)
  const masterKey = getMasterKeyFromSeed(seed)

  const childKey = childKeyDerivationHardened(masterKey, 0)

  t.ok(childKey.chainKey instanceof Uint8Array, 'should return chainKey as Uint8Array')
  t.ok(childKey.chainCode instanceof Uint8Array, 'should return chainCode as Uint8Array')
  t.is(childKey.chainKey.length, 32, 'chainKey should be 32 bytes')
  t.is(childKey.chainCode.length, 32, 'chainCode should be 32 bytes')
  t.not(childKey.chainKey, masterKey.chainKey, 'child key should differ from parent')
})

test('bip32 - childKeyDerivationHardened different indices', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const seed = Mnemonic.toSeed(mnemonic)
  const masterKey = getMasterKeyFromSeed(seed)

  const childKey0 = childKeyDerivationHardened(masterKey, 0)
  const childKey1 = childKeyDerivationHardened(masterKey, 1)

  t.not(childKey0.chainKey, childKey1.chainKey, 'should generate different keys for different indices')
})

test('bip32 - childKeyDerivationHardened deterministic', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const seed = Mnemonic.toSeed(mnemonic)
  const masterKey = getMasterKeyFromSeed(seed)

  const childKey1 = childKeyDerivationHardened(masterKey, 0)
  const childKey2 = childKeyDerivationHardened(masterKey, 0)

  t.alike(childKey1.chainKey, childKey2.chainKey, 'should generate same key for same index')
  t.alike(childKey1.chainCode, childKey2.chainCode, 'should generate same chainCode for same index')
})

test('bip32 - full derivation path', (t) => {
  const mnemonic = 'test test test test test test test test test test test junk'
  const seed = Mnemonic.toSeed(mnemonic)
  let currentKey = getMasterKeyFromSeed(seed)

  const path = "m/44'/1984'/0'/0'/5'"
  const segments = getPathSegments(path)

  for (const segment of segments) {
    currentKey = childKeyDerivationHardened(currentKey, segment)
  }

  t.ok(currentKey.chainKey instanceof Uint8Array, 'should derive key through full path')
  t.is(currentKey.chainKey.length, 32, 'derived key should be 32 bytes')
})
