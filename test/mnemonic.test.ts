import { test } from 'brittle'

import { hexToUint8Array, uint8ArrayToHex } from '../src/encoding'
import { Mnemonic } from '../src/mnemonic'
import { childKeyDerivationHardened, getMasterKeyFromSeed, getPathSegments } from '../src/wallet/bip32'

const TEST_MNEMONIC = 'test test test test test test test test test test test junk'
const TEST_SEED = Mnemonic.toSeed(TEST_MNEMONIC)
const TEST_MASTER_KEY = getMasterKeyFromSeed(TEST_SEED)

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
  t.ok(Mnemonic.validate(TEST_MNEMONIC), 'should validate correct mnemonic')

  t.absent(Mnemonic.validate('invalid mnemonic phrase that should not work'), 'should not validate incorrect mnemonic')
  t.absent(Mnemonic.validate(''), 'should not validate empty string')
})

test('bip39 - Mnemonic.toSeed', (t) => {
  const seed = Mnemonic.toSeed(TEST_MNEMONIC)

  t.ok(seed instanceof Uint8Array, 'should return Uint8Array')
  t.is(seed.length, 64, 'should return 64 bytes')

  // Test with password
  const seedWithPassword = Mnemonic.toSeed(TEST_MNEMONIC, 'password123')
  t.ok(seedWithPassword instanceof Uint8Array, 'should return Uint8Array with password')
  t.not(seed, seedWithPassword, 'should generate different seed with password')
})

test('bip39 - Mnemonic.toSeed deterministic', (t) => {
  const seed1 = Mnemonic.toSeed(TEST_MNEMONIC)
  const seed2 = Mnemonic.toSeed(TEST_MNEMONIC)

  t.alike(seed1, seed2, 'should generate same seed from same mnemonic')
})

test('bip39 - Mnemonic.toEntropy and fromEntropy', (t) => {
  const entropy = Mnemonic.toEntropy(TEST_MNEMONIC)

  t.ok(entropy instanceof Uint8Array, 'should return Uint8Array')
  t.ok(entropy.length >= 16, 'entropy should be at least 16 bytes')

  const recoveredMnemonic = Mnemonic.fromEntropy(entropy)
  t.is(recoveredMnemonic, TEST_MNEMONIC, 'should recover same mnemonic from entropy')
})

test('bip39 - Mnemonic.to0xPrivateKey', (t) => {
  const privateKey = Mnemonic.to0xPrivateKey(TEST_MNEMONIC)

  t.ok(privateKey instanceof Uint8Array, 'should return Uint8Array')
  t.is(privateKey.length, 32, 'should return 32 bytes')
})

test('bip39 - Mnemonic.to0xPrivateKey with derivation index', (t) => {
  const privateKey0 = Mnemonic.to0xPrivateKey(TEST_MNEMONIC, 0)
  const privateKey1 = Mnemonic.to0xPrivateKey(TEST_MNEMONIC, 1)

  t.not(privateKey0, privateKey1, 'should generate different keys for different indices')
})

test('bip39 - Mnemonic.to0xPrivateKey deterministic', (t) => {
  const privateKey1 = Mnemonic.to0xPrivateKey(TEST_MNEMONIC, 0)
  const privateKey2 = Mnemonic.to0xPrivateKey(TEST_MNEMONIC, 0)

  t.alike(privateKey1, privateKey2, 'should generate same key from same mnemonic and index')
})

test('bip32 - getPathSegments', (t) => {
  t.alike(getPathSegments("m/44'/0'/0'"), [44, 0, 0], 'should parse simple path correctly')
  t.alike(getPathSegments("m/44'/1984'/0'/0'/5'"), [44, 1984, 0, 0, 5], 'should parse complex path correctly')
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
  t.ok(TEST_MASTER_KEY.chainKey instanceof Uint8Array, 'should return chainKey as Uint8Array')
  t.ok(TEST_MASTER_KEY.chainCode instanceof Uint8Array, 'should return chainCode as Uint8Array')
  t.is(TEST_MASTER_KEY.chainKey.length, 32, 'chainKey should be 32 bytes')
  t.is(TEST_MASTER_KEY.chainCode.length, 32, 'chainCode should be 32 bytes')
})

test('bip32 - getMasterKeyFromSeed deterministic', (t) => {
  const masterKey1 = getMasterKeyFromSeed(TEST_SEED)
  const masterKey2 = getMasterKeyFromSeed(TEST_SEED)

  t.alike(masterKey1.chainKey, masterKey2.chainKey, 'should generate same chainKey')
  t.alike(masterKey1.chainCode, masterKey2.chainCode, 'should generate same chainCode')
})

test('bip32 - childKeyDerivationHardened', (t) => {
  const childKey = childKeyDerivationHardened(TEST_MASTER_KEY, 0)

  t.ok(childKey.chainKey instanceof Uint8Array, 'should return chainKey as Uint8Array')
  t.ok(childKey.chainCode instanceof Uint8Array, 'should return chainCode as Uint8Array')
  t.is(childKey.chainKey.length, 32, 'chainKey should be 32 bytes')
  t.is(childKey.chainCode.length, 32, 'chainCode should be 32 bytes')
  t.not(childKey.chainKey, TEST_MASTER_KEY.chainKey, 'child key should differ from parent')
})

test('bip32 - childKeyDerivationHardened different indices', (t) => {
  const childKey0 = childKeyDerivationHardened(TEST_MASTER_KEY, 0)
  const childKey1 = childKeyDerivationHardened(TEST_MASTER_KEY, 1)

  t.not(childKey0.chainKey, childKey1.chainKey, 'should generate different keys for different indices')
})

test('bip32 - childKeyDerivationHardened deterministic', (t) => {
  const childKey1 = childKeyDerivationHardened(TEST_MASTER_KEY, 0)
  const childKey2 = childKeyDerivationHardened(TEST_MASTER_KEY, 0)

  t.alike(childKey1.chainKey, childKey2.chainKey, 'should generate same key for same index')
  t.alike(childKey1.chainCode, childKey2.chainCode, 'should generate same chainCode for same index')
})

test('bip32 - full derivation path', (t) => {
  let currentKey = getMasterKeyFromSeed(TEST_SEED)

  const segments = getPathSegments("m/44'/1984'/0'/0'/5'")

  for (const segment of segments) {
    currentKey = childKeyDerivationHardened(currentKey, segment)
  }

  t.ok(currentKey.chainKey instanceof Uint8Array, 'should derive key through full path')
  t.is(currentKey.chainKey.length, 32, 'derived key should be 32 bytes')
})

const MNEMONIC_ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const MNEMONIC_MAMMAL = 'mammal step public march absorb critic visa rent miss color erase exhaust south lift ordinary ceiling stay physical'
const MNEMONIC_CULTURE = 'culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich'

const SEED_ABANDON = '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4'
const SEED_MAMMAL = 'd8c228addf9a9cfe5b7934223737815e2f709b3ac12b0c1b2aaec921e5d3a2e8aeea1df817af8159f981798dacd5a930a1fcd8570ba4845078c1b1d09fa060cb'
const SEED_CULTURE = '243c1266228fc9ff370d567ba4f805dfacc516375aecf4657cf870a4b551020d92d9b45a8181154f531c1358f742f42078a1620fca6251b1c4ec5fa6e1cf5c3a'
const SEED_CULTURE_PASSWORD = '87ec3e2ae9294cb5500698e6e6ee8357aa56222badae0e6b4150492c95ede7ddfca27c952afafb388453def93fac72f5d7e099debd79e85c2088f9b3e7a65df6'

const MASTER_KEY_ABANDON = { chainCode: '30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc', chainKey: '1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411' }
const MASTER_KEY_MAMMAL = { chainCode: 'b37268d31994f4bbe422feffb3e1dcb35b61b76c0c1ebea2ded5fb0e37aa0809', chainKey: 'c544e07e1007d25b6a3a7ddba8f1e20c2c23c9baec8e9a6200dd6c3b2f8df6a5' }

test('bip39 - Mnemonic.toSeed known vectors', (t) => {
  t.is(uint8ArrayToHex(Mnemonic.toSeed(MNEMONIC_ABANDON), false), SEED_ABANDON, 'abandon mnemonic seed')
  t.is(uint8ArrayToHex(Mnemonic.toSeed(MNEMONIC_MAMMAL), false), SEED_MAMMAL, 'mammal mnemonic seed')
  t.is(uint8ArrayToHex(Mnemonic.toSeed(MNEMONIC_CULTURE), false), SEED_CULTURE, 'culture mnemonic seed')
  t.is(uint8ArrayToHex(Mnemonic.toSeed(MNEMONIC_CULTURE, 'test'), false), SEED_CULTURE_PASSWORD, 'culture mnemonic seed with password')
})

test('bip39 - Mnemonic.toEntropy known vectors', (t) => {
  const vectors = [
    { mnemonic: MNEMONIC_ABANDON, entropy: '00000000000000000000000000000000' },
    { mnemonic: MNEMONIC_MAMMAL, entropy: '86baaeb443e00c67bd2db28dc5b531a7bd0302e71127d4f4' },
    { mnemonic: MNEMONIC_CULTURE, entropy: '358b3365e12896288ef42fc7f464b59e8076ea3ea6203bf528cb823b4dae29c4' },
  ]

  for (const v of vectors) {
    t.is(uint8ArrayToHex(Mnemonic.toEntropy(v.mnemonic), false), v.entropy, `entropy for: ${v.mnemonic.slice(0, 10)}...`)
    t.is(Mnemonic.fromEntropy(hexToUint8Array(v.entropy)), v.mnemonic, `fromEntropy roundtrip for: ${v.mnemonic.slice(0, 10)}...`)
  }
})

test('bip39 - Mnemonic.validate known invalid mnemonics', (t) => {
  t.absent(Mnemonic.validate("Why, sometimes I've believed as many as six impossible things before breakfast."), 'should reject non-mnemonic sentence')
  t.absent(Mnemonic.validate('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon'), 'should reject bad checksum')
  t.absent(Mnemonic.validate('chicken'), 'should reject single word')
})

test('bip32 - getMasterKeyFromSeed known vectors', (t) => {
  const vectors = [
    { seed: SEED_ABANDON, ...MASTER_KEY_ABANDON },
    { seed: SEED_MAMMAL, ...MASTER_KEY_MAMMAL },
    { seed: SEED_CULTURE, chainCode: '8bf4df70930efcf3ce0e8501464891837fa591b3b0924d9110b18152b8a85d37', chainKey: '73eb04585b9ecc409c76a2949f099193be82198eb6abab1594be4138070f19d6' },
    { seed: SEED_CULTURE_PASSWORD, chainCode: '5a7496d62dab5d3bef668bcff39eef421ea6b9544dba30805858989dc6611e36', chainKey: '5c8f71501f449b499feddb89d865f15d35d24586b6447b7c9b7385d0bf217fd4' },
  ]

  for (const v of vectors) {
    const mk = getMasterKeyFromSeed(hexToUint8Array(v.seed))
    t.is(uint8ArrayToHex(mk.chainCode, false), v.chainCode, 'chainCode should match')
    t.is(uint8ArrayToHex(mk.chainKey, false), v.chainKey, 'chainKey should match')
  }
})

test('bip32 - childKeyDerivationHardened known vectors', (t) => {
  const vectors = [
    { parent: MASTER_KEY_ABANDON, index: 0, childChainCode: 'e8e6a1bbce8bab145fe8225435dc98d20d53bd32318ce3ede560b8feef3394a5', childChainKey: '67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef' },
    { parent: MASTER_KEY_ABANDON, index: 12, childChainCode: 'ff90a1dcb6531d437dc959b6e03f308dd4d9db7e489bdb30d8b4b1894a9e1344', childChainKey: '9606ae0c844601e0af4d518dce577983ad756dea08726d92c080ed2ca3f5f31d' },
    { parent: MASTER_KEY_MAMMAL, index: 1, childChainCode: '30c3769638ef70c9179a7b18a507318d2353831c2d7990056334cbf14ed4a2cf', childChainKey: '0b20d68e515add21c2686d88b8ae02d82912741ed66cb776b6a2eec628ce5fef' },
  ]

  for (const v of vectors) {
    const parent = { chainCode: hexToUint8Array(v.parent.chainCode), chainKey: hexToUint8Array(v.parent.chainKey) }
    const child = childKeyDerivationHardened(parent, v.index)
    t.is(uint8ArrayToHex(child.chainCode, false), v.childChainCode, `childChainCode at index ${v.index}`)
    t.is(uint8ArrayToHex(child.chainKey, false), v.childChainKey, `childChainKey at index ${v.index}`)
  }
})
