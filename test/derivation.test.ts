import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { bytesToHex } from '@railgun-reloaded/bytes'

import { initializeCryptographyLibs } from '../src/keys.js'
import { DERIVATION_PATH_PREFIXES, deriveNodes, derivePathsForIndex } from '../src/wallet/derivation.js'

const TEST_MNEMONIC = 'test test test test test test test test test test test junk'
const ABANDON_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

// Fixed wallet key-derivation vectors captured from the previous HMAC-SHA512
// implementation. They are a byte-for-byte regression baseline: BIP-32
// derivation is fully determined by sha512HMAC, so these spending and viewing
// key pairs must remain unchanged across runtimes and implementations of it.
const WALLET_KEY_VECTORS = [
  {
    mnemonic: TEST_MNEMONIC,
    index: 0,
    spending: {
      privateKey: 'b0958f8bc286ae0832fa83b01b719a225a07ce7b861ff311323f221667b3bd50',
      pubkey: [
        '22ad4dc014b6e9373771c977a44060b329fd4a585cd1047d67fe5309d3e89e10',
        '1a430ec8dc1450fd29a1aedf4760f7c6aa348a2199360a70eadde078593cad04',
      ],
    },
    viewing: {
      privateKey: '9da4b4f0b5493a6ba3f7df0611c3e0842f7e2bb3d640f313b235f1b75c1d80b9',
      pubkey: '77d7aa7c5b978060be2ba78cbc0ef92a4f3aa3fc29803eaf47847cf510b986ea',
    },
  },
  {
    mnemonic: TEST_MNEMONIC,
    index: 1,
    spending: {
      privateKey: 'b54486f7304ca8618bce1ba764b24473592c967fef9ee425b1dafcb1504fe210',
      pubkey: [
        '0f95a3ff1c8c1549ff867be5778c4cff26c4b18f42285f00b9a859602899158a',
        '27224cd60fed924e9ba1eed6b605d210d14353be1ef2c448b5302c72f9d4627f',
      ],
    },
    viewing: {
      privateKey: '9960238a86a7ecff390b7f37f680e7468fa0c41ee3704fcc68f0be82d19be4b2',
      pubkey: '45f25fda60af06969b609b94203e90bbeb54ccb7cca7c1060862dc2f5f7395ea',
    },
  },
  {
    mnemonic: TEST_MNEMONIC,
    index: 5,
    spending: {
      privateKey: '4a5b1206789d273fa7be030715e736d32656209974d635a15440fb6542839bbb',
      pubkey: [
        '22982e7a319e72cf0edd921e30ffdd022c25e4be5efbd36d952ebbb4e3daaba7',
        '0f749a4cbaffcbc4751ee38285157c2f0d5b42e1b3769dbe3f5b66a6b9652ec0',
      ],
    },
    viewing: {
      privateKey: '9778c2cce27a9895136f9bb5b335a0b14b395420202f6f3b42ae506ec7bbf4de',
      pubkey: '597dc72bdbefefbd963b870edd3d78faf2d836f1e3676ccbcf82ca347a22ecba',
    },
  },
  {
    mnemonic: ABANDON_MNEMONIC,
    index: 0,
    spending: {
      privateKey: '08b2d974aa7fffd9d068b78c34434c534ddcd9343fcbf5aa12cf78e1a3c1ccb9',
      pubkey: [
        '3008064177791584c9378d04a8f382f43195f76d3fd6f758a50076dcd392ae4c',
        '2834610a1ec9e739a664edc0c8eb0839065e2debfbc592d5e75e3c978bcc29a0',
      ],
    },
    viewing: {
      privateKey: '9a9e1ca3b9476dc8500b43f30f34104c92a3eedfd727757ffd0ad15da8e11572',
      pubkey: 'df2dfb942aa6fb8cf9fe60d7984cd10b20b59027e677ecb4960d764f7d42408a',
    },
  },
  {
    mnemonic: ABANDON_MNEMONIC,
    index: 1,
    spending: {
      privateKey: '6b021e0d06d0b2d161cf0ea494e3fc1cbff12cc1b29281f7412170351b708fad',
      pubkey: [
        '2c6273d25129a29b109a2894d9c9782c03ef2535b2a51ad808c16e012cc27a57',
        '1bf569d094d9c1a39f97addec8275f7f2fe7a45cca3869d68a37bb53fcb5365a',
      ],
    },
    viewing: {
      privateKey: '4064dd49251ac6b9335305b200b0310bb22ff64692b2cb20d380b9101219ba9e',
      pubkey: '2ac164010ce76e813063dd51cbe146d98c1c449236e36913eec4bb4da5af6f45',
    },
  },
  {
    mnemonic: ABANDON_MNEMONIC,
    index: 5,
    spending: {
      privateKey: 'b6935226ed6923e7ac2fb5008ba2284e3d5c901d9282f2745fcb1db8178690c6',
      pubkey: [
        '138ad731e3959d9e5e6b5f2eb18fed5f4fb33734c651c93b246c2d56b5c6491c',
        '11ac28b73bd97efb8b3bd87b3445501228894224b3fd4365298ec717130e5e71',
      ],
    },
    viewing: {
      privateKey: 'f443832e8930e50712a08c9cc4b9f92674a44e686e2656515ef3964e2d7228c7',
      pubkey: '238fd15dc7f92098b8d8d9c3dc68f0e4c1e804e0d8cd1b0c7ffe9e99e0118fc8',
    },
  },
] as const

before(async () => {
  await initializeCryptographyLibs()
  assert.ok(true, 'cryptography libraries initialized')
})

test('derive - DERIVATION_PATH_PREFIXES', () => {
  assert.equal(DERIVATION_PATH_PREFIXES.SPENDING, "m/44'/1984'/0'/0'/", 'should have correct spending prefix')
  assert.equal(DERIVATION_PATH_PREFIXES.VIEWING, "m/420'/1984'/0'/0'/", 'should have correct viewing prefix')
})

test('derive - derivePathsForIndex with default index', () => {
  const paths = derivePathsForIndex()

  assert.equal(paths.spending, "m/44'/1984'/0'/0'/0'", 'should generate correct spending path for index 0')
  assert.equal(paths.viewing, "m/420'/1984'/0'/0'/0'", 'should generate correct viewing path for index 0')
})

test('derive - derivePathsForIndex with custom index', () => {
  const paths = derivePathsForIndex(1)
  assert.equal(paths.spending, "m/44'/1984'/0'/0'/1'", 'should generate correct spending path for index 1')
  assert.equal(paths.viewing, "m/420'/1984'/0'/0'/1'", 'should generate correct viewing path for index 1')
})

test('derive - deriveNodes with default index', async () => {
  const nodes = deriveNodes(TEST_MNEMONIC)

  assert.ok(nodes.spending, 'should return spending node')
  assert.ok(nodes.viewing, 'should return viewing node')
  assert.ok(typeof nodes.spending.getSpendingKeyPair === 'function', 'spending node should have getSpendingKeyPair method')
  assert.ok(typeof nodes.viewing.getViewingKeyPair === 'function', 'viewing node should have getViewingKeyPair method')
})

test('derive - deriveNodes with custom index', async () => {
  const nodes0 = deriveNodes(TEST_MNEMONIC, 0)
  const nodes1 = deriveNodes(TEST_MNEMONIC, 1)

  const spendingKey0 = nodes0.spending.getSpendingKeyPair()
  const spendingKey1 = nodes1.spending.getSpendingKeyPair()

  assert.notEqual(spendingKey0.privateKey, spendingKey1.privateKey, 'should generate different keys for different indices')
})

test('derive - deriveNodes with different mnemonics', async () => {
  const mnemonic2 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

  const nodes1 = deriveNodes(TEST_MNEMONIC, 0)
  const nodes2 = deriveNodes(mnemonic2, 0)

  const spendingKey1 = nodes1.spending.getSpendingKeyPair()
  const spendingKey2 = nodes2.spending.getSpendingKeyPair()

  assert.notEqual(spendingKey1.privateKey, spendingKey2.privateKey, 'should generate different keys for different mnemonics')
})

test('derive - matches fixed wallet key vectors byte-for-byte', () => {
  for (const vector of WALLET_KEY_VECTORS) {
    const { spending, viewing } = deriveNodes(vector.mnemonic, vector.index)

    const spendingPair = spending.getSpendingKeyPair()
    const viewingPair = viewing.getViewingKeyPair()

    const label = `mnemonic="${vector.mnemonic.split(' ')[0]}…" index=${vector.index}`

    assert.equal(bytesToHex(spendingPair.privateKey), vector.spending.privateKey, `${label} spending privateKey`)
    assert.equal(bytesToHex(spendingPair.pubkey[0]), vector.spending.pubkey[0], `${label} spending pubkey[0]`)
    assert.equal(bytesToHex(spendingPair.pubkey[1]), vector.spending.pubkey[1], `${label} spending pubkey[1]`)
    assert.equal(bytesToHex(viewingPair.privateKey), vector.viewing.privateKey, `${label} viewing privateKey`)
    assert.equal(bytesToHex(viewingPair.pubkey), vector.viewing.pubkey, `${label} viewing pubkey`)
  }
})

test('derive - multiple derivation indices', async () => {
  const indices = [0, 1, 2, 5, 10, 100]
  const keys = new Set()

  for (const index of indices) {
    const nodes = deriveNodes(TEST_MNEMONIC, index)
    const spendingKey = nodes.spending.getSpendingKeyPair()
    const keyString = Buffer.from(spendingKey.privateKey).toString('hex')
    keys.add(keyString)
  }

  assert.equal(keys.size, indices.length, 'should generate unique keys for each index')
})
