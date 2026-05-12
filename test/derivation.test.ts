import assert from 'node:assert/strict'
import { before, test } from 'node:test'

import { initializeCryptographyLibs } from '../src/keys'
import { DERIVATION_PATH_PREFIXES, deriveNodes, derivePathsForIndex } from '../src/wallet/derivation'

const TEST_MNEMONIC = 'test test test test test test test test test test test junk'

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
