import { test } from 'brittle'

import { DERIVATION_PATH_PREFIXES, deriveNodes, derivePathsForIndex } from '../src/derive'
import { initializeCryptographyLibs } from '../src/keys'

const TEST_MNEMONIC = 'test test test test test test test test test test test junk'

test('derive - DERIVATION_PATH_PREFIXES', (t) => {
  t.is(DERIVATION_PATH_PREFIXES.SPENDING, "m/44'/1984'/0'/0'/", 'should have correct spending prefix')
  t.is(DERIVATION_PATH_PREFIXES.VIEWING, "m/420'/1984'/0'/0'/", 'should have correct viewing prefix')
})

test('derive - derivePathsForIndex with default index', (t) => {
  const paths = derivePathsForIndex()

  t.is(paths.spending, "m/44'/1984'/0'/0'/0'", 'should generate correct spending path for index 0')
  t.is(paths.viewing, "m/420'/1984'/0'/0'/0'", 'should generate correct viewing path for index 0')
})

test('derive - derivePathsForIndex with custom index', (t) => {
  const paths1 = derivePathsForIndex(1)
  t.is(paths1.spending, "m/44'/1984'/0'/0'/1'", 'should generate correct spending path for index 1')
  t.is(paths1.viewing, "m/420'/1984'/0'/0'/1'", 'should generate correct viewing path for index 1')

  const paths5 = derivePathsForIndex(5)
  t.is(paths5.spending, "m/44'/1984'/0'/0'/5'", 'should generate correct spending path for index 5')
  t.is(paths5.viewing, "m/420'/1984'/0'/0'/5'", 'should generate correct viewing path for index 5')

  const paths100 = derivePathsForIndex(100)
  t.is(paths100.spending, "m/44'/1984'/0'/0'/100'", 'should generate correct spending path for index 100')
  t.is(paths100.viewing, "m/420'/1984'/0'/0'/100'", 'should generate correct viewing path for index 100')
})

test('derive - deriveNodes with default index', async (t) => {
  await initializeCryptographyLibs()

  const nodes = deriveNodes(TEST_MNEMONIC)

  t.ok(nodes.spending, 'should return spending node')
  t.ok(nodes.viewing, 'should return viewing node')
  t.ok(typeof nodes.spending.getSpendingKeyPair === 'function', 'spending node should have getSpendingKeyPair method')
  t.ok(typeof nodes.viewing.getViewingKeyPair === 'function', 'viewing node should have getViewingKeyPair method')
})

test('derive - deriveNodes with custom index', async (t) => {
  await initializeCryptographyLibs()

  const nodes0 = deriveNodes(TEST_MNEMONIC, 0)
  const nodes1 = deriveNodes(TEST_MNEMONIC, 1)

  const spendingKey0 = nodes0.spending.getSpendingKeyPair()
  const spendingKey1 = nodes1.spending.getSpendingKeyPair()

  t.not(spendingKey0.privateKey, spendingKey1.privateKey, 'should generate different keys for different indices')
})

test('derive - deriveNodes deterministic', async (t) => {
  await initializeCryptographyLibs()

  const nodes1 = deriveNodes(TEST_MNEMONIC, 0)
  const nodes2 = deriveNodes(TEST_MNEMONIC, 0)

  const spendingKey1 = nodes1.spending.getSpendingKeyPair()
  const spendingKey2 = nodes2.spending.getSpendingKeyPair()

  t.alike(spendingKey1.privateKey, spendingKey2.privateKey, 'should generate same keys for same mnemonic and index')
})

test('derive - deriveNodes with different mnemonics', async (t) => {
  await initializeCryptographyLibs()

  const mnemonic1 = 'test test test test test test test test test test test junk'
  const mnemonic2 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

  const nodes1 = deriveNodes(mnemonic1, 0)
  const nodes2 = deriveNodes(mnemonic2, 0)

  const spendingKey1 = nodes1.spending.getSpendingKeyPair()
  const spendingKey2 = nodes2.spending.getSpendingKeyPair()

  t.not(spendingKey1.privateKey, spendingKey2.privateKey, 'should generate different keys for different mnemonics')
})

test('derive - multiple derivation indices', async (t) => {
  await initializeCryptographyLibs()

  const indices = [0, 1, 2, 5, 10, 100]
  const keys = new Set()

  for (const index of indices) {
    const nodes = deriveNodes(TEST_MNEMONIC, index)
    const spendingKey = nodes.spending.getSpendingKeyPair()
    const keyString = Buffer.from(spendingKey.privateKey).toString('hex')
    keys.add(keyString)
  }

  t.is(keys.size, indices.length, 'should generate unique keys for each index')
})
