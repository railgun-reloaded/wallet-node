import { hook, test } from 'brittle'

import { DERIVATION_PATH_PREFIXES, deriveNodes, derivePathsForIndex } from '../src/derivation'
import { initializeCryptographyLibs } from '../src/keys'

const TEST_MNEMONIC = 'test test test test test test test test test test test junk'

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
  const paths = derivePathsForIndex(1)
  t.is(paths.spending, "m/44'/1984'/0'/0'/1'", 'should generate correct spending path for index 1')
  t.is(paths.viewing, "m/420'/1984'/0'/0'/1'", 'should generate correct viewing path for index 1')
})

test('derive - deriveNodes with default index', async (t) => {
  const nodes = deriveNodes(TEST_MNEMONIC)

  t.ok(nodes.spending, 'should return spending node')
  t.ok(nodes.viewing, 'should return viewing node')
  t.ok(typeof nodes.spending.getSpendingKeyPair === 'function', 'spending node should have getSpendingKeyPair method')
  t.ok(typeof nodes.viewing.getViewingKeyPair === 'function', 'viewing node should have getViewingKeyPair method')
})

test('derive - deriveNodes with custom index', async (t) => {
  const nodes0 = deriveNodes(TEST_MNEMONIC, 0)
  const nodes1 = deriveNodes(TEST_MNEMONIC, 1)

  const spendingKey0 = nodes0.spending.getSpendingKeyPair()
  const spendingKey1 = nodes1.spending.getSpendingKeyPair()

  t.not(spendingKey0.privateKey, spendingKey1.privateKey, 'should generate different keys for different indices')
})

test('derive - deriveNodes with different mnemonics', async (t) => {
  const mnemonic1 = 'test test test test test test test test test test test junk'
  const mnemonic2 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

  const nodes1 = deriveNodes(mnemonic1, 0)
  const nodes2 = deriveNodes(mnemonic2, 0)

  const spendingKey1 = nodes1.spending.getSpendingKeyPair()
  const spendingKey2 = nodes2.spending.getSpendingKeyPair()

  t.not(spendingKey1.privateKey, spendingKey2.privateKey, 'should generate different keys for different mnemonics')
})

test('derive - multiple derivation indices', async (t) => {
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
