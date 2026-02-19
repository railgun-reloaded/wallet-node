import { stringify } from '@railgun-reloaded/0zk-addresses'
import { hook, test } from 'brittle'

import { initializeCryptographyLibs } from '../src/keys'
import { RailgunWallet } from '../src/wallet/railgun-wallet'
import { WalletNode } from '../src/wallet/wallet-node'

const TEST_MNEMONIC = 'test test test test test test test test test test test junk'
const TEST_MNEMONIC_2 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

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

test('wallet-node - WalletNode.fromMnemonic', async (t) => {
  const walletNode = WalletNode.fromMnemonic(TEST_MNEMONIC)

  t.ok(walletNode instanceof WalletNode, 'should return WalletNode instance')
  t.ok(typeof walletNode.derive === 'function', 'should have derive method')
  t.ok(typeof walletNode.getSpendingKeyPair === 'function', 'should have getSpendingKeyPair method')
})

test('wallet-node - WalletNode.derive', async (t) => {
  const walletNode = WalletNode.fromMnemonic(TEST_MNEMONIC)
  const derivedNode = walletNode.derive("m/44'/1984'/0'/0'/0'")

  t.ok(derivedNode instanceof WalletNode, 'should return WalletNode instance')
  t.not(derivedNode, walletNode, 'should return new instance')
})

test('wallet-node - WalletNode.derive multiple paths', async (t) => {
  const walletNode = WalletNode.fromMnemonic(TEST_MNEMONIC)
  const derived1 = walletNode.derive("m/44'/1984'/0'/0'/0'")
  const derived2 = walletNode.derive("m/44'/1984'/0'/0'/1'")

  const key1 = derived1.getSpendingKeyPair()
  const key2 = derived2.getSpendingKeyPair()

  t.not(key1.privateKey, key2.privateKey, 'should generate different keys for different paths')
})

test('wallet-node - WalletNode.getSpendingKeyPair', async (t) => {
  const walletNode = WalletNode.fromMnemonic(TEST_MNEMONIC)
  const keyPair = walletNode.getSpendingKeyPair()

  t.ok(keyPair.privateKey instanceof Uint8Array, 'should return privateKey as Uint8Array')
  t.ok(Array.isArray(keyPair.pubkey), 'should return pubkey as array')
  t.is(keyPair.pubkey.length, 2, 'pubkey should have 2 elements')
  t.is(keyPair.privateKey.length, 32, 'privateKey should be 32 bytes')
})

test('wallet-node - WalletNode.getViewingKeyPair', async (t) => {
  const walletNode = WalletNode.fromMnemonic(TEST_MNEMONIC)
  const keyPair = walletNode.getViewingKeyPair()

  t.ok(keyPair.privateKey instanceof Uint8Array, 'should return privateKey as Uint8Array')
  t.ok(keyPair.pubkey instanceof Uint8Array, 'should return pubkey as Uint8Array')
  t.is(keyPair.privateKey.length, 32, 'privateKey should be 32 bytes')
  t.is(keyPair.pubkey.length, 32, 'pubkey should be 32 bytes')
})

test('wallet-node - WalletNode.getNullifyingKey', async (t) => {
  const walletNode = WalletNode.fromMnemonic(TEST_MNEMONIC)
  const nullifyingKey = walletNode.getNullifyingKey()

  t.ok(nullifyingKey instanceof Uint8Array, 'should return Uint8Array')
  t.ok(nullifyingKey.length > 0, 'should return non-empty array')
})

test('wallet-node - WalletNode.getMasterPublicKey', async (t) => {
  const walletNode = WalletNode.fromMnemonic(TEST_MNEMONIC)
  const spendingKeyPair = walletNode.getSpendingKeyPair()
  const nullifyingKey = walletNode.getNullifyingKey()

  const masterPublicKey = WalletNode.getMasterPublicKey(spendingKeyPair.pubkey, nullifyingKey)

  t.ok(masterPublicKey instanceof Uint8Array, 'should return Uint8Array')
  t.ok(masterPublicKey.length > 0, 'should return non-empty array')
})

test('railgun-wallet - RailgunWallet initialization', async (t) => {
  const wallet = new RailgunWallet(TEST_MNEMONIC)

  t.ok(wallet instanceof RailgunWallet, 'should create RailgunWallet instance')
})

test('railgun-wallet - RailgunWallet.getSpendingPrivateKey', async (t) => {
  const wallet = new RailgunWallet(TEST_MNEMONIC)
  const privateKey = wallet.getSpendingPrivateKey()

  t.ok(privateKey instanceof Uint8Array, 'should return Uint8Array')
  t.is(privateKey.length, 32, 'should return 32 bytes')
})

test('railgun-wallet - RailgunWallet.getSpendingPublicKey', async (t) => {
  const wallet = new RailgunWallet(TEST_MNEMONIC)
  const publicKey = wallet.getSpendingPublicKey()

  t.ok(Array.isArray(publicKey), 'should return array')
  t.is(publicKey.length, 2, 'should have 2 elements')
})

test('railgun-wallet - RailgunWallet.getMasterPublicKey', async (t) => {
  const wallet = new RailgunWallet(TEST_MNEMONIC)
  const masterPublicKey = wallet.getMasterPublicKey()

  t.ok(masterPublicKey instanceof Uint8Array, 'should return Uint8Array')
  t.ok(masterPublicKey.length > 0, 'should return non-empty array')
})

test('railgun-wallet - RailgunWallet.getNullifyingKey', async (t) => {
  const wallet = new RailgunWallet(TEST_MNEMONIC)
  const nullifyingKey = wallet.getNullifyingKey()

  t.ok(nullifyingKey instanceof Uint8Array, 'should return Uint8Array')
  t.ok(nullifyingKey.length > 0, 'should return non-empty array')
})

test('railgun-wallet - RailgunWallet.getViewingPublicKey', async (t) => {
  const wallet = new RailgunWallet(TEST_MNEMONIC)
  const viewingPublicKey = wallet.getViewingPublicKey()

  t.ok(viewingPublicKey instanceof Uint8Array, 'should return Uint8Array')
  t.is(viewingPublicKey.length, 32, 'should return 32 bytes')
})

test('railgun-wallet - RailgunWallet.getViewingPrivateKey', async (t) => {
  const wallet = new RailgunWallet(TEST_MNEMONIC)
  const viewingPrivateKey = wallet.getViewingPrivateKey()

  t.ok(viewingPrivateKey instanceof Uint8Array, 'should return Uint8Array')
  t.is(viewingPrivateKey.length, 32, 'should return 32 bytes')
})

test('railgun-wallet - RailgunWallet with custom index', async (t) => {
  const wallet0 = new RailgunWallet(TEST_MNEMONIC, 0)
  const wallet1 = new RailgunWallet(TEST_MNEMONIC, 1)

  const key0 = wallet0.getSpendingPrivateKey()
  const key1 = wallet1.getSpendingPrivateKey()

  t.not(key0, key1, 'should generate different keys for different indices')
})

test('railgun-wallet - RailgunWallet generates expected address', async (t) => {
  const wallet = new RailgunWallet(TEST_MNEMONIC)

  const expectedAddress = stringify({
    masterPublicKey: new Uint8Array([
      44, 89, 205, 71, 51, 249, 17, 186,
      116, 13, 166, 143, 183, 186, 59, 135,
      63, 33, 218, 236, 228, 227, 161, 5,
      174, 241, 45, 100, 20, 229, 78, 191
    ]),
    viewingPublicKey: new Uint8Array([
      119, 215, 170, 124, 91, 151, 128, 96,
      190, 43, 167, 140, 188, 14, 249, 42,
      79, 58, 163, 252, 41, 128, 62, 175,
      71, 132, 124, 245, 16, 185, 134, 234
    ])
  })

  const railgunAddress = stringify({
    masterPublicKey: wallet.getMasterPublicKey(),
    viewingPublicKey: wallet.getViewingPublicKey(),
  })

  t.is(expectedAddress, '0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48tlrv7j6fe3z53lama02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5ajy990', 'expected address constant should be correct')
  t.is(expectedAddress, railgunAddress, 'wallet should generate expected address')
})

test('railgun-wallet - RailgunWallet.getShieldPrivateKeySignatureMessage', (t) => {
  const message = RailgunWallet.getShieldPrivateKeySignatureMessage()

  t.is(message, 'RAILGUN_SHIELD', 'should return correct constant message')
})

test('railgun-wallet - Different mnemonics generate different wallets', async (t) => {
  const wallet1 = new RailgunWallet(TEST_MNEMONIC, 0)
  const wallet2 = new RailgunWallet(TEST_MNEMONIC_2, 0)

  const address1 = stringify({
    masterPublicKey: wallet1.getMasterPublicKey(),
    viewingPublicKey: wallet1.getViewingPublicKey(),
  })

  const address2 = stringify({
    masterPublicKey: wallet2.getMasterPublicKey(),
    viewingPublicKey: wallet2.getViewingPublicKey(),
  })

  t.not(address1, address2, 'different mnemonics should generate different addresses')
})
