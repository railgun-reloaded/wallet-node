import { test } from 'brittle'

import { WalletInfo } from '../src/notes/wallet-info'

test('wallet-info - encode and decode roundtrip', (t) => {
  const source = 'railway wallet'
  const encoded = WalletInfo.encodeWalletSource(source)
  const decoded = WalletInfo.decodeWalletSource(encoded)
  t.is(decoded, source, 'Should roundtrip wallet source')
})

test('wallet-info - encode and decode max length', (t) => {
  const source = 'abcdefghijklmnop' // 16 chars (max)
  const encoded = WalletInfo.encodeWalletSource(source)
  const decoded = WalletInfo.decodeWalletSource(encoded)
  t.is(decoded, source, 'Should handle max length')
})

test('wallet-info - empty string returns empty array', (t) => {
  const encoded = WalletInfo.encodeWalletSource('')
  t.is(encoded.length, 0, 'Empty string should return empty array')
  const decoded = WalletInfo.decodeWalletSource(new Uint8Array(0))
  t.is(decoded, '', 'Empty array should return empty string')
})

test('wallet-info - throws on too long source', (t) => {
  t.exception(() => {
    WalletInfo.encodeWalletSource('abcdefghijklmnopq') // 17 chars
  }, 'Should throw for source > 16 chars')
})

test('wallet-info - throws on invalid characters', (t) => {
  t.exception(() => {
    WalletInfo.encodeWalletSource('INVALID!')
  }, 'Should throw for invalid chars')
})

test('wallet-info - case insensitive encoding', (t) => {
  const encoded = WalletInfo.encodeWalletSource('Memo Wallet')
  const decoded = WalletInfo.decodeWalletSource(encoded)
  t.is(decoded, 'memo wallet', 'Should lowercase the input')
})

test('wallet-info - decode all-zero bytes returns empty string', (t) => {
  const decoded = WalletInfo.decodeWalletSource(new Uint8Array(4))
  t.is(decoded, '', 'all-zero bytes should decode to empty string')
})

test('wallet-info - decode single zero byte returns empty string', (t) => {
  const decoded = WalletInfo.decodeWalletSource(new Uint8Array([0]))
  t.is(decoded, '', 'single zero byte should decode to empty string')
})
