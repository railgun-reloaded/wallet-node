import assert from 'node:assert/strict'
import { test } from 'node:test'

import { WalletInfo } from '../src/notes/wallet-info.js'

test('wallet-info - encode and decode roundtrip', () => {
  const source = 'railway wallet'
  const encoded = WalletInfo.encodeWalletSource(source)
  const decoded = WalletInfo.decodeWalletSource(encoded)
  assert.equal(decoded, source, 'Should roundtrip wallet source')
})

test('wallet-info - encode and decode max length', () => {
  const source = 'abcdefghijklmnop' // 16 chars (max)
  const encoded = WalletInfo.encodeWalletSource(source)
  const decoded = WalletInfo.decodeWalletSource(encoded)
  assert.equal(decoded, source, 'Should handle max length')
})

test('wallet-info - empty string returns empty array', () => {
  const encoded = WalletInfo.encodeWalletSource('')
  assert.equal(encoded.length, 0, 'Empty string should return empty array')
  const decoded = WalletInfo.decodeWalletSource(new Uint8Array(0))
  assert.equal(decoded, '', 'Empty array should return empty string')
})

test('wallet-info - throws on too long source', () => {
  assert.throws(() => {
    WalletInfo.encodeWalletSource('abcdefghijklmnopq') // 17 chars
  }, 'Should throw for source > 16 chars')
})

test('wallet-info - throws on invalid characters', () => {
  assert.throws(() => {
    WalletInfo.encodeWalletSource('INVALID!')
  }, 'Should throw for invalid chars')
})

test('wallet-info - case insensitive encoding', () => {
  const encoded = WalletInfo.encodeWalletSource('Memo Wallet')
  const decoded = WalletInfo.decodeWalletSource(encoded)
  assert.equal(decoded, 'memo wallet', 'Should lowercase the input')
})

test('wallet-info - decode all-zero bytes returns empty string', () => {
  const decoded = WalletInfo.decodeWalletSource(new Uint8Array(4))
  assert.equal(decoded, '', 'all-zero bytes should decode to empty string')
})

test('wallet-info - decode single zero byte returns empty string', () => {
  const decoded = WalletInfo.decodeWalletSource(new Uint8Array([0]))
  assert.equal(decoded, '', 'single zero byte should decode to empty string')
})
