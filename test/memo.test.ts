import { test } from 'brittle'

import { MEMO_SENDER_RANDOM_NULL, OutputType } from '../src/notes/definitions'
import { Memo } from '../src/notes/memo'

test('memo - encode and decode undefined memo text', (t) => {
  const encoded = Memo.encodeMemoText(undefined)
  t.is(encoded.length, 0, 'Undefined should encode to empty array')
  const decoded = Memo.decodeMemoText(new Uint8Array(0))
  t.is(decoded, undefined, 'Empty array should decode to undefined')
})

test('memo - encode and decode simple text', (t) => {
  const text = 'Hello, RAILGUN!'
  const encoded = Memo.encodeMemoText(text)
  const decoded = Memo.decodeMemoText(encoded)
  t.is(decoded, text, 'Should roundtrip simple text')
})

test('memo - encode and decode text with emojis', (t) => {
  const text = 'Private memo field 🤡🙀🥰'
  const encoded = Memo.encodeMemoText(text)
  const decoded = Memo.decodeMemoText(encoded)
  t.is(decoded, text, 'Should roundtrip emoji text')
})

test('memo - encode and decode long text with emojis', (t) => {
  const text = 'A really long memo with emojis 😐👩🏾‍🔧😎 and other text !@#$%^&*() Private memo field 🤡🙀🥰👩🏿‍🚒🧞 🤡 🙀 🥰 👩🏿‍🚒 🧞, in order to test a major memo for a real live production use case.'
  const encoded = Memo.encodeMemoText(text)
  const decoded = Memo.decodeMemoText(encoded)
  t.is(decoded, text, 'Should roundtrip long text with emojis')
})

test('memo - encrypt and decrypt V2 annotation data', (t) => {
  const viewingPrivateKey = new Uint8Array(32)
  for (let i = 0; i < 32; i++) viewingPrivateKey[i] = i + 1

  const outputType = OutputType.BroadcasterFee
  const senderRandom = '1234567890abcde1234567890abcde' // 15 bytes (30 hex chars)
  const walletSource = 'memo wallet'

  const encrypted = Memo.encryptAnnotationData(outputType, senderRandom, walletSource, viewingPrivateKey)
  t.is(encrypted.length, 64, 'Encrypted annotation should be 64 bytes (IV + 3 blocks)')

  const decrypted = Memo.decryptAnnotationData(encrypted, viewingPrivateKey)
  t.ok(decrypted, 'Should successfully decrypt')
  t.is(decrypted!.outputType, outputType, 'OutputType should match')
  t.is(decrypted!.senderRandom, senderRandom, 'SenderRandom should match')
  t.is(decrypted!.walletSource, walletSource, 'WalletSource should match')
})

test('memo - encrypt and decrypt V2 annotation with Transfer type', (t) => {
  const viewingPrivateKey = new Uint8Array(32)
  for (let i = 0; i < 32; i++) viewingPrivateKey[i] = i + 10

  const outputType = OutputType.Transfer
  const senderRandom = 'aabbccddeeff001122334455667788' // 15 bytes
  const walletSource = 'test wallet'

  const encrypted = Memo.encryptAnnotationData(outputType, senderRandom, walletSource, viewingPrivateKey)
  const decrypted = Memo.decryptAnnotationData(encrypted, viewingPrivateKey)

  t.ok(decrypted, 'Should decrypt Transfer type annotation')
  t.is(decrypted!.outputType, OutputType.Transfer, 'Should be Transfer type')
  t.is(decrypted!.senderRandom, 'aabbccddeeff001122334455667788', 'SenderRandom should match')
})

test('memo - encrypt and decrypt V2 annotation with Change type', (t) => {
  const viewingPrivateKey = new Uint8Array(32)
  for (let i = 0; i < 32; i++) viewingPrivateKey[i] = i + 20

  const outputType = OutputType.Change
  const senderRandom = '000000000000000000000000000000' // 15 zero bytes
  const walletSource = 'railway'

  const encrypted = Memo.encryptAnnotationData(outputType, senderRandom, walletSource, viewingPrivateKey)
  const decrypted = Memo.decryptAnnotationData(encrypted, viewingPrivateKey)

  t.ok(decrypted, 'Should decrypt Change type annotation')
  t.is(decrypted!.outputType, OutputType.Change, 'Should be Change type')
})

test('memo - decrypt with wrong key returns undefined', (t) => {
  const correctKey = new Uint8Array(32)
  for (let i = 0; i < 32; i++) correctKey[i] = i + 1

  const wrongKey = new Uint8Array(32)
  for (let i = 0; i < 32; i++) wrongKey[i] = 255 - i

  const encrypted = Memo.encryptAnnotationData(
    OutputType.Transfer,
    '1234567890abcde1234567890abcde',
    'test',
    correctKey
  )

  const decrypted = Memo.decryptAnnotationData(encrypted, wrongKey)
  t.is(decrypted, undefined, 'Should return undefined for wrong key')
})

test('memo - decrypt empty annotation returns undefined', (t) => {
  const key = new Uint8Array(32)
  const result = Memo.decryptAnnotationData(new Uint8Array(0), key)
  t.is(result, undefined, 'Empty annotation should return undefined')
})

test('memo - throws on invalid senderRandom length', (t) => {
  const key = new Uint8Array(32).fill(1)
  t.exception(() => {
    Memo.encryptAnnotationData(OutputType.Transfer, 'tooshort', 'test', key)
  }, 'Should throw for invalid senderRandom length')
})

test('memo - decryptSenderRandom returns sender random on success', (t) => {
  const viewingPrivateKey = new Uint8Array(32)
  for (let i = 0; i < 32; i++) viewingPrivateKey[i] = i + 1

  const senderRandom = 'aabbccddeeff001122334455667788'
  const encrypted = Memo.encryptAnnotationData(
    OutputType.Transfer,
    senderRandom,
    'test',
    viewingPrivateKey
  )

  const result = Memo.decryptSenderRandom(encrypted, viewingPrivateKey)
  t.is(result, senderRandom, 'Should return correct senderRandom')
})

test('memo - decryptSenderRandom returns null constant on failure', (t) => {
  const key = new Uint8Array(32).fill(1)
  const wrongKey = new Uint8Array(32).fill(2)

  const encrypted = Memo.encryptAnnotationData(
    OutputType.Transfer,
    '1234567890abcde1234567890abcde',
    'test',
    key
  )

  const result = Memo.decryptSenderRandom(encrypted, wrongKey)
  t.is(result, MEMO_SENDER_RANDOM_NULL, 'Should return MEMO_SENDER_RANDOM_NULL on failure')
})
