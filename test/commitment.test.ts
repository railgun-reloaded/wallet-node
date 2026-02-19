import { test } from 'brittle'

import { uint8ArrayToHex } from '../src/encoding'
import { formatCommitmentCiphertext } from '../src/notes/commitment'
import type { CommitmentCiphertextStruct } from '../src/notes/definitions'

test('commitment - formatCommitmentCiphertext parses V2 ciphertext', (t) => {
  const struct: CommitmentCiphertextStruct = {
    ciphertext: [
      '0xba002e1e01f1d63d7fa06c83880b2bef23063903d3f4a2b8f7eb800f6c45491c',
      '0x8687c2941bddfc807aa3512ebef36e889a82f3885383877e55b7f86e488b6360',
      '0x40521d04c766273db030a1ee070706493383f26b8fd677cb51acf0fd30682a37',
      '0x6588e860594d6709193c391b4e79de12cecdaed31eef71a2894af5729c0209f7',
    ],
    blindedSenderViewingKey:
      '0x2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc',
    blindedReceiverViewingKey:
      '0x2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc',
    annotationData:
      '0x3f5ff6e7bab3653afd46501dac3d55bd72b33355e41bfc02fcd63a78fe9d5da550957fabde36c9ded90126755f80a3fa3cdd0d84be4686c4192e920d85dd',
    memo: '0x',
  }

  const result = formatCommitmentCiphertext(struct)

  // iv = first 16 bytes of ciphertext[0]
  t.is(
    uint8ArrayToHex(result.ciphertext.iv, false),
    'ba002e1e01f1d63d7fa06c83880b2bef',
    'iv should be first 16 bytes of ciphertext[0]'
  )

  // tag = last 16 bytes of ciphertext[0]
  t.is(
    uint8ArrayToHex(result.ciphertext.tag, false),
    '23063903d3f4a2b8f7eb800f6c45491c',
    'tag should be last 16 bytes of ciphertext[0]'
  )

  // data = remaining ciphertext elements
  t.is(result.ciphertext.data.length, 3, 'should have 3 data blocks')
  t.is(
    uint8ArrayToHex(result.ciphertext.data[0]!, false),
    '8687c2941bddfc807aa3512ebef36e889a82f3885383877e55b7f86e488b6360',
    'data[0] should match ciphertext[1]'
  )
  t.is(
    uint8ArrayToHex(result.ciphertext.data[1]!, false),
    '40521d04c766273db030a1ee070706493383f26b8fd677cb51acf0fd30682a37',
    'data[1] should match ciphertext[2]'
  )
  t.is(
    uint8ArrayToHex(result.ciphertext.data[2]!, false),
    '6588e860594d6709193c391b4e79de12cecdaed31eef71a2894af5729c0209f7',
    'data[2] should match ciphertext[3]'
  )

  // blinded keys
  t.is(
    uint8ArrayToHex(result.blindedSenderViewingKey, false),
    '2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc',
    'should parse blinded sender viewing key'
  )
  t.is(
    uint8ArrayToHex(result.blindedReceiverViewingKey, false),
    '2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc',
    'should parse blinded receiver viewing key'
  )

  // annotation data preserved
  t.is(
    uint8ArrayToHex(result.annotationData, false),
    '3f5ff6e7bab3653afd46501dac3d55bd72b33355e41bfc02fcd63a78fe9d5da550957fabde36c9ded90126755f80a3fa3cdd0d84be4686c4192e920d85dd',
    'should preserve annotation data'
  )

  // empty memo
  t.is(result.memo.length, 0, 'empty memo should produce empty Uint8Array')
})

test('commitment - formatCommitmentCiphertext throws on empty ciphertext', (t) => {
  const struct: CommitmentCiphertextStruct = {
    ciphertext: [],
    blindedSenderViewingKey: '0x00',
    blindedReceiverViewingKey: '0x00',
    annotationData: '0x',
    memo: '0x',
  }

  t.exception(() => {
    formatCommitmentCiphertext(struct)
  }, 'should throw when ciphertext array is empty')
})

test('commitment - formatCommitmentCiphertext pads short hex values', (t) => {
  const struct: CommitmentCiphertextStruct = {
    ciphertext: [
      '0xaabb',
      '0xccdd',
    ],
    blindedSenderViewingKey: '0xff',
    blindedReceiverViewingKey: '0xee',
    annotationData: '0x',
    memo: '0x',
  }

  const result = formatCommitmentCiphertext(struct)

  // Short ciphertext[0] should be left-padded to 32 bytes
  t.is(result.ciphertext.iv.length, 16, 'iv should be 16 bytes')
  t.is(result.ciphertext.tag.length, 16, 'tag should be 16 bytes')

  // Short blinded keys should be left-padded to 32 bytes
  t.is(result.blindedSenderViewingKey.length, 32, 'blinded sender key should be 32 bytes')
  t.is(result.blindedReceiverViewingKey.length, 32, 'blinded receiver key should be 32 bytes')
})
