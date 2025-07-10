import assert from 'node:assert/strict'
import { before, describe, it } from 'node:test'

import { stringify } from '@railgun-reloaded/0zk-addresses'

import { initializeCryptographyLibs } from '../src/keys'
import { RailgunWallet } from '../src/wallet-node/railgun'

const TEST_MNEMONIC = 'test test test test test test test test test test test junk'

describe('Wallet-Node', () => {
  before(async () => {
    await initializeCryptographyLibs()
  })
  it('Initialize Module', () => {
    const railgunWallet = new RailgunWallet(TEST_MNEMONIC)
    const expectedAddress = stringify(
      {
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
    const railgunAddress = stringify(
      {

        masterPublicKey: railgunWallet.getMasterPublicKey(),
        viewingPublicKey: railgunWallet.getViewingPublicKey(),
      }
    )
    console.log('address', railgunAddress)
    assert(expectedAddress === '0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48tlrv7j6fe3z53lama02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5ajy990', 'Constant value incorrect.')
    assert(expectedAddress === railgunAddress, 'Result address does not match expected.')
  })
})
