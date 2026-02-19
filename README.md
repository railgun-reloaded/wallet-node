# @railgun-reloaded/wallet-node

Hierarchical deterministic wallet and note management for the RAILGUN privacy system.

`wallet-node` handles key derivation, note construction, token serialization, and commitment decryption.

## Installing

```sh
npm install @railgun-reloaded/wallet-node
```

## Quick start

```typescript
import {
  Mnemonic,
  RailgunWallet,
  initializeCryptographyLibs,
} from '@railgun-reloaded/wallet-node'

// Initialize cryptography (required once before any operations)
await initializeCryptographyLibs()

// Generate or use an existing mnemonic
const mnemonic = Mnemonic.generate() // 12-word BIP39 phrase

// Create a wallet
const wallet = new RailgunWallet(mnemonic)

// Access keys
const spendingPubKey = wallet.getSpendingPublicKey()   // [Uint8Array, Uint8Array]
const viewingPubKey  = wallet.getViewingPublicKey()     // Uint8Array (32 bytes)
const masterPubKey   = wallet.getMasterPublicKey()       // Uint8Array
const nullifyingKey  = wallet.getNullifyingKey()         // Uint8Array
```

## Architecture

```
wallet-node/
  src/
    index.ts                  Package entry point
    encoding.ts               Byte utilities (hex, bigint, XOR, HMAC-SHA512)
    keys.ts                   Cryptographic key operations (ECDH, blinding, scalars)
    mnemonic/
      mnemonic.ts             Mnemonic class (BIP39 generation and validation)
    wallet/
      types.ts                Core type definitions (KeyNode, SpendingKeyPair, etc.)
      bip32.ts                BIP32 HD key derivation (hardened, Uint8Array-based)
      derivation.ts           Derivation path logic and node generation
      wallet-node.ts          WalletNode class (key derivation and pair generation)
      railgun-wallet.ts       RailgunWallet class (high-level wallet interface)
    notes/
      definitions.ts          Note types, enums, constants (TokenType, SNARK_PRIME, etc.)
      token-utils.ts          Token serialization, hashing, and validation
      address-utils.ts        0zk address encoding/decoding (bech32)
      commitment.ts           Commitment formatting and decryption from on-chain data
      note.ts                 Note class (abstract base with hash and validation)
      shield-note.ts          ShieldNote class (public -> private)
      transact-note.ts        TransactNote class (private -> private)
      unshield-note.ts        UnshieldNote class (private -> public)
      memo.ts                 Memo class (annotation data and memo text encryption/decryption)
      wallet-info.ts          WalletInfo class (wallet info encoding for note annotations)
  test/
    *.test.ts                 Tests covering all modules
```

## Developing

### Install dependencies

```sh
npm install
```

### Build

```sh
npm run build
```

### Run tests

```sh
npm test
```

### Lint

```sh
npm run lint
npm run lint:fix
```

## License

MIT
