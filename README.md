# @railgun-reloaded/wallet-node

Hierarchical deterministic wallet and note management for the RAILGUN privacy system.

`wallet-node` is a standalone module extracted from the [RAILGUN Engine](https://github.com/Railgun-Community/engine). It handles key derivation, note construction, token serialization, and commitment decryption — everything a RAILGUN wallet needs to manage private balances without depending on the full engine.

## Key design decisions

- **Uint8Array everywhere** — All keys, hashes, and byte data are represented as `Uint8Array` instead of hex strings or bigints. Conversions happen at system boundaries only.
- **No side effects** — Pure functions for key derivation and note operations. No global state, no singletons.
- **Minimal dependencies** — Built on audited cryptographic libraries (`@noble/ed25519`, `@noble/hashes`, `@scure/bip32`, `@scure/bip39`).

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
    types.ts                  Core type definitions (KeyNode, SpendingKeyPair, etc.)
    hash.ts                   Byte utilities (hex, bigint, XOR, HMAC)
    keys.ts                   Cryptographic key operations (ECDH, blinding, scalars)
    derive/
      index.ts                Derivation path logic and node generation
    seed/
      bip32.ts                BIP32 HD key derivation (hardened, Uint8Array-based)
      bip39.ts                BIP39 mnemonic generation and validation
    wallet-node/
      wallet-node.ts          WalletNode class (key derivation and pair generation)
      railgun.ts              RailgunWallet class (high-level wallet interface)
    notes/
      definitions.ts          Note types, enums, constants (TokenType, SNARK_PRIME, etc.)
      note.ts                 Abstract base Note class with validation
      note-utils.ts           Note hashing and random validation
      token-utils.ts          Token serialization, hashing, and validation
      shield-note.ts          ShieldNote (public -> private)
      transact-note.ts        TransactNote (private -> private)
      unshield-note.ts        UnshieldNote (private -> public)
      decrypt-commitment.ts   Commitment decryption from on-chain data
  test/
    *.test.ts                 133 tests covering all modules
```

## API

### Wallet

| Export | Description |
|---|---|
| `RailgunWallet` | High-level wallet — pass a mnemonic, get all key pairs |
| `WalletNode` | Low-level HD node — derive along custom paths, get individual key pairs |
| `Mnemonic` | BIP39 utilities — generate, validate, toSeed, toEntropy, to0xPrivateKey |

### Key derivation

| Export | Description |
|---|---|
| `deriveNodes(mnemonic, index)` | Derives spending + viewing `WalletNode` pair for a given index |
| `derivePathsForIndex(index)` | Returns the BIP32 derivation paths for spending and viewing |
| `DERIVATION_PATH_PREFIXES` | Path prefixes: spending `m/44'/1984'/0'/0'/`, viewing `m/420'/1984'/0'/0'/` |
| `getMasterKeyFromSeed(seed)` | BIP32 master key from seed bytes |
| `childKeyDerivationHardened(...)` | Single-level hardened child key derivation |

### Cryptographic operations

| Export | Description |
|---|---|
| `initializeCryptographyLibs()` | **Must be called once** before using EdDSA or Poseidon operations |
| `getPublicSpendingKey(privateKey)` | EdDSA (Baby Jubjub) public key from 32-byte private key |
| `getPublicViewingKey(privateKey)` | Ed25519 public key from 32-byte private key |
| `getSharedSymmetricKey(privateKey, publicKey)` | ECDH shared key (SHA-256 of scalar multiplication) |
| `getNoteBlindingKeys(...)` | Blinds sender and receiver viewing keys for a note |
| `unblindNoteKey(...)` | Reverses blinding to recover the original viewing key |
| `getRandomScalar()` | Poseidon hash of 32 random bytes |
| `seedToScalar(seed)` | Deterministic scalar from seed (SHA-512, mod curve order) |

### Notes

| Export | Description |
|---|---|
| `ShieldNote` | Note for public-to-private transfers (shielding) |
| `TransactNote` | Note for private-to-private transfers |
| `UnshieldNote` | Note for private-to-public transfers (unshielding) |
| `decryptCommitment(...)` | Decrypts on-chain ciphertext using ECDH + AES-GCM |
| `decryptCommitmentAsReceiverOrSender(...)` | Tries decryption as receiver first, then sender |
| `getNoteHash(address, tokenData, value)` | Poseidon hash of note components |

### Token utilities

| Export | Description |
|---|---|
| `serializeTokenData(address, type, subID)` | Normalizes raw token fields into `TokenData` |
| `deserializeTokenData(data)` | Validates and normalizes from plain objects |
| `getTokenDataERC20(address)` | Shorthand for ERC20 token data |
| `getTokenDataNFT(address, type, subID)` | Shorthand for ERC721/ERC1155 token data |
| `computeTokenHash(tokenData)` | Token hash (padded address for ERC20, keccak256 mod SNARK_PRIME for NFTs) |

### Byte utilities

| Export | Description |
|---|---|
| `uint8ArrayToHex(bytes, prefix?)` | Uint8Array to hex string |
| `hexToUint8Array(hex)` | Hex string to Uint8Array (with validation) |
| `uint8ArrayToBigInt(bytes)` | Big-endian bytes to bigint |
| `bigintToUint8Array(value, length?)` | Bigint to fixed-length Uint8Array |

### Types

| Type | Description |
|---|---|
| `KeyNode` | `{ chainKey: Uint8Array, chainCode: Uint8Array }` |
| `SpendingKeyPair` | `{ privateKey: Uint8Array, pubkey: [Uint8Array, Uint8Array] }` |
| `ViewingKeyPair` | `{ privateKey: Uint8Array, pubkey: Uint8Array }` |
| `TokenData` | `{ tokenAddress: string, tokenType: TokenType, tokenSubID: string }` |
| `AddressData` | `{ masterPublicKey: bigint, viewingPublicKey: Uint8Array }` |

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

## Further reading

- [How RAILGUN Notes Work](./docs/notes.md) — Deep dive into note types, on-chain data structures, and the commitment decryption flow.

## License

MIT
