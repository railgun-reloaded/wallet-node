type KeyNode = {
  chainKey: Uint8Array;
  chainCode: Uint8Array;
}
type SpendingPublicKey = [Uint8Array, Uint8Array]
type SpendingKeyPair = {
  privateKey: Uint8Array;
  pubkey: SpendingPublicKey;
}
type ViewingKeyPair = { privateKey: Uint8Array; pubkey: Uint8Array }

export type { KeyNode, SpendingKeyPair, SpendingPublicKey, ViewingKeyPair }
