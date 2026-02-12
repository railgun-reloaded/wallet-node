/**
 * SNARK scalar field prime used in RAILGUN's zero-knowledge proofs.
 * This is the maximum value for field elements in the BN254 curve.
 */
const SNARK_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n as const

/**
 * Standard value for ERC721 notes - always 1 since NFTs are non-fungible.
 */
const ERC721_NOTE_VALUE = 1n as const

type GeneratedCommitment = {
  hash: Uint8Array;
  treeNumber: number;
  treePosition: number;
  preimage: {
    npk: Uint8Array;
    value: bigint;
    token: {
      tokenAddress: Uint8Array;
      tokenType: string;
      tokenSubID: Uint8Array;
    };
  };
  encryptedRandom: Uint8Array[];
}

type ShieldCommitment = {
  hash: Uint8Array;
  treeNumber: number;
  treePosition: number;
  preimage: {
    npk: Uint8Array;
    value: bigint;
    token: {
      tokenAddress: Uint8Array;
      tokenType: string;
      tokenSubID: Uint8Array;
    };
  };
  encryptedBundle: Uint8Array[];
  shieldKey: Uint8Array;
  fee?: bigint;
}

type UnshieldData = {
  to: Uint8Array;
  token: {
    tokenAddress: Uint8Array;
    tokenType: string;
    tokenSubID: Uint8Array;
  };
  amount: bigint;
  fee: bigint;
}

type Ciphertext = {
  iv: Uint8Array;
  tag: Uint8Array;
  data: Uint8Array[];
}

type TransactCommitment = {
  hash: Uint8Array;
  ciphertext: Ciphertext;
  blindedSenderViewingKey: Uint8Array;
  blindedReceiverViewingKey: Uint8Array;
  annotationData: Uint8Array;
  memo: Uint8Array[];
  treeNumber: number;
  treePosition: number;
}

type EncryptedCommitment = {
  hash: Uint8Array;
  ciphertext: Ciphertext;
  memo: Uint8Array[];
  ephemeralKeys: Uint8Array[];
  treeNumber: number;
  treePosition: number;
}

enum TokenType {
  ERC20 = 0,
  ERC721 = 1,
  ERC1155 = 2,
}

enum OutputType {
  Transfer = 0,
  BroadcasterFee = 1,
  Change = 2,
}

type TokenData = {
  tokenType: TokenType;
  tokenAddress: string;
  tokenSubID: string;
}

enum ChainType {
  EVM = 0,
}

type Chain = {
  type: ChainType;
  id: number;
}

type AddressData = {
  masterPublicKey: bigint;
  viewingPublicKey: Uint8Array;
  chain?: Chain;
  version?: number;
}

type NoteCiphertext = {
  iv: string;
  tag: string;
  data: string[];
}

/**
 * Legacy ciphertext format using AES-GCM encryption.
 * Used for backward compatibility with older note formats.
 */
type LegacyCiphertext = {
  iv: string;
  tag: string;
  data: string[];
}

/**
 * Encrypted data tuple: [ivTag, data]
 * Used in legacy note serialization.
 */
type EncryptedData = [string, string]

type NoteAnnotationData = {
  outputType: OutputType;
  senderRandom: string;
  walletSource: string | undefined;
}

/**
 * Base interface for all note types, containing common properties.
 */
interface NoteBase {
  notePublicKey: string;
  random: string;
  value: bigint;
  tokenData: TokenData;
}

interface ShieldNote extends NoteBase {
  masterPublicKey: bigint;
  tokenHash: string;
}

interface TransactNote extends NoteBase {
  receiverAddressData: AddressData;
  senderAddressData: AddressData | undefined;
  tokenHash: string;
  hash: bigint;
  outputType: OutputType | undefined;
  walletSource: string | undefined;
  senderRandom: string | undefined;
  memoText: string | undefined;
  shieldFee: string | undefined;
  blockNumber: number | undefined;
}

interface UnshieldNote extends NoteBase {
  toAddress: string;
  hash: bigint;
  allowOverride: boolean;
}

/**
 * Legacy serialized transact note format.
 * Used for backward compatibility with older database entries.
 * DO NOT MODIFY - This format is stored in databases.
 */
interface LegacyTransactNoteSerialized {
  npk: string;
  value: string;
  tokenHash: string;
  encryptedRandom: EncryptedData;
  memoField: string[];
  recipientAddress: string;
  memoText: string | undefined;
  blockNumber: number | undefined;
}

/**
 * Modern serialized transact note format.
 * DO NOT MODIFY - This format is stored in databases.
 */
interface TransactNoteSerialized {
  npk: string;
  value: string;
  tokenHash: string;
  random: string;
  recipientAddress: string;
  outputType: OutputType | undefined;
  senderRandom: string | undefined;
  walletSource: string | undefined;
  senderAddress: string | undefined;
  memoText: string | undefined;
  shieldFee: string | undefined;
  blockNumber: number | undefined;
}

/**
 * Null sender random value used when annotation data decryption fails.
 * 15 zero bytes (30 hex chars) matching the senderRandom field size.
 */
const MEMO_SENDER_RANDOM_NULL = '000000000000000000000000000000'

export type { TokenData, Chain, AddressData, NoteCiphertext, LegacyCiphertext, EncryptedData, NoteAnnotationData, NoteBase, ShieldNote, TransactNote, LegacyTransactNoteSerialized, TransactNoteSerialized, UnshieldNote, GeneratedCommitment, ShieldCommitment, UnshieldData, Ciphertext, TransactCommitment, EncryptedCommitment }
export { TokenType, OutputType, ChainType, SNARK_PRIME, ERC721_NOTE_VALUE, MEMO_SENDER_RANDOM_NULL }
