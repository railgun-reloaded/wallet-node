/**
 * SNARK scalar field prime used in RAILGUN's zero-knowledge proofs.
 * This is the maximum value for field elements in the BN254 curve.
 */
const SNARK_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n as const

/**
 * Standard value for ERC721 notes - always 1 since NFTs are non-fungible.
 */
const ERC721_NOTE_VALUE = 1n as const

/**
 * Scanner commitment types - used for type safety when converting scanner data.
 * These types match the scanner's output format.
 */
type GeneratedCommitment = {
  hash: Uint8Array;
  treeNumber: number;
  treePosition: number;
  preimage: {
    npk: Uint8Array;
    value: bigint;
    token: {
      tokenAddress: Uint8Array;
      tokenType: string; // Scanner uses string, needs conversion to TokenType enum
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
      tokenType: string; // Scanner uses string, needs conversion to TokenType enum
      tokenSubID: Uint8Array;
    };
  };
  encryptedBundle: Uint8Array[];
  shieldKey: Uint8Array;
  fee?: bigint;
}

/**
 * Unshield data type - used when converting unshield events to notes.
 */
type UnshieldData = {
  to: Uint8Array;
  token: {
    tokenAddress: Uint8Array;
    tokenType: string; // Uses string, needs conversion to TokenType enum
    tokenSubID: Uint8Array;
  };
  amount: bigint;
  fee: bigint;
}

/**
 * Ciphertext type - used in encrypted commitments.
 */
type Ciphertext = {
  iv: Uint8Array;
  tag: Uint8Array;
  data: Uint8Array[];
}

/**
 * Transact commitment type - used when converting transact events to notes.
 */
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

/**
 * Encrypted commitment type - used when converting encrypted commitment events to notes.
 */
type EncryptedCommitment = {
  hash: Uint8Array;
  ciphertext: Ciphertext;
  memo: Uint8Array[];
  ephemeralKeys: Uint8Array[];
  treeNumber: number;
  treePosition: number;
}

/**
 * TokenType
 * Enumeration of supported token types in the Railgun system.
 */
enum TokenType {
  ERC20 = 0,
  ERC721 = 1,
  ERC1155 = 2,
}

/**
 * OutputType
 * Enumeration of output types in transactions.
 */
enum OutputType {
  Transfer = 0,
  BroadcasterFee = 1,
  Change = 2,
}

/**
 *
 * Represents data for a token, including its type, address, and sub-ID.
 */
type TokenData = {
  tokenType: TokenType;
  tokenAddress: string;
  tokenSubID: string;
}

/**
 * ChainType
 * Enumeration of supported blockchain chain types.
 */
enum ChainType {
  EVM = 0,
}

/**
 *
 * Represents a blockchain chain with its type and ID.
 */
type Chain = {
  type: ChainType;
  id: number;
}

/**
 *
 * Contains address-related data including public keys and optional chain/version info.
 */
type AddressData = {
  masterPublicKey: bigint;
  viewingPublicKey: Uint8Array;
  chain?: Chain;
  version?: number;
}

/**
 *
 * Represents the ciphertext data for a note, including IV, tag, and encrypted data.
 */
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

/**
 * Note annotation data containing output type, sender random, and wallet source.
 */
type NoteAnnotationData = {
  outputType: OutputType;
  senderRandom: string;
  walletSource: string | undefined;
}

/**
 * Base interface for all note types, containing common properties.
 * notePublicKey - Also known as npk
 * random - 16 byte random
 * value - The value of the note
 * tokenData - Token data
 */
interface NoteBase {
  notePublicKey: string;
  random: string;
  value: bigint;
  tokenData: TokenData;
}

/**
 * Interface for shield notes, extending NoteBase with additional properties for shielding.
 */
interface ShieldNote extends NoteBase {
  masterPublicKey: bigint;
  tokenHash: string;
}

/**
 * Interface for transaction notes, extending NoteBase with sender/receiver data and transaction details.
 * receiverAddressData - address data of recipient
 * senderAddressData - address data of sender
 * tokenHash - 32 byte hash of token data
 * hash - Note hash
 * shieldFee - Only used during serialization/storage of ShieldCommitments.
 */
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

/**
 * Interface for unshield notes, extending NoteBase with unshielding-specific properties.
 */
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

export type { TokenData, Chain, AddressData, NoteCiphertext, LegacyCiphertext, EncryptedData, NoteAnnotationData, NoteBase, ShieldNote, TransactNote, LegacyTransactNoteSerialized, TransactNoteSerialized, UnshieldNote, GeneratedCommitment, ShieldCommitment, UnshieldData, Ciphertext, TransactCommitment, EncryptedCommitment }
export { TokenType, OutputType, ChainType, SNARK_PRIME, ERC721_NOTE_VALUE }
