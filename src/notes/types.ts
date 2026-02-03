/**
 * @enum {number} TokenType
 * Enumeration of supported token types in RAILGUN.
 */
export enum TokenType {
  ERC20 = 0,
  ERC721 = 1,
  ERC1155 = 2,
}

/**
 * @enum {number} OutputType
 * Enumeration of output types in transactions.
 */
export enum OutputType {
  Transfer = 0,
  BroadcasterFee = 1,
  Change = 2,
}

/**
 * @typedef {object} TokenData
 * Represents data for a token, including its type, address, and sub-ID.
 */
export type TokenData = {
  tokenType: TokenType;
  tokenAddress: string;
  tokenSubID: string;
};

/**
 * @enum {number} ChainType
 * Enumeration of supported blockchain chain types.
 */
export enum ChainType {
  EVM = 0,
}

/**
 * @typedef {object} Chain
 * Represents a blockchain chain with its type and ID.
 */
export type Chain = {
  type: ChainType;
  id: number;
};

/**
 * @typedef {object} AddressData
 * Contains address-related data including public keys and optional chain/version info.
 */
export type AddressData = {
  masterPublicKey: bigint;
  viewingPublicKey: Uint8Array;
  chain?: Chain;
  version?: number;
};

/**
 * @typedef {object} NoteCiphertext
 * Represents the ciphertext data for a note, including IV, tag, and encrypted data.
 */
export type NoteCiphertext = {
  iv: string;
  tag: string;
  data: string[];
};

/**
 * @interface NoteBase
 * Base interface for all note types, containing common properties.
 * @property {string} notePublicKey - Also known as npk
 * @property {string} random - 16 byte random
 * @property {bigint} value - The value of the note
 * @property {TokenData} tokenData - Token data
 */
export interface NoteBase {
  notePublicKey: string;
  random: string;
  value: bigint;
  tokenData: TokenData;
}

/**
 * @interface ShieldNote
 * Interface for shield notes, extending NoteBase with additional properties for shielding.
 */
export interface ShieldNote extends NoteBase {
  masterPublicKey: bigint;
  tokenHash: string;
}

/**
 * @interface TransactNote
 * Interface for transaction notes, extending NoteBase with sender/receiver data and transaction details.
 * @property {AddressData} receiverAddressData - address data of recipient
 * @property {AddressData | undefined} senderAddressData - address data of sender
 * @property {string} tokenHash - 32 byte hash of token data
 * @property {bigint} hash - Note hash
 * @property {OutputType | undefined} outputType
 * @property {string | undefined} walletSource
 * @property {string | undefined} senderRandom
 * @property {string | undefined} memoText
 * @property {string | undefined} shieldFee - Only used during serialization/storage of ShieldCommitments.
 * @property {number | undefined} blockNumber
 */
export interface TransactNote extends NoteBase {
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
 * @interface UnshieldNote
 * Interface for unshield notes, extending NoteBase with unshielding-specific properties.
 */
export interface UnshieldNote extends NoteBase {
  toAddress: string;
  hash: bigint;
  allowOverride: boolean;
}
