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

export type { TokenData, Chain, AddressData, NoteCiphertext, NoteBase, ShieldNote, TransactNote, UnshieldNote }
export { TokenType, OutputType, ChainType }
