import type { Ciphertext } from '@railgun-reloaded/cryptography'

/**
 * SNARK scalar field prime used in RAILGUN's zero-knowledge proofs.
 * This is the maximum value for field elements in the BN254 curve.
 */
const SNARK_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n as const

/**
 * Standard value for ERC721 notes - always 1 since NFTs are non-fungible.
 */
const ERC721_NOTE_VALUE = 1n as const

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

enum TXIDVersion {
  V2_PoseidonMerkle = 'V2_PoseidonMerkle',
  V3_PoseidonMerkle = 'V3_PoseidonMerkle',
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

/**
 * Interface for resolving a token hash to full token data.
 * Matches the engine's TokenDataGetter pattern.
 */
interface TokenDataGetter {
  getTokenDataFromHash (txidVersion: TXIDVersion, chain: Chain, tokenHash: string): Promise<TokenData>
}

/**
 * Raw commitment ciphertext as received from on-chain events.
 * Matches the format in TransactionStructV2.boundParams.commitmentCiphertext[].
 */
type CommitmentCiphertextStruct = {
  ciphertext: string[]
  blindedSenderViewingKey: string
  blindedReceiverViewingKey: string
  annotationData: string
  memo: string
}

/**
 * Formatted commitment ciphertext with parsed Uint8Array fields,
 * ready for use by decryptCommitment.
 */
type FormattedCommitmentCiphertext = {
  ciphertext: Ciphertext
  blindedSenderViewingKey: Uint8Array
  blindedReceiverViewingKey: Uint8Array
  annotationData: Uint8Array
  memo: Uint8Array
}

export type { Ciphertext } from '@railgun-reloaded/cryptography'
export type { EncryptedCommitment, GeneratedCommitment, ShieldCommitment, TransactCommitment, Unshield } from '@railgun-reloaded/scanner'
export type { TokenData, Chain, AddressData, NoteCiphertext, LegacyCiphertext, EncryptedData, NoteAnnotationData, LegacyTransactNoteSerialized, TransactNoteSerialized, TokenDataGetter, CommitmentCiphertextStruct, FormattedCommitmentCiphertext }
export { TokenType, OutputType, TXIDVersion, ChainType, SNARK_PRIME, ERC721_NOTE_VALUE, MEMO_SENDER_RANDOM_NULL }
