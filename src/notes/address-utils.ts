import { parse as parse0zkAddress, stringify as stringify0zkAddress } from '@railgun-reloaded/0zk-addresses'

import { bigintToUint8Array, uint8ArrayToBigInt } from '../encoding'

import type { AddressData } from './definitions'

/**
 * Converts wallet-node AddressData to the format expected by @railgun-reloaded/0zk-addresses stringify.
 * @param addressData - The wallet-node AddressData with bigint masterPublicKey
 * @returns Address data compatible with 0zk-addresses stringify
 */
function to0zkAddressData (addressData: AddressData) {
  return {
    masterPublicKey: bigintToUint8Array(addressData.masterPublicKey, 32),
    viewingPublicKey: addressData.viewingPublicKey,
  }
}

/**
 * Converts @railgun-reloaded/0zk-addresses parsed address back to wallet-node AddressData.
 * @param parsed - The parsed address data from 0zk-addresses parse
 * @returns Wallet-node AddressData with bigint masterPublicKey
 */
function from0zkAddressData (parsed: ReturnType<typeof parse0zkAddress>): AddressData {
  return {
    masterPublicKey: uint8ArrayToBigInt(parsed.masterPublicKey),
    viewingPublicKey: parsed.viewingPublicKey,
  }
}

/**
 * Encodes wallet-node AddressData into a bech32m RAILGUN address string.
 * @param addressData - The wallet-node AddressData to encode
 * @returns Bech32m encoded address string with '0zk' prefix
 */
function encodeAddress (addressData: AddressData): string {
  return stringify0zkAddress(to0zkAddressData(addressData))
}

/**
 * Decodes a bech32m RAILGUN address string into wallet-node AddressData.
 * @param address - Bech32m encoded RAILGUN address
 * @returns Wallet-node AddressData
 */
function decodeAddress (address: string): AddressData {
  return from0zkAddressData(parse0zkAddress(address))
}

export { to0zkAddressData, from0zkAddressData, encodeAddress, decodeAddress }
