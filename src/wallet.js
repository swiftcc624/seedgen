// Seed generation + public derivation. No cryptography is hand-rolled here —
// entropy and BIP-39/32 come from the audited @scure/@noble libraries.

import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';

// Standard Ethereum-family account path: m/44'/60'/0'/0/<index>.
// Hyperliquid and every EVM chain use these addresses.
const ACCOUNT_NODE = "m/44'/60'/0'";

/**
 * Generate a fresh BIP-39 mnemonic. `words` is 12 or 24.
 * @scure draws entropy from the platform CSPRNG.
 */
export function newMnemonic(words = 24) {
  const strength = words === 12 ? 128 : 256; // bits of entropy
  return generateMnemonic(wordlist, strength);
}

/** EIP-55 mixed-case checksum for a 20-byte hex address (no 0x). */
function toChecksumAddress(hexNoPrefix) {
  const a = hexNoPrefix.toLowerCase();
  const h = bytesToHex(keccak_256(new TextEncoder().encode(a)));
  let out = '0x';
  for (let i = 0; i < a.length; i++) {
    out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  }
  return out;
}

/** Derive the EVM address for an HDKey node. */
function addressOf(node) {
  // Uncompressed pubkey (65 bytes), drop the 0x04 prefix -> 64 bytes.
  const pub = secp256k1.ProjectivePoint.fromHex(node.publicKey).toRawBytes(false).slice(1);
  const addr = bytesToHex(keccak_256(pub)).slice(-40);
  return toChecksumAddress(addr);
}

/**
 * Derive the PUBLIC-only material for a mnemonic:
 *   - account-level xpub (m/44'/60'/0') — safe to keep anywhere, derives all addresses
 *   - the receive address at m/44'/60'/0'/0/<index>
 * Returns only public data; the caller is responsible for wiping the seed.
 */
export function derivePublic(mnemonic, index = 0) {
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error('invalid mnemonic (checksum failed)');
  }
  const seed = mnemonicToSeedSync(mnemonic); // Uint8Array
  try {
    const root = HDKey.fromMasterSeed(seed);
    const account = root.derive(ACCOUNT_NODE);
    const addressNode = root.derive(`${ACCOUNT_NODE}/0/${index}`);
    return {
      path: `${ACCOUNT_NODE}/0/${index}`,
      address: addressOf(addressNode),
      xpub: account.publicExtendedKey,
    };
  } finally {
    seed.fill(0); // best-effort wipe of the derived seed bytes
  }
}
