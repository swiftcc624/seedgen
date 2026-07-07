// Encrypt-to-public-key and decrypt, using the audited `age-encryption` library.
// Output is ASCII-armored so a backup is text-friendly (paste / QR / paper) and
// still opens with the standard `age` CLI, which auto-detects armor on decrypt.

import { Encrypter, Decrypter, armor } from 'age-encryption';
import { createHash } from 'node:crypto';

const ARMOR_HEADER = '-----BEGIN AGE ENCRYPTED FILE-----';

/** Basic shape check for an age recipient string. */
export function isRecipient(s) {
  return typeof s === 'string' && /^age1[0-9a-z]+$/.test(s.trim());
}

/**
 * Short, human-verifiable fingerprint of a recipient string, so the operator
 * can confirm the key matches the one on the air-gapped machine before sealing.
 */
export function fingerprint(recipient) {
  const h = createHash('sha256').update(recipient.trim()).digest('hex');
  return `${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8, 12)}`.toUpperCase();
}

/**
 * Encrypt `plaintext` (string) either to one or more age recipients, or with a
 * passphrase (scrypt — symmetric, so quantum-resistant). The two modes are
 * mutually exclusive: age's scrypt stanza cannot be combined with recipients.
 * Returns an ASCII-armored string.
 *
 * @param {string} plaintext
 * @param {{recipients?: string[], passphrase?: string|null}} opts
 */
export async function seal(plaintext, { recipients = [], passphrase = null } = {}) {
  const e = new Encrypter();
  if (passphrase) {
    if (recipients.length) throw new Error('passphrase and recipients are mutually exclusive');
    e.setPassphrase(passphrase);
  } else {
    if (!recipients.length) throw new Error('a passphrase or at least one recipient is required');
    for (const r of recipients) {
      if (!isRecipient(r)) throw new Error(`not a valid age recipient: ${r}`);
      e.addRecipient(r.trim());
    }
  }
  const ciphertext = await e.encrypt(plaintext); // Uint8Array
  return armor.encode(ciphertext);
}

/**
 * Decrypt an age file (armored or binary) with one or more identities
 * (`AGE-SECRET-KEY-1...`) and/or a passphrase. Returns the plaintext string.
 *
 * @param {string|Uint8Array} fileContents
 * @param {{identities?: string[], passphrase?: string|null}} opts
 */
export async function unseal(fileContents, { identities = [], passphrase = null } = {}) {
  if (!passphrase && !identities.length) {
    throw new Error('a passphrase or at least one identity is required');
  }
  const bytes =
    typeof fileContents === 'string' && fileContents.includes(ARMOR_HEADER)
      ? armor.decode(fileContents)
      : typeof fileContents === 'string'
        ? new TextEncoder().encode(fileContents)
        : fileContents;
  const d = new Decrypter();
  if (passphrase) d.addPassphrase(passphrase);
  for (const id of identities) d.addIdentity(id.trim());
  return await d.decrypt(bytes, 'text');
}
