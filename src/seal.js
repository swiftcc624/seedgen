// Encrypt-to-public-key and decrypt. age-native (age1.../age1pq1...) and
// passphrase modes run fully in-process via the audited `age-encryption`
// library. SSH recipients/identities are delegated to the standard `age`
// binary (typage cannot do SSH), so we still never hand-roll crypto.
// Output is ASCII-armored so a backup is text-friendly and opens with plain age.

import { Encrypter, Decrypter, armor } from 'age-encryption';
import { createHash } from 'node:crypto';
import { sealWithBinary, unsealWithBinary, ageVersion, versionAtLeast } from './agecli.js';

const ARMOR_HEADER = '-----BEGIN AGE ENCRYPTED FILE-----';

/** age-native recipient (X25519 `age1...` or post-quantum `age1pq1...`). */
export function isAgeRecipient(s) {
  return typeof s === 'string' && /^age1[0-9a-z]+$/.test(s.trim());
}

/** Post-quantum age recipient (needs age >= 1.3.0 in the binary path). */
export function isPqRecipient(s) {
  return typeof s === 'string' && /^age1pq1/.test(s.trim());
}

/** OpenSSH public key line (ed25519 / rsa / ecdsa / sk-*). */
export function isSshRecipient(s) {
  return (
    typeof s === 'string' &&
    /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[\w-]+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-[\w-]+@openssh\.com)\s+\S+/.test(
      s.trim(),
    )
  );
}

/** Any recipient seedgen can seal to. */
export function isRecipient(s) {
  return isAgeRecipient(s) || isSshRecipient(s);
}

/**
 * Short, human-verifiable fingerprint of a recipient string, so the operator
 * can confirm the key matches the one on the air-gapped machine before sealing.
 */
export function fingerprint(recipient) {
  const h = createHash('sha256').update(recipient.trim()).digest('hex');
  return `${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8, 12)}`.toUpperCase();
}

/** Throw a clear error if SSH is requested but the age binary can't serve it. */
function requireAgeBinaryFor(recipients) {
  const v = ageVersion();
  if (!v) {
    throw new Error("SSH recipients require the 'age' binary on PATH (install age >= 1.1)");
  }
  if (recipients.some(isPqRecipient) && !versionAtLeast(v, '1.3.0')) {
    throw new Error(
      `mixing a post-quantum (age1pq1) recipient with SSH needs age >= 1.3.0, found ${v}`,
    );
  }
  return v;
}

/**
 * Encrypt `plaintext` (string) to recipients, or with a passphrase (scrypt —
 * symmetric, quantum-resistant). Passphrase and recipients are mutually
 * exclusive. Returns ASCII-armored ciphertext.
 *
 * @param {string} plaintext
 * @param {{recipients?: string[], passphrase?: string|null}} opts
 */
export async function seal(plaintext, { recipients = [], passphrase = null } = {}) {
  if (passphrase) {
    if (recipients.length) throw new Error('passphrase and recipients are mutually exclusive');
    const e = new Encrypter();
    e.setPassphrase(passphrase);
    return armor.encode(await e.encrypt(plaintext));
  }

  if (!recipients.length) throw new Error('a passphrase or at least one recipient is required');
  const rs = recipients.map((r) => r.trim());
  for (const r of rs) if (!isRecipient(r)) throw new Error(`not a valid recipient: ${r}`);

  // Any SSH recipient forces the age-binary path (it also handles age-native
  // recipients in the same file, so a mixed backup is openable by any key).
  if (rs.some(isSshRecipient)) {
    requireAgeBinaryFor(rs);
    return await sealWithBinary(plaintext, rs);
  }

  // All age-native: stay fully in-process.
  const e = new Encrypter();
  for (const r of rs) e.addRecipient(r);
  return armor.encode(await e.encrypt(plaintext));
}

/**
 * Decrypt an armored age file. Tries, in order: passphrase and/or inline age
 * identities (in-process), then each identity FILE via the age binary (this is
 * how SSH private keys — and age key files — are used). Returns the first
 * successful plaintext.
 *
 * @param {string|Uint8Array} fileContents
 * @param {{identities?: string[], identityFiles?: string[], passphrase?: string|null}} opts
 */
export async function unseal(fileContents, { identities = [], identityFiles = [], passphrase = null } = {}) {
  if (!passphrase && !identities.length && !identityFiles.length) {
    throw new Error('a passphrase or at least one identity is required');
  }
  const text =
    typeof fileContents === 'string' ? fileContents : new TextDecoder().decode(fileContents);
  const errors = [];

  // In-process path: passphrase and/or inline age identities.
  if (passphrase || identities.length) {
    try {
      const bytes = text.includes(ARMOR_HEADER) ? armor.decode(text) : new TextEncoder().encode(text);
      const d = new Decrypter();
      if (passphrase) d.addPassphrase(passphrase);
      for (const id of identities) d.addIdentity(id.trim());
      return await d.decrypt(bytes, 'text');
    } catch (e) {
      errors.push(e.message);
    }
  }

  // Binary path: SSH keys or age key files, each tried independently.
  for (const f of identityFiles) {
    try {
      return await unsealWithBinary(text, f);
    } catch (e) {
      errors.push(`${f}: ${e.message}`);
    }
  }

  throw new Error(errors.join('; ') || 'no identity could decrypt the file');
}
