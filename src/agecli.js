// Thin wrapper around the standard `age` binary, used ONLY when an SSH key is
// involved (typage cannot do SSH recipients). We never hand-roll crypto: this
// delegates to age itself. Plaintext/ciphertext cross the process boundary via
// in-memory stdin/stdout pipes only — never a temp file, never on argv.

import { spawn, execFileSync } from 'node:child_process';

const AGE_BIN = process.env.SEEDGEN_AGE_BIN || 'age';

/** Return the age binary version string (e.g. "1.3.1"), or null if unavailable. */
export function ageVersion() {
  try {
    const out = execFileSync(AGE_BIN, ['--version'], { encoding: 'utf8' }).trim();
    // age prints e.g. "1.3.1" or "v1.3.1"; normalize.
    return out.replace(/^v/, '');
  } catch {
    return null;
  }
}

/** Compare dotted versions: returns true if `have` >= `want`. */
export function versionAtLeast(have, want) {
  const a = String(have).split('.').map((n) => parseInt(n, 10) || 0);
  const b = String(want).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] || 0) - (b[i] || 0);
    if (d !== 0) return d > 0;
  }
  return true;
}

/** Run the age binary with args, piping `input` to stdin, resolving stdout. */
function runAge(args, input) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(AGE_BIN, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (e) {
      return reject(new Error(`could not run '${AGE_BIN}': ${e.message}`));
    }
    const out = [];
    const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => reject(new Error(`could not run '${AGE_BIN}': ${e.message}`)));
    child.on('close', (code) => {
      if (code === 0) resolve(Buffer.concat(out).toString('utf8'));
      else reject(new Error(Buffer.concat(err).toString('utf8').trim() || `age exited with code ${code}`));
    });
    child.stdin.on('error', () => {}); // ignore EPIPE if age exits early
    child.stdin.end(input);
  });
}

/**
 * Encrypt `plaintext` to the given recipients using the age binary, returning
 * ASCII-armored ciphertext. Recipients may be age-native strings, inline SSH
 * pubkey strings, or "@<path>" to pass a recipients/.pub file via -R.
 */
export async function sealWithBinary(plaintext, recipients) {
  const args = ['--armor', '--encrypt'];
  for (const r of recipients) {
    if (r.startsWith('@')) args.push('-R', r.slice(1)); // recipients/.pub file
    else args.push('-r', r); // recipient string (age1... or "ssh-ed25519 ...")
  }
  return runAge(args, plaintext);
}

/**
 * Decrypt armored/binary `ciphertext` with an identity FILE (age key file or
 * SSH private key), returning the plaintext string.
 */
export async function unsealWithBinary(ciphertext, identityPath) {
  return runAge(['--decrypt', '-i', identityPath], ciphertext);
}
