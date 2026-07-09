// SSH-key support, end to end. Delegates to the `age` binary, so this test
// skips gracefully if `age` is not installed.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { seal, unseal, isSshRecipient, isRecipient } from '../src/seal.js';
import { ageVersion } from '../src/agecli.js';
import { derivePublic } from '../src/wallet.js';

const v = ageVersion();
if (!v) {
  console.log('SKIP  ssh e2e (age binary not found on PATH)');
  process.exit(0);
}
console.log(`(age binary ${v})`);

const dir = mkdtempSync(join(tmpdir(), 'seedgen-ssh-'));
const cleanup = () => rmSync(dir, { recursive: true, force: true });
process.on('exit', cleanup);

function sshKeygen(type, name, bits) {
  const f = join(dir, name);
  const args = ['-t', type, '-N', '', '-f', f, '-q'];
  if (bits) args.push('-b', String(bits));
  execFileSync('ssh-keygen', args);
  return { priv: f, pub: readFileSync(`${f}.pub`, 'utf8').trim() };
}

const MN = 'test test test test test test test test test test test junk';
const EXPECT = derivePublic(MN, 0).address;

// 1) ssh-ed25519 round-trip.
const ed = sshKeygen('ed25519', 'id_ed');
assert.ok(isSshRecipient(ed.pub) && isRecipient(ed.pub), 'ed25519 pub should be a recognized recipient');
const sealedEd = await seal(MN, { recipients: [ed.pub] });
assert.ok(sealedEd.includes('BEGIN AGE ENCRYPTED FILE'), 'ssh output not armored');
assert.equal(await unseal(sealedEd, { identityFiles: [ed.priv] }), MN, 'ssh-ed25519 round-trip mismatch');
console.log('ok  ssh-ed25519 round-trip');

// 2) ssh-rsa round-trip.
const rsa = sshKeygen('rsa', 'id_rsa', 3072);
const sealedRsa = await seal(MN, { recipients: [rsa.pub] });
assert.equal(await unseal(sealedRsa, { identityFiles: [rsa.priv] }), MN, 'ssh-rsa round-trip mismatch');
console.log('ok  ssh-rsa round-trip');

// 3) Mixed file: age-native + ssh recipients, openable by EITHER key type.
const ageId = await generateIdentity();
const ageRcpt = await identityToRecipient(ageId);
const mixed = await seal(MN, { recipients: [ageRcpt, ed.pub] });
assert.equal(await unseal(mixed, { identities: [ageId] }), MN, 'mixed: age identity failed');
assert.equal(await unseal(mixed, { identityFiles: [ed.priv] }), MN, 'mixed: ssh identity failed');
// derived address must match what generate would have shown
assert.equal(derivePublic(await unseal(mixed, { identityFiles: [ed.priv] }), 0).address, EXPECT);
console.log('ok  mixed age+ssh, either key opens it');

// 4) Wrong ssh key must fail.
const other = sshKeygen('ed25519', 'other', 0);
await assert.rejects(() => unseal(sealedEd, { identityFiles: [other.priv] }), 'wrong ssh key should fail');
console.log('ok  wrong ssh key rejected');

console.log('\nSSH e2e passed.');
