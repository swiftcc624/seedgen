// Minimal sanity test: derivation must match a well-known vector, and a
// seal -> unseal round-trip must return the same mnemonic.
import assert from 'node:assert/strict';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { derivePublic, newMnemonic } from '../src/wallet.js';
import { seal, unseal, fingerprint } from '../src/seal.js';

// 1) Known hardhat/anvil mnemonic -> account 0 address (m/44'/60'/0'/0/0).
const KNOWN = 'test test test test test test test test test test test junk';
const pub = derivePublic(KNOWN, 0);
assert.equal(pub.address, '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 'address vector mismatch');
assert.ok(pub.xpub.startsWith('xpub'), 'xpub missing');
console.log('ok  derivation vector      ', pub.address);

// 2) A freshly generated 24-word mnemonic derives a valid checksummed address.
const mn = newMnemonic(24);
assert.equal(mn.trim().split(/\s+/).length, 24, 'expected 24 words');
const p2 = derivePublic(mn, 0);
assert.match(p2.address, /^0x[0-9a-fA-F]{40}$/, 'bad address format');
console.log('ok  fresh mnemonic derive  ', p2.address);

// 3) seal -> unseal round-trip with a real age identity.
const identity = await generateIdentity();      // AGE-SECRET-KEY-1...
const recipient = await identityToRecipient(identity); // age1...
const armored = await seal(mn, [recipient]);
assert.ok(armored.includes('BEGIN AGE ENCRYPTED FILE'), 'output not armored');
const round = await unseal(armored, [identity]);
assert.equal(round, mn, 'round-trip mnemonic mismatch');
console.log('ok  seal/unseal round-trip ', fingerprint(recipient));

// 4) Wrong identity must fail to decrypt.
const otherId = await generateIdentity();
await assert.rejects(() => unseal(armored, [otherId]), 'wrong key should not decrypt');
console.log('ok  wrong key rejected');

console.log('\nAll tests passed.');
