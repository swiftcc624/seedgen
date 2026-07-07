#!/usr/bin/env node
// seedgen — offline CLI: generate a wallet seed and seal it to a backup public key.
//
// Security model: the plaintext mnemonic is generated in memory, used only to
// derive PUBLIC data (address + xpub) and to encrypt itself to the given age
// recipient(s), then wiped. It is NEVER printed, written to disk in the clear,
// copied to the clipboard, logged, or sent over the network. Recovery happens
// only on the machine holding the age secret key.

import { parseArgs } from 'node:util';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { newMnemonic, derivePublic } from './wallet.js';
import { seal, unseal, isRecipient, fingerprint } from './seal.js';

const HELP = `seedgen — generate a wallet seed and seal it to a backup public key

USAGE
  seedgen generate --recipient <age1...> [--recipient <age1...>] [options]
  seedgen recover  --identity  <AGE-SECRET-KEY-1...> [--in <file>]
  seedgen help

GENERATE OPTIONS
  -r, --recipient <age1...>   Backup public key to encrypt to. Repeatable;
                              any one matching secret key can later recover.
  -o, --out <file>            Output ciphertext path (default: seed.age)
  -w, --words <12|24>         Mnemonic length (default: 24)
  -a, --account <n>           Receive-address index to show (default: 0)
  -y, --yes                   Skip the fingerprint confirmation prompt
  -f, --force                 Overwrite --out if it already exists

RECOVER OPTIONS
  -i, --identity <KEY|file>   age secret key string, or a path to a key file.
                              Repeatable.
      --in <file>            Ciphertext to decrypt (default: seed.age)
      --show-address          Also derive & print the address (sanity check)

Recovery is also possible without this tool:  age -d -i secret.key seed.age
`;

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

async function confirm(question) {
  if (!stdin.isTTY) {
    fail('confirmation required but input is not a terminal; re-run with --yes if you have verified the key');
  }
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    const ans = (await rl.question(question)).trim().toLowerCase();
    return ans === 'y' || ans === 'yes';
  } finally {
    rl.close();
  }
}

/** Accept an identity given either inline or as a path to a key file. */
function resolveIdentity(value) {
  const v = value.trim();
  if (v.startsWith('AGE-SECRET-KEY-')) return v;
  if (existsSync(v)) {
    // age key files may contain comment lines (`# ...`); pick the key line.
    const line = readFileSync(v, 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l.startsWith('AGE-SECRET-KEY-'));
    if (!line) fail(`no AGE-SECRET-KEY found in ${v}`);
    return line;
  }
  fail(`identity is neither an AGE-SECRET-KEY nor a readable file: ${value}`);
}

async function cmdGenerate(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      recipient: { type: 'string', short: 'r', multiple: true },
      out: { type: 'string', short: 'o', default: 'seed.age' },
      words: { type: 'string', short: 'w', default: '24' },
      account: { type: 'string', short: 'a', default: '0' },
      yes: { type: 'boolean', short: 'y', default: false },
      force: { type: 'boolean', short: 'f', default: false },
    },
    allowPositionals: false,
  });

  const recipients = (values.recipient ?? []).map((r) => r.trim());
  if (recipients.length === 0) fail('at least one --recipient (age1...) is required');
  for (const r of recipients) if (!isRecipient(r)) fail(`not a valid age recipient: ${r}`);

  const words = values.words === '12' ? 12 : values.words === '24' ? 24 : fail('--words must be 12 or 24');
  const index = Number.parseInt(values.account, 10);
  if (!Number.isInteger(index) || index < 0) fail('--account must be a non-negative integer');

  if (existsSync(values.out) && !values.force) {
    fail(`refusing to overwrite existing ${values.out} (use --force)`);
  }

  // Confirm each recipient's fingerprint against the air-gapped machine.
  console.error('Sealing the seed to these backup key(s):');
  for (const r of recipients) {
    console.error(`  ${fingerprint(r)}   ${r}`);
  }
  if (!values.yes) {
    const ok = await confirm('Do these fingerprints match the keys on your secure machine? [y/N] ');
    if (!ok) fail('aborted — fingerprints not confirmed');
  }

  // --- sensitive section: keep it short, never print the mnemonic ---
  let mnemonic = newMnemonic(words);
  try {
    const pub = derivePublic(mnemonic, index);
    const armored = await seal(mnemonic, recipients);
    writeFileSync(values.out, armored, { mode: 0o600 });

    console.log('');
    console.log('  Wallet address :', pub.address);
    console.log('  Path           :', pub.path);
    console.log('  Account xpub   :', pub.xpub);
    console.log('  Encrypted seed :', values.out, `(${recipients.length} recipient(s))`);
    console.log('');
    console.log('  The plaintext seed was never stored. Recover it with:');
    console.log(`    age -d -i <secret.key> ${values.out}`);
    console.log(`    seedgen recover -i <secret.key> --in ${values.out}`);
  } finally {
    // Best-effort wipe. Note: JS strings are immutable and cannot be reliably
    // zeroed; see the "Known limitation" section in README/USAGE.
    mnemonic = null;
  }
}

async function cmdRecover(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      identity: { type: 'string', short: 'i', multiple: true },
      in: { type: 'string', default: 'seed.age' },
      'show-address': { type: 'boolean', default: false },
    },
    allowPositionals: false,
  });

  const ids = (values.identity ?? []).map(resolveIdentity);
  if (ids.length === 0) fail('at least one --identity (AGE-SECRET-KEY-... or key file) is required');
  if (!existsSync(values.in)) fail(`ciphertext not found: ${values.in}`);

  const contents = readFileSync(values.in, 'utf8');
  let mnemonic;
  try {
    mnemonic = await unseal(contents, ids);
  } catch (e) {
    fail(`decryption failed (wrong key or corrupt file): ${e.message}`);
  }

  if (values['show-address']) {
    const pub = derivePublic(mnemonic, 0);
    console.error(`  (address ${pub.address})`);
  }
  // This is the one place the plaintext is meant to be shown — on the secure
  // machine, by explicit request.
  console.log(mnemonic);
}

async function main() {
  const [, , cmd, ...rest] = process.argv;
  switch (cmd) {
    case 'generate':
    case 'gen':
      return cmdGenerate(rest);
    case 'recover':
      return cmdRecover(rest);
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      stdout.write(HELP);
      return;
    default:
      fail(`unknown command: ${cmd}\n\n${HELP}`);
  }
}

main().catch((e) => fail(e.message));
