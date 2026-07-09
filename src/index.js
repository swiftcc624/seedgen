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
import { seal, unseal, isRecipient, isSshRecipient, fingerprint } from './seal.js';
import { ageVersion } from './agecli.js';

const HELP = `seedgen — generate a wallet seed and seal it to a backup public key

USAGE
  seedgen generate --recipient <age1...|ssh-...|file> [--recipient ...] [options]
  seedgen recover  --identity  <AGE-SECRET-KEY-1...|keyfile> [--in <file>]
  seedgen help

GENERATE OPTIONS
  -r, --recipient <key>       Backup public key to encrypt to. Accepts an age
                              key (age1.../age1pq1...), an SSH public key
                              ("ssh-ed25519 ..."/"ssh-rsa ..."), or a .pub file.
                              Repeatable; any one matching key can later recover.
  -p, --passphrase            Encrypt with a passphrase instead of recipients
                              (symmetric/scrypt — quantum-resistant). Prompts.
  -o, --out <file>            Output ciphertext path (default: seed.age)
  -w, --words <12|24>         Mnemonic length (default: 24)
  -a, --account <n>           Receive-address index to show (default: 0)
  -y, --yes                   Skip the fingerprint confirmation prompt
  -f, --force                 Overwrite --out if it already exists

  Provide EITHER --recipient (one or more) OR --passphrase, not both.
  SSH recipients require the 'age' binary on PATH (age >= 1.1).

RECOVER OPTIONS
  -i, --identity <KEY|file>   age secret key string, an age key file, or an SSH
                              private key file. Repeatable.
  -p, --passphrase            Decrypt a passphrase-encrypted file. Prompts.
      --in <file>             Ciphertext to decrypt (default: seed.age)
      --show-address          Also derive & print the address (sanity check)

  SSH identities require the 'age' binary on PATH.

Recovery is also possible without this tool:
  age -d -i secret.key seed.age     (age or SSH key)
  age -d seed.age                   (passphrase mode — age will prompt)
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

// For piped stdin (scripts/tests) we read it once and serve lines from a queue,
// because opening/closing a readline per prompt would discard buffered lines.
let pipedLines = null;
let pipedIdx = 0;
async function readAllStdin() {
  const chunks = [];
  for await (const c of stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

/** Read a line without echoing it (for passphrases). Over a TTY the typed
 *  characters are hidden; over a pipe nothing is echoed anyway. */
async function readSecret(promptText) {
  if (!stdin.isTTY) {
    if (pipedLines === null) pipedLines = (await readAllStdin()).split(/\r?\n/);
    return pipedLines[pipedIdx++] ?? '';
  }
  const rl = createInterface({ input: stdin, output: stdout, terminal: true });
  let muted = false;
  rl._writeToOutput = (str) => {
    if (!muted) stdout.write(str); // show the prompt, hide the typed chars
  };
  try {
    const p = rl.question(promptText);
    muted = true;
    return await p;
  } finally {
    rl.close();
    stdout.write('\n');
  }
}

/** Prompt twice and confirm a passphrase for encryption. */
async function readNewPassphrase() {
  const a = await readSecret('Passphrase: ');
  if (a.length < 8) fail('passphrase too short — use at least 8 characters (a few random words is better)');
  const b = await readSecret('Confirm passphrase: ');
  if (a !== b) fail('passphrases do not match');
  return a;
}

/** Resolve a --recipient value to a recipient STRING. Accepts an age/SSH key
 *  string directly, or a path to a file whose first key-like line is used
 *  (e.g. an SSH `.pub` file). */
function resolveRecipient(value) {
  const v = value.trim();
  if (isRecipient(v)) return v;
  if (existsSync(v)) {
    const line = readFileSync(v, 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l && !l.startsWith('#'));
    if (line && isRecipient(line)) return line;
    fail(`file ${v} does not contain a recognizable recipient`);
  }
  fail(`not a valid recipient (age1.../ssh-... or a .pub file): ${value}`);
}

/** Classify a --identity value into an in-process age identity or a key FILE
 *  (SSH private keys and age key files are handled by the age binary). */
function classifyIdentity(value) {
  const v = value.trim();
  if (v.startsWith('AGE-SECRET-KEY-')) return { kind: 'age', value: v };
  if (existsSync(v)) {
    const content = readFileSync(v, 'utf8');
    // An age key file: use the inline key in-process (no binary needed).
    const ageLine = content
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l.startsWith('AGE-SECRET-KEY-'));
    if (ageLine) return { kind: 'age', value: ageLine };
    // Otherwise treat it as a key file for the age binary (e.g. SSH key).
    return { kind: 'file', value: v };
  }
  fail(`identity is neither an AGE-SECRET-KEY nor a readable file: ${value}`);
}

async function cmdGenerate(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      recipient: { type: 'string', short: 'r', multiple: true },
      passphrase: { type: 'boolean', short: 'p', default: false },
      out: { type: 'string', short: 'o', default: 'seed.age' },
      words: { type: 'string', short: 'w', default: '24' },
      account: { type: 'string', short: 'a', default: '0' },
      yes: { type: 'boolean', short: 'y', default: false },
      force: { type: 'boolean', short: 'f', default: false },
    },
    allowPositionals: false,
  });

  const rawRecipients = values.recipient ?? [];
  if (values.passphrase && rawRecipients.length > 0) {
    fail('use EITHER --passphrase OR --recipient, not both');
  }
  if (!values.passphrase && rawRecipients.length === 0) {
    fail('provide --passphrase or at least one --recipient (age1.../ssh-...)');
  }
  const recipients = rawRecipients.map(resolveRecipient);
  // SSH recipients are sealed via the age binary — check it exists up front,
  // before we generate any seed material.
  if (recipients.some(isSshRecipient) && !ageVersion()) {
    fail("SSH recipients require the 'age' binary on PATH (install age >= 1.1)");
  }

  const words = values.words === '12' ? 12 : values.words === '24' ? 24 : fail('--words must be 12 or 24');
  const index = Number.parseInt(values.account, 10);
  if (!Number.isInteger(index) || index < 0) fail('--account must be a non-negative integer');

  if (existsSync(values.out) && !values.force) {
    fail(`refusing to overwrite existing ${values.out} (use --force)`);
  }

  // Establish how the seed will be sealed (passphrase or recipient keys).
  let passphrase = null;
  if (values.passphrase) {
    console.error('Encrypting with a passphrase (symmetric/scrypt — quantum-resistant).');
    console.error('If you lose this passphrase, the seed is unrecoverable. Store it safely.');
    passphrase = await readNewPassphrase();
  } else {
    // Confirm each recipient's fingerprint against the air-gapped machine.
    console.error('Sealing the seed to these backup key(s):');
    for (const r of recipients) {
      console.error(`  ${fingerprint(r)}   ${r}`);
    }
    if (!values.yes) {
      const ok = await confirm('Do these fingerprints match the keys on your secure machine? [y/N] ');
      if (!ok) fail('aborted — fingerprints not confirmed');
    }
  }

  // --- sensitive section: keep it short, never print the mnemonic ---
  let mnemonic = newMnemonic(words);
  try {
    const pub = derivePublic(mnemonic, index);
    const armored = await seal(mnemonic, { recipients, passphrase });
    writeFileSync(values.out, armored, { mode: 0o600 });

    const how = passphrase ? 'passphrase (scrypt)' : `${recipients.length} recipient(s)`;
    console.log('');
    console.log('  Wallet address :', pub.address);
    console.log('  Path           :', pub.path);
    console.log('  Account xpub   :', pub.xpub);
    console.log('  Encrypted seed :', values.out, `(${how})`);
    console.log('');
    console.log('  The plaintext seed was never stored. Recover it with:');
    if (passphrase) {
      console.log(`    age -d ${values.out}                      # age will prompt for the passphrase`);
      console.log(`    seedgen recover --passphrase --in ${values.out}`);
    } else {
      console.log(`    age -d -i <secret.key> ${values.out}`);
      console.log(`    seedgen recover -i <secret.key> --in ${values.out}`);
    }
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
      passphrase: { type: 'boolean', short: 'p', default: false },
      in: { type: 'string', default: 'seed.age' },
      'show-address': { type: 'boolean', default: false },
    },
    allowPositionals: false,
  });

  const parsed = (values.identity ?? []).map(classifyIdentity);
  const identities = parsed.filter((p) => p.kind === 'age').map((p) => p.value);
  const identityFiles = parsed.filter((p) => p.kind === 'file').map((p) => p.value);

  if (values.passphrase && parsed.length > 0) fail('use EITHER --passphrase OR --identity, not both');
  if (!values.passphrase && parsed.length === 0) {
    fail('provide --passphrase or at least one --identity (AGE-SECRET-KEY-... or key file)');
  }
  if (identityFiles.length && !ageVersion()) {
    fail("SSH/key-file identities require the 'age' binary on PATH (install age >= 1.1)");
  }
  if (!existsSync(values.in)) fail(`ciphertext not found: ${values.in}`);

  const passphrase = values.passphrase ? await readSecret('Passphrase: ') : null;

  const contents = readFileSync(values.in, 'utf8');
  let mnemonic;
  try {
    mnemonic = await unseal(contents, { identities, identityFiles, passphrase });
  } catch (e) {
    fail(`decryption failed (wrong key/passphrase or corrupt file): ${e.message}`);
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
