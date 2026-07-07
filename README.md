# seedgen

Offline CLI that generates a crypto wallet seed and **seals it to a backup
public key**. The plaintext seed phrase is never stored, printed, or
transmitted — it only exists briefly in memory on the generating machine and is
decrypted later on an air-gapped machine that holds the matching secret key.

This is *envelope-encryption backup*: the machine that creates the seed only
ever holds a **public** key, so it is physically unable to read the seed back.

## Why it's built this way

- **No hand-rolled cryptography.** Everything is a thin wrapper over audited
  libraries:
  - [`@scure/bip39`](https://github.com/paulmillr/scure-bip39) — CSPRNG entropy → BIP-39 mnemonic
  - [`@scure/bip32`](https://github.com/paulmillr/scure-bip32) — BIP-32/44 derivation (address + xpub)
  - [`@noble/curves`](https://github.com/paulmillr/noble-curves) / [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — secp256k1 + keccak for the EVM address
  - [`age-encryption`](https://github.com/FiloSottile/typage) — encrypt-to-public-key, interoperable with the standard [`age`](https://age-encryption.org) CLI
- **Multi-recipient backup.** Seal to several keys; any one secret key recovers
  the seed, so losing one is not fatal.
- **Fingerprint confirmation.** You must confirm each recipient's fingerprint
  before sealing — this blocks a swapped-key attack that would silently encrypt
  your seed to an attacker.
- **Minimal plaintext window.** Generate → derive public info → encrypt → drop.
  Nothing plaintext is logged, written to disk, put on the clipboard, or sent
  over the network.

## Install

```bash
npm install
npm test          # run the derivation + round-trip checks
npm link          # optional: puts `seedgen` on your PATH
```

Run it with `node src/index.js` from the project folder, or as the bare
`seedgen` command once you've run `npm link`. The examples below use the
`node src/index.js` form.

`age`/`age-keygen` are only needed to create backup keys and (optionally) to
recover; `seedgen recover` can also decrypt without them.

## Quick start

```bash
# On the SECURE machine:
age-keygen -o backupA.key            # note the "age1..." public key

# On the GENERATING machine (keep the command on ONE line):
node src/index.js generate --recipient age1abc... --out seed.age
#   → prints wallet address + xpub, writes encrypted seed.age

# Back on the SECURE machine, when you need the seed:
node src/index.js recover -i backupA.key --in seed.age
```

> Keep each command on a single line. If you press Enter in the middle, the
> shell splits it into two commands (e.g. `command not found: --out`). To wrap a
> long command, end every non-final line with a trailing `\` and no comment.

## Commands

```
seedgen generate (--recipient <age1...> [--recipient ...] | --passphrase)
                 [--out seed.age] [--words 12|24] [--account <n>] [--yes] [--force]
seedgen recover  (--identity <KEY|file> [--identity ...] | --passphrase)
                 [--in seed.age] [--show-address]
seedgen help
```

### Post-quantum backups

There are two quantum-resistant options:

1. **Post-quantum recipient (recommended).** age ≥ 1.3.0 has native
   post-quantum keys (`age-keygen -pq` → an `age1pq1...` recipient, hybrid
   ML-KEM-768). Pass it to `--recipient` exactly like a normal key — seedgen
   supports it out of the box (needs `age-encryption` ≥ 0.3.0). This keeps the
   asymmetric model: the generating machine holds only the public key.

   ```bash
   age-keygen -pq -o backupA-pq.key                 # on the secure machine
   node src/index.js generate --recipient age1pq1... --out seed.age
   node src/index.js recover  -i backupA-pq.key --in seed.age
   ```

2. **Passphrase mode.** `--passphrase` encrypts symmetrically (age's scrypt
   mode) with no key file at all — also post-quantum safe, but you must never
   forget the passphrase. Mutually exclusive with `--recipient`.

   ```bash
   node src/index.js generate --passphrase --out seed.age
   node src/index.js recover  --passphrase --in  seed.age
   ```

Full walkthrough and diagram: [USAGE.md](./USAGE.md).

## Wallet type

Addresses use the Ethereum/EVM path `m/44'/60'/0'/0/<index>` (works for
Hyperliquid and every EVM chain). The account-level `xpub` (`m/44'/60'/0'`) is
printed so you can watch/receive without ever exposing the seed.

## Known limitation

Node.js cannot reliably zero a plaintext string in memory (immutable strings +
GC). Run generation offline and short-lived to minimize exposure. Documented,
not pretended away.

## License

MIT
