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
npm link          # optional: puts `seedgen` on your PATH
npm test          # run the derivation + round-trip checks
```

`age`/`age-keygen` are only needed to create backup keys and (optionally) to
recover; `seedgen recover` can also decrypt without them.

## Quick start

```bash
# On the SECURE machine:
age-keygen -o backupA.key            # note the "age1..." public key

# On the GENERATING machine:
seedgen generate --recipient age1abc... --out seed.age
#   → prints wallet address + xpub, writes encrypted seed.age

# Back on the SECURE machine, when you need the seed:
seedgen recover -i backupA.key --in seed.age
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
