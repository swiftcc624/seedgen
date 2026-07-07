# Using seedgen

`seedgen` generates a crypto wallet seed and immediately **seals it to a backup
public key**. The plaintext seed is never stored or transmitted — it is only
decrypted later on the air-gapped machine that holds the matching secret key.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 1 — SETUP           Machine A  (air-gapped, secure, stays offline) │
│                                                                           │
│     age-keygen ─┬─▶  age1abc...            (PUBLIC key  → copy out)        │
│                 └─▶  AGE-SECRET-KEY-...     (SECRET key  → NEVER leaves)   │
└─────────────────────────────────────────────────────────────────────────┘
                          │
                          │  carry ONLY the public key  (USB / QR / paper)
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 2 — GENERATE        Machine B  (can be online; never sees a secret)│
│                                                                           │
│   seedgen generate --recipient age1abc... --out seed.age                  │
│                                                                           │
│        ┌── generate 24-word seed  (in memory only, briefly)               │
│        ├── derive ──▶  address + xpub  ─────────▶  PUBLIC, save anywhere   │
│        └── encrypt with age1abc... ─▶ seed.age ─▶  CIPHERTEXT, back up     │
│                        (plaintext seed wiped — B can never read it back)   │
└─────────────────────────────────────────────────────────────────────────┘
                          │                                    │
        seed.age  ────────┘                                    │  address/xpub
        (back up freely: cloud, USB, email — useless alone)    ▼
                          │                          use the wallet:
                          │                          receive funds, watch balance
                          │                          (NO seed needed)
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PHASE 3 — RECOVER         Machine A  (only when you must sign / move $)   │
│                                                                           │
│   age -d -i backupA.key seed.age  ─────▶  24-word seed                     │
│        (the SECRET key from Phase 1 is the only thing that opens it)       │
└─────────────────────────────────────────────────────────────────────────┘

Rule: the PUBLIC key travels (A → B) and locks the seed; the SECRET key never
travels — it stays on A and is the only thing that unlocks it.

With redundancy (two backup keys), only Phase 2 changes:
   seedgen generate --recipient age1abc... --recipient age1xyz... --out seed.age
   → seed.age opens with EITHER backupA.key OR backupB.key (lose one, still safe)
```

## Phase 1 — create the backup key (on the secure machine)

```bash
age-keygen -o backupA.key
# Public key: age1abc...        <- copy this string to Machine B
```

`backupA.key` contains the `AGE-SECRET-KEY-...`. It must never leave this
machine. For redundancy, repeat on a second secure machine to get `backupB.key`
/ `age1xyz...`.

## Phase 2 — generate & seal (on the generating machine)

```bash
seedgen generate \
  --recipient age1abc... \
  --recipient age1xyz... \   # optional 2nd key = recover even if one is lost
  --out seed.age
```

You will be shown each recipient's fingerprint and asked to confirm it matches
the key on your secure machine (this blocks a swapped-key attack). On success it
prints the **public** wallet address + account `xpub` and writes the encrypted
`seed.age`. The mnemonic itself is never printed or written in the clear.

Useful flags: `--words 12` (shorter seed), `--account 3` (show a different
receive index), `--yes` (skip the prompt, only if scripted), `--force`
(overwrite an existing output file).

## Phase 3 — recover (only on the secure machine)

Either the standard `age` tool:

```bash
age -d -i backupA.key seed.age        # prints the 24 words
```

or this CLI (same result, no `age` binary needed):

```bash
seedgen recover -i backupA.key --in seed.age
seedgen recover -i backupA.key --in seed.age --show-address   # sanity-check the address
```

## Known limitation

Node.js cannot reliably wipe a plaintext seed from memory (strings are immutable
and cleared only by garbage collection). Mitigate by running Phase 2 **offline**,
keeping the process short-lived, disabling swap, and never sharing the machine's
memory dump. This is a property of the runtime, not a bug in the tool.
