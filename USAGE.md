# Using seedgen

`seedgen` generates a crypto wallet seed and immediately **seals it to a backup
public key**. The plaintext seed is never stored or transmitted — it is only
decrypted later on the air-gapped machine that holds the matching secret key.

> **How to run it.** If you haven't installed it globally, invoke it with
> `node src/index.js` from the project folder. If you run `npm link` once, you
> can use the bare command `seedgen` instead. In the examples below,
> **`seedgen` = `node src/index.js`** unless you've linked it.

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

Single recipient — **keep the whole command on one line:**

```bash
node src/index.js generate --recipient age1abc... --out seed.age
```

Two recipients (recover even if one key is lost):

```bash
node src/index.js generate --recipient age1abc... --recipient age1xyz... --out seed.age
```

> ⚠️ **Keep it on one line.** If you press Enter mid-command, the shell runs the
> two halves as separate commands (you'll see errors like
> `command not found: --out`, and `generate` runs with whatever was on the first
> line only). If you *want* to split it, end **every** non-final line with a
> trailing backslash and put **no comment after it**:
>
> ```bash
> node src/index.js generate \
>   --recipient age1abc... \
>   --recipient age1xyz... \
>   --out seed.age
> ```

You will be shown each recipient's fingerprint and asked to confirm it matches
the key on your secure machine (this blocks a swapped-key attack). On success it
prints the **public** wallet address + account `xpub` and writes the encrypted
`seed.age`. The mnemonic itself is never printed or written in the clear.

Useful flags: `--words 12` (shorter seed), `--account 3` (show a different
receive index), `--yes` (skip the confirmation prompt — only when scripted),
`--force` (overwrite an existing output file).

### Post-quantum options (quantum-resistant)

The default `age1...` recipient uses X25519, which a future quantum computer
could break. Two ways to be quantum-resistant:

**Option A — post-quantum recipient (recommended).** age ≥ 1.3.0 can generate a
native post-quantum key with `age-keygen -pq`; its public key starts with
`age1pq1...` (hybrid ML-KEM-768). Use it anywhere you'd use a normal recipient —
seedgen accepts it directly (requires `age-encryption` ≥ 0.3.0). This keeps the
public-key model: Machine B still holds no secret.

```bash
# Phase 1 on the secure machine:
age-keygen -pq -o backupA-pq.key       # public key: age1pq1...

# Phase 2 on the generating machine:
node src/index.js generate --recipient age1pq1... --out seed.age

# Phase 3 recovery on the secure machine:
node src/index.js recover -i backupA-pq.key --in seed.age
```

**Option B — passphrase.** Encrypt the seed with a **passphrase** (age's
symmetric scrypt mode) — also post-quantum safe, and needs no key file at all.

```bash
node src/index.js generate --passphrase --out seed.age
# prompts (hidden): Passphrase: … / Confirm passphrase: …
```

Use a strong passphrase (a handful of random words). ⚠️ With Option B there is
**no key file** to fall back on — if you forget the passphrase, the seed is gone
forever. `--passphrase` and `--recipient` are mutually exclusive; pick one per
file.

## Phase 3 — recover (only on the secure machine)

Either the standard `age` tool:

```bash
age -d -i backupA.key seed.age        # prints the seed words
```

or this CLI (same result, no `age` binary needed):

```bash
node src/index.js recover -i backupA.key --in seed.age
node src/index.js recover -i backupA.key --in seed.age --show-address   # sanity-check the address
```

`-i` accepts either the key file (`backupA.key`) or the raw
`AGE-SECRET-KEY-1...` string, and can be repeated to try multiple keys.

If you sealed with a passphrase, recover with `--passphrase` instead:

```bash
node src/index.js recover --passphrase --in seed.age   # prompts for the passphrase
age -d seed.age                                        # standard age, also prompts
```

## Known limitation

Node.js cannot reliably wipe a plaintext seed from memory (strings are immutable
and cleared only by garbage collection). Mitigate by running Phase 2 **offline**,
keeping the process short-lived, disabling swap, and never sharing the machine's
memory dump. This is a property of the runtime, not a bug in the tool.
