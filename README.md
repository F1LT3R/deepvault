# DeepVault

> Lock a directory into a single cascaded-encrypted file; open it back.

`vault` collapses a directory tree into one file by compressing a
deterministic tar and encrypting the result through a user-chosen stack of
unauthenticated ciphers (innermost first). Opening is the reverse: peel the
ciphers, locate the deflate stream, inflate, and extract.

- 🚫 zero runtime dependencies (Node builtins only)
- ⚡ Node 22.13+
- 🔇 prompts are read from a TTY only; secrets are never printed

## 🔐 Usage

```
vault lock <dir> <vaultfile.vlt>
vault open <vaultfile.vlt> <outdir>
vault list
vault check
```

### 🔒 lock

1. `Stack order (1+ tokens; see 'vault list'):` — comma-separated tokens,
   innermost first (e.g. `a256-ctr,sm4-ctr`).
2. `Confirm stack order:` — retype the same order.
3. `Vault passphrase:` (typed, hidden) — the Human Entry Passphrase.
4. `Confirm passphrase:`
5. `scrypt N (power of 2; this machine max <max>):` — the KDF cost for this
   vault, chosen from the machine-verified set shown in the `vault list`
   footer. It is typed, hidden, and **never written to the file**.

The vault file is written atomically (`<vaultfile>.tmp` then rename) and is
refused if it already exists.

### 🔓 open

1. `Vault passphrase:`
2. `Stack order (innermost first):`
3. `scrypt N (power of 2, as used at lock; this machine max <max>):` — the
   same N you typed at lock, retyped. A valid-but-different N is just a wrong
   guess: the same single failure message, no oracle.

Two failure shapes, both reported as one line:

- `vault: wrong passphrase/stack or tampered file` — nothing was written
  (no outdir created).
- `vault: integrity failure — N file(s) fully written before the failure
  point; inspect <outdir> before deleting` — the tail of the archive was
  corrupted; N files are complete.

By design the tool cannot tell a wrong passphrase from a tampered file —
and it cannot tell a wrong scrypt N either: wrong HEP, wrong stack order,
wrong depth, and wrong N all collapse to the same single message (no oracle).

### 📜 list

Prints the 47-token alphabet grouped by mode, with per-machine availability
and the max vault size each token allows. The footer lists the **machine-
verified scrypt N values** (every candidate actually probed on this machine,
e.g. `32768 (2^15)`) — that list is the menu you pick from when typing N at
lock/open.

### 🔍 check

Prompts for a proposed stack (same format as lock; no HEP needed) and prints an
advisory report: one line per token (DEPRECATED marked), the stack ceiling,
and a tip. Invalid tokens fail with
`vault: stack token not in alphabet: <token>`.

## ⚖️ Constraints & practice

- **HEP floor.** The passphrase must be at least `max(64, COUNT)` characters,
  where COUNT is the number of tokens. Checked before any KDF work.
- **Stack depth.** Unbounded — the only limits are the per-token ceiling and
  your patience (each layer is a full scrypt + a full pass over the data).
- **Ceilings.** 64-bit-block tokens (e.g. `3des-cbc`) cap the vault at 4 GiB
  of file content; other tokens are unlimited.
- **Symlinks and non-regular files are refused** (one line each, exit 1);
  entry names are limited to 100 UTF-8 bytes.
- **scrypt N discipline.** N is a third typed secret — never stored, never
  auto-selected. Some OpenSSL builds hard-cap the N they will run (this
  machine: max 32768 = 2^15), so a vault locked at N=2^20 **cannot be opened
  on a machine whose verified set tops out lower** — the typed N must be in
  the opening machine's `vault list` footer, or the open fails with the
  single phase-A message. Check the footer before locking on a machine you
  might later move away from; N is cheap to retype and fatal to forget.
- **Memory.** lock and open stream; steady-state memory is O(chunk + 512)
  plus the scrypt scratch area (128·N bytes per KDF call: 4 MiB at N=2^15,
  128 MiB at N=2^20).

## 🧠 HEP — what it is, and how one passphrase keys many layers

The HEP (Human Entry Passphrase) is the long passphrase you type — 64+ chars,
hidden, never printed. It is not a web-password: its job is to be long enough
that *length alone* makes the search space astronomical.

**Entropy in plain terms.** Entropy = how many candidates the attacker must
consider. Every character multiplies that count by the size of the character
set you could have drawn from:

- 64 chars from the 95 printable keyboard chars → 95^64 ≈ 2^420 ≈ 10^126 candidates
- 64 chars from lowercase letters only → 26^64 ≈ 2^301 ≈ 10^90
- a 12-char password from 95 chars → 95^12 ≈ 2^79 — already small; with
  dictionary structure a real 12-char password is far smaller still

**How one passphrase keys COUNT layers.** DeepVault does not compress the HEP
into a single master key that all layers derive from. It **splits the HEP
into COUNT contiguous slices** (they cover the HEP exactly, in order) and
**stretches each slice with scrypt** into that layer's key + IV:

```
HEP (L chars)  →  slice 1 ‖ slice 2 ‖ … ‖ slice COUNT     (contiguous, exact cover)
slice i        →  scrypt(slice i, salt‖i, N)  →  layer i's key ‖ IV
```

Two properties make this a wall instead of a projection:

1. **No smaller projection to attack.** A design where all layer keys derive
   from one 32-byte master would let the attacker search 2^256 masters
   directly — never touching your HEP — so the wall caps at the master's size
   no matter how long your passphrase is. With sections there is no
   intermediate object: the only input that reproduces all COUNT layers is
   the full L-char HEP. Your wall is L × log2(charset) bits, uncapped by HEP
   length.
2. **Verification is all-or-nothing.** Layer i peels correctly only if slice i
   is correct — but nothing tells you that until you have peeled all COUNT
   layers and the innermost content parses as a valid tar. A partial guess
   (right slice 1, wrong slice 2) is indistinguishable from a fully wrong
   guess: the same single failure message. The attacker cannot peel
   "halfway" or layer by layer — every candidate pays the full
   COUNT×scrypt + full peel, and the only oracle is the very last step.

The per-layer salt (`fileSalt ‖ LE32(layer index)`) keeps every scrypt call
distinct even if two slices happened to be equal. The HEP floor
`L ≥ max(64, COUNT)` keeps each slice from shrinking to a token as you add
layers.

## 🛡️ Security model (deliberate)

The ciphers are used **without authentication tags** (no GCM/etc.). The
format defends against the practical failures instead:

- R1 (1 KiB–64 KiB random prefix) + R2 (random suffix, 16-aligned) make the
  deflate offset unguessable and the stream length ambiguous; tampering
  inside R1 or R2 is a documented blind spot (flip it, the file still opens).
- Wrong HEP / wrong stack order / wrong depth / wrong scrypt N / tampered
  early bytes all produce the same single failure message.
- Three typed secrets (HEP, stack order, scrypt N) are **not stored in the
  file** — the header is magic + 4 reserved zero bytes + salt; the body is
  pure ciphertext (verified: 0 of 47 token strings appear in vault bytes).
- Depth is unobservable: the same directory locked with a 3-token and an
  8-token stack produces byte-identical M0 when HEP+order match.
- mtime (seconds) is preserved on open; the tar is deterministic.

## 🕰️ How crackable is this, really?

The honest way to read it: what must the attacker do, and what does that cost
in human time?

**What the attacker holds:** the vault file, this source code, the 47-token
alphabet, the file format — everything public. **What the attacker does not
hold:** your HEP (L chars), your stack order (which tokens, which order, how
many — depth included), and the N you typed. None of it is in the file.

**The attacker's walk.** For each candidate (order, HEP, N):

1. run COUNT scrypts at N (tens of ms each at N=2^15, ~1 s each at N=2^20,
   each allocating 128·N bytes),
2. peel COUNT layers over the whole file,
3. scan the first 128 KiB for the deflate offset,
4. inflate and check the innermost tar.

Only step 4 tells them anything. There is no layer-by-layer progress: a wrong
HEP or wrong order at any depth produces uniform noise the scan rejects, and
the file does not reveal how many layers there are — so the walk includes
every possible depth: 1 token, 47 tokens, 300 tokens — all of them
(47 + 47² + 47³ + … possible orders). "Try the first layer, see if it's
right, then the second" is not an option; there is no "right" to see until
the end.

**The math, in years.** Take a deliberately *weak* setup: a 1-token stack the
attacker fully knows, a 64-char lowercase HEP (2^301 ≈ 10^90 candidates), and
an attacker doing 10,000 full guesses per second — each guess already
paying one scrypt at N=2^15 plus a full peel (a generous rate for memory-hard
work):

```
2^301 / 2^13  ≈  2^288 guesses  ≈  10^86 s  ≈  10^79 years
```

The age of the universe is ~1.4×10^10 years (call it 10^10). That weak setup
still needs **~10^69 times the age of the universe** — a 1 followed by 69
zeros of universe-lifetimes. Now realistic:

| Setup | Candidates | Time at 10,000 guesses/s |
|---|---|---|
| 12-char password, *uniform* (no dictionary) | ~2^79 | ~10^12 years — and a real 12-char password is far smaller than 2^79 |
| 64-char HEP, lowercase (known stack) | 2^301 | ~10^79 years |
| 64-char HEP, 95 keyboard chars (known stack) | 2^420 | ~10^114 years |
| + a 2-token stack the attacker does not know | ×47² ≈ ×2,200 | ×2,200 more |
| + the attacker does not know the depth | ×(47 + 47² + … + 47^D) | unbounded multiplier |

At N=2^20 each guess costs ~1000× more KDF work — another ~10^3 in years on
every row.

Two honest caveats:

- These are **lower bounds on the attacker's problem**: they ignore the
  order/depth search (which only adds work), assume a fixed known stack, and
  fold the per-guess KDF cost into the flat 10k/s rate.
- **The HEP is your responsibility.** The math assumes random characters. A
  dictionary phrase, a reused password, or 64 chars made of words collapses
  the candidate count to the number of *likely* phrases — the 64-char floor
  is a minimum discipline, not a substitute for randomness.

**Quantum computers (Grover).** Grover's algorithm is the standard "quantum
future" speedup: search an unstructured N-candidate space in ~√N queries
instead of N.

- **Against the ciphers** it is a real design input, and the alphabet
  reflects it: AES/SM4/Camellia-128 → 64-bit effective under Grover (which is
  why their 256-bit siblings exist in the alphabet); AES/SM4/Camellia-256 and
  ChaCha20-256 → 128-bit (considered safe); 2DES (56 → 28-bit) and 3DES
  (112 → 56-bit) → dead — exactly why both are marked DEPRECATED and capped
  at 4 GiB vaults.
- **Against the HEP search**, even granting a full Grover speedup on the
  outer search: 2^420 → 2^210 → ~10^49 years ≈ 10^39 × the age of the
  universe. And the grant is a fiction: each "query" here is not one hash
  evaluation but COUNT memory-hard scrypts plus a full file peel. Memory-hard
  KDFs are chosen precisely because quantum speedups do not amortize the
  per-guess memory cost, and a machine holding 2^210 × (multi-megabyte
  scrypt states) in quantum memory is not a plausible machine.

Bottom line: Grover is a serious argument for *which ciphers you stack*
(prefer the 256-bit/stream tokens) and a theoretical footnote for the HEP
wall.

## 🧪 Testing & verification

**Acceptance suite — `npm test` (28 tests, ~40 s).** The suite drives the real
CLI through a pseudo-TTY (`test/pty-run.py`) plus lib-level tests:

- 🔁 round-trip at stack depths 3 / 10 / 16 — byte-exact trees incl. file AND
  dir mtimes
- 🔐 non-CTR modes (CBC/OFB/CFB, 3DES, Camellia, ChaCha20) round-trip
- 🕵️ known plaintext is absent from vault bytes; the HEP and the stack order
  are absent from file bytes AND terminal output
- ❌ wrong HEP, wrong order/depth, early tamper → the single phase-A message,
  no outdir created; late tamper → phase B with the count of complete files
- 🔢 scrypt N discipline: a valid-but-wrong N at open → the same single
  phase-A message (no oracle); non-power-of-2 and over-machine-max N rejected
  before any KDF
- 🕳️ R1/R2 blind spots verified: a flipped byte inside R2 is harmless, one
  inside the deflate is fatal
- 📏 HEP floor `max(64, COUNT)`; ceiling math + boundary; R2 16-alignment
  formula
- 🌫️ depth unobservability (3- vs 8-token stack → byte-identical M0); fresh
  salts → different bytes, both open
- 🧱 300-token stack round-trip; every available alphabet token in one
  cascade (test 26)
- 🚫 overwrite refusal, symlink rejection (one line each), missing vaultfile
  fails before any prompt, piped stdin refused
- 📜 `list` renders all 47 tokens with correct availability; `check` report
  + invalid-token path; zero runtime deps; `npm run check` gate

**Full cipher matrix — `node tmp/all-tokens.mjs` (53 round-trips).** Every
available token as a single-token stack (47 here) + 6 cross-family 2-layer
stacks (block⊕stream, OFB/CFB mixes) — each lock → open → byte-exact compare
including dir mtimes. This matrix is what caught the dir-mtime restoration bug
(fixed in `openVault`: dir mtimes are re-applied after all child writes).

**Verified end-to-end:** all 4 verbs and every failure path through the CLI
pty; `vault check` on the full 47-token stack (47 lines, 6 DEPRECATED, HEP
min 64, 4 GiB ceiling).

**Known-unverified territory:**

- machines that cannot run the N used at lock (verified-set differences —
  the open then fails with the single phase-A message; check the `vault list`
  footer before locking)
- all 47×47 pairwise layer combinations (per-cipher behaviour is fully covered
  by the matrix; the peel mechanics are cipher-independent)
- multi-GB vaults (5 MB paths are covered at lib level; CLI pty runs use
  small dirs)

## 🧩 Layout

- `bin/vault.js` — CLI entry
- `lib/mode.js` — token alphabet, availability probe, stack parsing, list/check rendering
- `lib/derive.js` — HEP section split + scrypt material derivation
- `lib/cascade.js` — lock/open pipelines, file format (VLT1)
- `lib/scan.js` — bounded deflate-offset scan (open side)
- `lib/tar.js` — deterministic USTAR writer/reader
- `lib/fsutil.js` — directory walk (symlink/type rejection, sorting)
- `test/vault.test.js` — acceptance suite (28 tests), pty-driven via `test/pty-run.py`

## 📦 Requirements

- Node 22.13+ (engines field enforced)
- An OpenSSL build exposing the ciphers you stack (`vault list` shows which
  are present on this machine)
