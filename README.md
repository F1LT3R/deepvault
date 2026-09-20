<center><img src="docs/logo.webp" alt="" /></center>

# vault

> Lock a directory into a single cascaded-encrypted file; open it back.

`vault` collapses a directory tree into one file by compressing a
deterministic tar and encrypting the result through a user-chosen stack of
unauthenticated ciphers (innermost first). Opening is the reverse: peel the
ciphers, locate the deflate stream, inflate, and extract.

- zero runtime dependencies (Node builtins only)
- Node 22.13+
- prompts are read from a TTY only; secrets are never printed

## Usage

```
vault lock <dir> <vaultfile.vlt>
vault open <vaultfile.vlt> <outdir>
vault list
vault check <stack> [more tokens...]
```

### lock

1. `Stack order (1+ tokens; see 'vault list'):` — comma-separated tokens,
   innermost first (e.g. `a256-ctr,sm4-ctr`).
2. `Confirm stack order:` — retype the same order.
3. `Vault passphrase:` (typed, hidden) — the Human Entry Passphrase.
4. `Confirm passphrase:`

The vault file is written atomically (`<vaultfile>.tmp` then rename) and is
refused if it already exists.

### open

1. `Vault passphrase:`
2. `Stack order (innermost first):`

Two failure shapes, both reported as one line:

- `vault: wrong passphrase/stack or tampered file` — nothing was written
  (no outdir created).
- `vault: integrity failure — N file(s) fully written before the failure
  point; inspect <outdir> before deleting` — the tail of the archive was
  corrupted; N files are complete.

By design the tool cannot tell a wrong passphrase from a tampered file —
the single message is intentional (no oracle).

### list

Prints the 47-token alphabet grouped by mode, with per-machine availability
and the max vault size each token allows. The footer shows the effective
scrypt N actually in use on this machine (probed at startup).

### check

Advisory report for a proposed stack: one line per token (DEPRECATED marked),
the stack ceiling, and a tip. Invalid tokens fail with
`vault: stack token not in alphabet: <token>`.

## Constraints & practice

- **HEP floor.** The passphrase must be at least `max(64, COUNT)` characters,
  where COUNT is the number of tokens. Checked before any KDF work.
- **Stack depth.** Unbounded — the only limits are the per-token ceiling and
  your patience (each layer is a full scrypt + a full pass over the data).
- **Ceilings.** 64-bit-block tokens (e.g. `3des-cbc`) cap the vault at 4 GiB
  of file content; other tokens are unlimited.
- **Symlinks and non-regular files are refused** (one line each, exit 1);
  entry names are limited to 100 UTF-8 bytes.
- **Cross-device caution.** The scrypt N is probed at startup (2^20, falling
  back to 2^10 in 2^5 steps) because some OpenSSL builds hard-cap N. A vault
  locked on a machine with N=2^20 opens on a machine with N=2^10 and vice
  versa — the KDF output is identical for the same N, so **if the probed N
  differs between lock and open machines, the passphrase will not verify.**
  Keep the vault on machines with the same effective N (the `vault list`
  footer shows it).
- **Memory.** lock and open stream; steady-state memory is O(chunk + 512)
  plus the scrypt scratch area.

## Security model (deliberate)

The ciphers are used **without authentication tags** (no GCM/etc.). The
format defends against the practical failures instead:

- R1 (1 KiB–64 KiB random prefix) + R2 (random suffix, 16-aligned) make the
  deflate offset unguessable and the stream length ambiguous; tampering
  inside R1 or R2 is a documented blind spot (flip it, the file still opens).
- Wrong HEP / wrong stack order / tampered early bytes all produce the same
  single failure message.
- Depth is unobservable: the same directory locked with a 3-token and an
  8-token stack produces byte-identical M0 when HEP+order match.
- mtime (seconds) is preserved on open; the tar is deterministic.

## Layout

- `bin/vault.js` — CLI entry
- `lib/mode.js` — token alphabet, availability probe, stack parsing, list/check rendering
- `lib/derive.js` — HEP section split + scrypt material derivation
- `lib/cascade.js` — lock/open pipelines, file format (VLT1)
- `lib/scan.js` — bounded deflate-offset scan (open side)
- `lib/tar.js` — deterministic USTAR writer/reader
- `lib/fsutil.js` — directory walk (symlink/type rejection, sorting)
- `test/vault.test.js` — acceptance suite (25 tests), pty-driven via `test/pty-run.py`

## Requirements

- Node 22.13+ (engines field enforced)
- An OpenSSL build exposing the ciphers you stack (`vault list` shows which
  are present on this machine)
