# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-20

### Added

- Initial vault: `lock`/`open` (VLT1 format — cascaded unauthenticated ciphers
  over R1 || deflate(deterministic USTAR) || R2, scrypt-derived materials)
- `list` and `check` advisory verbs (47-token alphabet, per-machine
  availability, stack ceiling, DEPRECATED markers)
- TTY-only prompts, HEP floor `max(64, COUNT)`, atomic vaultfile writes,
  single-message tamper/wrong-HEP failure (phase A / phase B on open)
- 25-test acceptance suite (`node --test`), pty-driven via `test/pty-run.py`

[0.1.0]: https://example.invalid/vault/compare/v0.0.0...v0.1.0