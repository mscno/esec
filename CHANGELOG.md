# v0.7.0

Monorepo support: component-scoped environments and public-key key lookup.

- Dotted environment names: `esec decrypt registry.production -f .env` resolves
  `.env.registry.production`; any `.<format>[.<component>...].<env>` naming works
- Key lookup now tries, per location (env vars, then each keyring in priority order):
  `ESEC_PRIVATE_KEY_<FULL_SUFFIX>` (dots become underscores) → `ESEC_PRIVATE_KEY_<LAST_SEGMENT>`
  → `ESEC_PRIVATE_KEY_<file public key hex>`; the file's embedded public key is ground truth,
  so any file naming scheme works and key rotation needs no renames
- Pubkey-keyed entries are validated: a private key that doesn't match its public key errors loudly
- Per-key fallthrough across keyring locations (repo-local → global project → global default);
  previously an existing keyring missing the key was terminal
- `.esec-project` discovery stops at the git repository root — a parent directory's project
  file no longer leaks into repos that lack their own
- Project identifiers may include path segments for subprojects: `org/repo/services/registry`
- New exported helpers: `KeySuffixes`, `ResolveKey`, `ExtractPublicKey`,
  `crypto.PublicFromPrivate`

# v0.6.0

Global keyring store and esec-vault foundation:

- Add global keyring store: after the repo-local `.esec-keyring`, key lookup falls back to
  `~/.config/esec/keyrings/<org>_<repo>.keyring` (project from `.esec-project`) and
  `~/.config/esec/keyrings/default.keyring`; override the directory with `ESEC_KEYRING_DIR`
- Add git-style subcommand passthrough: `esec <x>` runs `esec-<x>` from PATH when `<x>` is not a
  builtin command (e.g. `esec vault` → `esec-vault`)
- Add `pkg/crypto` helpers `SealAnonymous`/`OpenAnonymous` (NaCl sealed boxes) and `DeriveKey` (HKDF)
- Add `pkg/projectfile` for reading and writing `.esec-project` files

# v0.5.0

CLI usability and conventions overhaul:

- Fix `--dry-run` encrypting files in place instead of printing to stdout (file is no longer modified)
- Fix `esec run` failing in non-TTY environments (CI pipelines, redirected stdio)
- Fix short flag collision: `--dry-run` is now `-n`; `-d` consistently means `--key-dir`
- Add `--output/-o` flag to `encrypt` for writing encrypted output to a separate file
- Add global `--quiet/-q` flag to suppress status output
- Add `ESEC_DEBUG`, `ESEC_FORMAT` and `ESEC_KEY_DIR` environment variable support for flags
- Status messages now go to stderr, keeping stdout clean for piping
- `decrypt` writes byte-accurate output (no extra trailing newline)
- `run` propagates the child process exit code and exits 130 on SIGINT
- Library logging now uses the CLI's logger; keyring permission warnings match CLI log format
- `--version` shows commit and build date; add Windows release builds
- Fix error message wrapping (`%w`) and remove "error:" stutter

# v0.3.0

Added options to the decrypt from embed function.

# v0.0.7

Fix version build flags

# v0.0.6

Docs update

# v0.0.5

# v0.0.4

Add version flag to the CLI

# v0.0.3

Some code cleanup and better docs