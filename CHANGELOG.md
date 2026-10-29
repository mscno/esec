# v0.12.1

- Document the companion esec-vault v0.23.0 self-service personal/work tenant
  flow, collision recovery and receiving-owner project transfers through
  `esec vault`. The companion CLI and upgraded vault server implement these
  features; this release does not change the esec library or file formats.

# v0.12.0

- **`esec.toml` replaces `.esec-project`** (no compatibility): the project
  id, how its secrets files are named (applied over `config.toml`, so every
  machine finds them alike), and each environment's public key, guard and
  readers. Edits keep comments and layout; unknown keys are listed, not
  fatal, so an older esec reads a file a newer one wrote.
- **Sealed keys**: an environment's private key can live in the repository
  as `.esec/<env>.age`, a standard age file to its readers (`pkg/seal`).
  When no keyring holds the key, esec opens it with the identity in
  `ESEC_AGE_IDENTITY` or `ESEC_AGE_IDENTITY_FILE`, checking the project,
  environment and the public key the files use: CI and deploys need only
  esec.
- **Embedded seals**: a binary that embeds `esec.toml`, its file and
  `.esec/<env>.age` decrypts with `ESEC_AGE_IDENTITY` alone, a secret that
  survives rotation; with no `ESEC_PRIVATE_KEY*` set, the environment is
  the one whose seal the identity opens. `ESEC_PRIVATE_KEY_<ENV>` still
  comes first. `esec.DecryptFromFS` decrypts from any `fs.FS`.

# v0.11.0

- Help that agents and people can find their way with. `esec` alone and
  `esec help <command>` show help; the overview explains files, keys and
  environment names with examples, and each command's help has examples.
- `esec --help` lists commands that `esec-<name>` programs on `PATH` add,
  such as `esec vault`, and says how to install esec-vault when it is
  missing. `esec vault` without esec-vault now says that, instead of
  "unexpected argument vault".
- A missing secrets file names the secrets files that do exist, and points
  to `--format env` when the environment has a `.env` file rather than
  `.ejson`.
- A missing private key lists the ways to provide it. The library returns it
  as `*esec.KeyNotFoundError`, which matches `esec.ErrKeyNotFound`; the
  message is unchanged.
- `esec run` without a command shows how to call it.
- Usage errors print the usage on stderr, keeping stdout clean.
- Fix: `esec export` and `esec capabilities` could be taken over by an
  `esec-export` or `esec-capabilities` program on `PATH`.

# v0.10.1

- Fix the release workflow: `sigstore/cosign-installer` has no `v4` tag, so
  v0.10.0 was tagged but built no release binaries. It is now pinned to
  v4.1.2 by commit. The code is unchanged from v0.10.0.

# v0.10.0

- Add `esec export`: prints the decrypted variables of a `.env` or `.ejson`
  file as sorted `NAME=value` lines, without the public key, for tools such as
  `fly secrets import` and `gh secret set -f`. Each value is written in the
  simplest form that dotenv parsers read back unchanged, and checked by
  parsing it back; if a value cannot be written, nothing is printed.
- `esec run` no longer passes the public key to the child process.
  `ESEC_PUBLIC_KEY` leaked from `.env` files and `_ESEC_PUBLIC_KEY` from
  `.ejson` files.
- `esec run` now rejects `.env` names that are not valid identifiers, as it
  already did for `.ejson`.
- Add `esec.EnvVars`, which `run` and `export` share. `EjsonToEnv` now also
  leaves out `_ESEC_PUBLIC_KEY`.
- Update dependencies (`golang.org/x/crypto` v0.58.0, `x/sys` v0.49.0,
  `x/term` v0.47.0) and GitHub Actions (checkout v7, setup-go v7,
  cosign-installer v4, goreleaser-action v7.3.0, attest-build-provenance
  v4.2.2).
- CI now runs golangci-lint v2.15.0, pinned in `mise.toml` as well.

# v0.9.0

- Read sealed keyring files (`ESEC-SEALED-KEYRING-V1`), encrypted with
  XChaCha20-Poly1305 under a per-machine cache key and bound to their file
  name. Plain keyrings keep working unchanged. A sealed keyring whose cache key
  is unavailable fails with an error naming the file, never "key not found".
- Add `pkg/secretstore` with OS keychain, TPM (`systemd-creds`), 0600 file,
  and Linux kernel keyring backends. The backend is recorded in
  `secret-store.toml` and shared with esec-vault; `ESEC_SECRET_STORE`
  overrides it.
- Add `pkg/keyringfile`, the single implementation of the sealed format.
- `keygen --save` keeps an existing keyring's form and seals new keyrings when
  `seal_keyrings = true`.
- Add the hidden `esec capabilities` command so tools can check for
  sealed-keyring support before sealing.

# v0.8.1

- Add step-by-step project, environment, and subfolder guides in simplified
  technical English, including key lookup rules and shared-key layouts.
- Update the release workflow to GoReleaser action v7.2.1 and provenance
  attestation action v4.1.0.
- Fix workflow shell quoting and preserve Markdown spacing in release notes.

# v0.8.0

- `keygen --save --env <name> [--project org/repo]` stores private keys atomically
  in the global store and prints only the public key; existing keys are preserved.
- Respect `ESEC_VAULT_HOME` for the default global keyring directory.
- Notify the vault daemon after saving keys; share kernel-managed writer locks
  with esec-vault so process crashes cannot leave stale lock ownership.

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
