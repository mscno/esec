# esec: Encrypted Secrets Management for Go

**esec** encrypts secrets files. You can commit the encrypted files to Git.
The private keys stay on your computer or in your deployment secret store.
You can use esec as a command-line tool or a Go library.

Use the companion [esec-vault](https://github.com/mscno/esec-vault) to create
projects, store keys, share keys with other people, and back up keys.

## Start here

- [Install the tools](#cli-installation).
- [Set up a project](#project-guide).
- [Use keys in subfolders](#subfolder-guide).
- [Check how esec finds a key](#private-key-lookup).
- [Share keys with a teammate](https://github.com/mscno/esec-vault#share-project-keys-with-a-teammate).
- [Manage the daemon and backups](https://github.com/mscno/esec-vault#automatic-backups).

The command examples use esec v0.8.0 or later and esec-vault v0.3.0 or later.
Replace `acme` and the project names with your own names.
Replace `npm run dev` with your application's start command. Set `$EDITOR` to
your editor, or replace `$EDITOR` in the examples with an editor command.

It draws heavy inspiration from the [EJSON](https://github.com/Shopify/ejson) project and aims to provide a similar experience for Go developers. A large part of the crypto related code and the file format handling is also inspired by or directly taken from the EJSON project.

Main differences are that **esec** is more opinionated on the file naming conventions and the key lookup process. EJSON writes the keys to a local dir in the format of `keydir/<public-key>/<private-key>` and then looks up the keys from there. **esec** uses environment variables and a `.esec-keyring` file for key lookup.

## Features

- **Secure secrets storage** using public/private key encryption (NaCl box)
- **Support for multiple formats** (`.env`, `.ejson`, `.eyaml`, `.yaml`)
- **Decryption of secrets in embedded or external vaults**
- **CLI tool for encryption & decryption**
- **Run commands with decrypted environment variables**
- **Extract specific keys** from encrypted files
- **Flexible environment & key management** via keyring file
- **Debug logging** with `--debug` flag

## Installation

### Using Go Modules

```sh
go get github.com/mscno/esec
```

### CLI Installation

```sh
GOBIN="$HOME/go/bin" go install github.com/mscno/esec/cmd/esec@latest
GOBIN="$HOME/go/bin" go install github.com/mscno/esec-vault/cmd/esec-vault@latest
export PATH="$HOME/go/bin:$PATH"

esec --version
esec-vault --version
```

Use the same install directory for both tools. The explicit `GOBIN` value also
keeps these tools outside a Go version manager's toolchain directory.

### Verifying Releases

All release artifacts are signed and include provenance attestations. To verify a downloaded release:

```bash
gh attestation verify esec_*.tar.gz --owner mscno
```

For detailed verification instructions including checksum verification and SBOM inspection, see [VERIFICATION.md](VERIFICATION.md).

---

## Project guide

### Understand the files and keys

| Item | Purpose | Commit to Git? |
|---|---|---|
| `.esec-project` | Selects the project's global keyring | Yes |
| `ESEC_PUBLIC_KEY` in `.env.dev` | Selects the key pair used to encrypt the file | Yes |
| Encrypted `.env.dev` | Stores the project's development secrets | Yes, after encryption |
| Global `*.keyring` file | Stores private keys on this computer | No |
| Personal vault identity | Opens your backups and shares sent to you | No |

A project key is different from your personal vault identity.
Create your personal identity once. Create project keys for each application.
Use different keys for environments that need different access.

### Step 1: Create the project marker and environment keys

Run this command from the project root:

```sh
cd ~/projects/store
esec vault project init acme/store --env dev,staging,prod --format env
```

The command creates these files:

```text
store/
  .esec-project
  .env.dev
  .env.staging
  .env.prod
```

The project marker contains one line:

```dotenv
ESEC_PROJECT=acme/store
```

The marker contains no private key. It does not set the active environment,
file format, remote backup location, or daemon policy.

The private keys are stored in:

```text
~/.config/esec/keyrings/acme_store.keyring
```

Use a stable project ID. Two clones with the same ID use the same global
keyring on this computer. A different ID selects a different keyring.

If you only need to create a marker, create `.esec-project` in your editor.
For a new file, this command has the same result:

```sh
printf 'ESEC_PROJECT=acme/store\n' > .esec-project
```

Write the value without quotes. Use `org/repo` or `org/repo/subproject`.
Changing the marker does not move existing keys to the new project ID.

### Step 2: Add values and encrypt the file

Keep the generated `ESEC_PUBLIC_KEY` line. Add your values below it:

```dotenv
ESEC_PUBLIC_KEY=THE_GENERATED_PUBLIC_KEY
DATABASE_URL=postgres://localhost/store_dev
API_TOKEN=replace-with-your-token
```

Edit the real generated file, then encrypt it:

```sh
$EDITOR .env.dev
esec encrypt dev -f env
```

Use `-f env` when you pass an environment name for a dotenv file.
Core esec defaults to `.ejson`.

You can also pass the file path:

```sh
esec encrypt .env.dev
```

### Step 3: Read a value or run the application

```sh
esec get dev DATABASE_URL -f env
esec run dev -f env -- npm run dev
```

To print all decrypted values:

```sh
esec decrypt dev -f env
```

`esec run` reads private keys directly. For daemon-controlled access, use
`esec vault run` with an unlocked broker and an allow rule for the project.
See the [broker guide](https://github.com/mscno/esec-vault#run-applications-through-the-broker).

### Step 4: Commit encrypted files and back up the keys

Encrypt each file after you add its values. Then commit the project marker,
the encrypted files, and the `.gitignore` update.

```sh
esec encrypt staging -f env
esec encrypt prod -f env
git add .esec-project .gitignore .env.dev .env.staging .env.prod
esec vault backup --verify --push
```

If your repository ignores all `.env.*` files, add an exception for the specific
encrypted files you want to track. A Git commit stores the encrypted data.
A vault backup stores the keys needed to decrypt that data.

### Add another environment

Use `project init` again to add a key and a file template:

```sh
esec vault project init acme/store --env qa --format env
$EDITOR .env.qa
esec encrypt qa -f env
esec vault env list
```

This adds `qa`. It does not remove `dev`, `staging`, or `prod`.
It keeps existing keys and files when they match.

Use this command when you need a key without a file template:

```sh
esec vault env add preview
```

It prints `ESEC_PUBLIC_KEY=...`. Put that line in a new `.env.preview` file.
Do not redirect the command into an existing secrets file: shell redirection
can truncate the file before the command checks whether the key exists.

Core esec can also store a key without creating a template:

```sh
esec keygen --save --env preview2 --project acme/store
```

Use lowercase letters and digits in environment names. Dots separate parts:
`dev`, `prod`, `api.dev`, and `worker.prod` are valid names.

### Work in a second project

```sh
cd ~/projects/billing
esec vault project init acme/billing --env dev,prod --format env
esec vault env list

cd ~/projects/store
esec vault env list
```

Each `env list` command uses the nearest project marker.
The two projects have separate keys, even when both use the name `dev`.
You can inspect a project without changing directory:

```sh
esec vault env list --project acme/store
esec vault keyring list
```

### Edit an encrypted file

Encrypted values are not an editable copy of the original text.
Decrypt to a separate private file, edit that file, then encrypt it back.
This example uses a new temporary directory so it cannot overwrite the source
before decryption completes:

```sh
umask 077
work=$(mktemp -d)
esec decrypt .env.dev > "$work/.env.dev"
$EDITOR "$work/.env.dev"
esec encrypt "$work/.env.dev" --output .env.dev
rm "$work/.env.dev"
rmdir "$work"
```

Run each step only after the previous step succeeds. Keep the public-key line.
Use the same process for `.ejson`, `.eyaml`, or `.etoml` files.

## Subfolder guide

Choose one of the following layouts for a repository.
Each example starts in that repository's root directory.

### Layout A: One project and a shared environment key

Use this layout when two components need the same key access.

```sh
esec vault project init acme/sharedapp --env dev,prod --format env
mkdir -p services/api services/worker
cp .env.dev services/api/.env.dev
cp .env.dev services/worker/.env.dev
```

These commands copy new, empty templates. Both copies have the same public key.
Edit each copy to store different values for each component.

```text
sharedapp/
  .esec-project                 # ESEC_PROJECT=acme/sharedapp
  services/
    api/.env.dev
    worker/.env.dev
```

Keep one marker at the repository root. From the API directory:

```sh
cd services/api
$EDITOR .env.dev
esec encrypt dev -f env
esec run dev -f env -- npm run dev
```

esec finds `.env.dev` in `services/api`. It searches upward for the project
marker and selects `acme/sharedapp`. Both components use that project's `dev`
key. Sharing this key gives access to every file encrypted to that key.

### Layout B: One project with separate component keys

Use dotted environment names to create separate keys in one project keyring:

```sh
esec vault project init acme/platform \
  --env api.dev,api.prod,worker.dev,worker.prod --format env
mkdir -p services/api services/worker
mv .env.api.dev .env.api.prod services/api/
mv .env.worker.dev .env.worker.prod services/worker/
```

The result is:

```text
platform/
  .esec-project                 # ESEC_PROJECT=acme/platform
  services/
    api/.env.api.dev
    api/.env.api.prod
    worker/.env.worker.dev
    worker/.env.worker.prod
```

From the API directory:

```sh
cd services/api
$EDITOR .env.api.dev
esec encrypt api.dev -f env
esec run api.dev -f env -- npm run dev
```

The `api.dev` name selects `.env.api.dev` in the current directory.
It selects `ESEC_PRIVATE_KEY_API_DEV` in the shared project keyring.
The folder name does not add `api` to the environment name automatically.

From the repository root, core esec can use an explicit file path:

```sh
esec decrypt services/api/.env.api.dev
```

The root marker is correct for both components in this layout.
To share only the API development key with a teammate, use
`esec vault share --to alice --env api.dev` from the repository root after
[setting up member trust](https://github.com/mscno/esec-vault#share-project-keys-with-a-teammate).

### Layout C: A separate project in each subfolder

Use nested project markers when components need separate project keyrings:

```sh
esec vault project init acme/mono/services/api \
  --dir services/api --env dev,prod --format env
esec vault project init acme/mono/services/worker \
  --dir services/worker --env dev,prod --format env
```

```text
mono/
  services/
    api/
      .esec-project            # ESEC_PROJECT=acme/mono/services/api
      .env.dev
      .env.prod
    worker/
      .esec-project            # ESEC_PROJECT=acme/mono/services/worker
      .env.dev
      .env.prod
```

Run commands inside the component:

```sh
cd services/api
$EDITOR .env.dev
esec encrypt dev -f env
esec run dev -f env -- npm run dev
esec vault env list
```

The API and worker now have different `dev` keys.
A nested marker selects its own project keyring. It does not merge keys from
a parent project's keyring. Environment-variable overrides and the global
default keyring can still apply to core esec.

From the repository root, set the key directory when reading a child project:

```sh
esec decrypt services/api/.env.dev --key-dir services/api
esec run services/api/.env.dev --key-dir services/api -- npm --prefix services/api run dev
```

The file argument selects the file. `--key-dir` selects where core esec starts
its project-marker and keyring lookup. A file path alone does not change that
starting directory.

For broker commands, change into the component and use an environment name:

```sh
(cd services/api && esec vault run dev -f env -- npm run dev)
```

Run `members`, `share`, and `sync` in the directory that contains the component's
marker. These sharing commands do not walk the repository or collect child
projects automatically.

### Reuse a root secrets file from a subfolder

esec does not search parent folders for a secrets file. Supply its path:

```sh
# From services/api; the file is at the repository root.
esec run ../../.env.dev -- npm run dev
```

With one root project marker, the normal upward marker lookup selects the root
keyring. If `services/api` has its own marker, select the root keyring explicitly:

```sh
project_root=$(git rev-parse --show-toplevel)
esec run "$project_root/.env.dev" --key-dir "$project_root" -- npm run dev
```

Use an absolute root path for this key-directory override. The current CLI
rejects `..` in `--key-dir`, even though a secrets file path can contain `..`.

### Quick lookup table

| Command location | Command | File selected | Project lookup starts at |
|---|---|---|---|
| Project root | `esec decrypt dev -f env` | `./.env.dev` | `.` |
| `services/api` | `esec decrypt api.dev -f env` | `./.env.api.dev` | `.` |
| Project root | `esec decrypt services/api/.env.dev` | `services/api/.env.dev` | `.` |
| Project root | `esec decrypt services/api/.env.dev -d services/api` | `services/api/.env.dev` | `services/api` |
| `services/api` | `esec decrypt ../../.env.dev -d "$project_root"` | `../../.env.dev` | Absolute repository root |

Project lookup uses the nearest marker. It stops at the Git root.
esec reads one secrets file per command. It does not merge parent and child
secrets files, or load `dev` and `prod` together.

---

## CLI Usage

```
Usage: esec <command> [flags]

Commands:
  keygen     Generate a new keypair
  encrypt    Encrypt a secrets file in place
  decrypt    Decrypt a secrets file to stdout
  get        Decrypt a secrets file and print a single value
  run        Run a command with decrypted secrets as environment variables

Global Flags:
  --help       Show help
  --version    Show version
  --debug      Enable debug logging (env: ESEC_DEBUG)
  -q, --quiet  Suppress non-essential output
```

Unknown subcommands are dispatched git-style: if `esec <x>` is not a builtin command, esec
runs `esec-<x>` from your `PATH` (e.g. `esec vault ...` → `esec-vault ...`).

**Conventions:**

- Data is written to **stdout**, status messages and logs to **stderr**
- `--format` accepts `ejson`, `env`, `eyaml`, `etoml` (a leading dot is optional)
- `--format` and `--key-dir` can also be set via the `ESEC_FORMAT` and `ESEC_KEY_DIR` environment variables
- Exit codes: `0` success, `1` error. `run` propagates the child process exit code and exits `130` on `SIGINT`

### Generate Keys

Save a new environment key directly to the global project keyring (only the
public key is printed):

```sh
esec keygen --save --env dev --project myorg/myapp
# Inside a project with .esec-project, --project is optional.
```

`--save` refuses to replace an existing environment key. Dotted environments
such as `registry.prod` are supported. The companion CLI can scaffold the
whole project and handle encrypted, recoverable cloud backups:

```sh
esec vault init
esec vault project init myorg/myapp --env dev,staging,prod
esec vault remote add                 # interactive destination setup
esec vault backup --verify --push
esec vault daemon install --start     # background broker and backup service
```

See [esec-vault](https://github.com/mscno/esec-vault) for remote configuration,
recovery and unattended operation. `ESEC_VAULT_HOME` is respected by both CLIs
for the default keyring directory; `ESEC_KEYRING_DIR` takes precedence.

Generate a new public/private keypair:

```sh
esec keygen
```

Output:

```
Public Key:
e50e7c0086bfac43263dc087dc9a0118d3b567d26a87c22876690bca8b50c00c
Private Key:
dfe357ede9f3b42b34ac1fca814a27a99f610e4fde361d09b78adcc659b88b79
```

### Encrypt Secrets

```sh
# Encrypt a file directly (in place)
esec encrypt .ejson.dev

# Encrypt using environment name (resolves to .ejson.dev)
esec encrypt dev

# Encrypt with a specific format
esec encrypt dev -f env

# Dry run (print encrypted output to stdout, file is not modified)
esec encrypt dev --dry-run

# Write encrypted output to a different file
esec encrypt dev -o .ejson.dev.enc
```

**Flags:**
| Flag | Short | Default | Env | Description |
|------|-------|---------|-----|-------------|
| `--format` | `-f` | `.ejson` | `ESEC_FORMAT` | File format (`ejson`, `env`, `eyaml`, `etoml`) |
| `--dry-run` | `-n` | `false` | | Print encrypted output to stdout without writing |
| `--output` | `-o` | | | Write encrypted output to this file instead of in place |

### Decrypt Secrets

```sh
# Decrypt a file directly
esec decrypt .ejson.dev

# Decrypt using environment name
esec decrypt dev

# Decrypt with a specific format
esec decrypt dev -f .env

# Decrypt with key from stdin
echo "your-private-key" | esec decrypt dev -k

# Decrypt using keyring from specific directory
esec decrypt dev -d /path/to/keyring/dir
```

**Flags:**
| Flag | Short | Default | Env | Description |
|------|-------|---------|-----|-------------|
| `--format` | `-f` | `.ejson` | `ESEC_FORMAT` | File format (`ejson`, `env`, `eyaml`, `etoml`) |
| `--key-from-stdin` | `-k` | `false` | | Read private key from stdin |
| `--key-dir` | `-d` | `.` | `ESEC_KEY_DIR` | Directory containing `.esec-keyring` file |

### Get a Specific Key

Extract a single value from an encrypted file:

```sh
# Get a specific key from encrypted file
esec get dev DATABASE_URL

# Get with specific format
esec get dev API_KEY -f .env

# Get with key from stdin
echo "your-private-key" | esec get dev SECRET -k
```

**Flags:**
| Flag | Short | Default | Env | Description |
|------|-------|---------|-----|-------------|
| `--format` | `-f` | `.ejson` | `ESEC_FORMAT` | File format (`ejson`, `env`, `eyaml`, `etoml`) |
| `--key-from-stdin` | `-k` | `false` | | Read private key from stdin |
| `--key-dir` | `-d` | `.` | `ESEC_KEY_DIR` | Directory containing `.esec-keyring` file |

### Run Commands with Secrets

Decrypt secrets and run a command with them as environment variables:

```sh
# Run with ejson format (default)
esec run dev -- myapp serve

# Run with env format
esec run production -f .env -- myapp serve

# Equivalent explicit file paths
esec run .ejson.dev -- myapp serve
esec run .env.production -- myapp serve

# With key from stdin
echo "your-private-key" | esec run dev -k -- myapp serve
```

**Flags:**
| Flag | Short | Default | Env | Description |
|------|-------|---------|-----|-------------|
| `--format` | `-f` | `.ejson` | `ESEC_FORMAT` | File format (`ejson`, `env`, `eyaml`, `etoml`) |
| `--key-from-stdin` | `-k` | `false` | | Read private key from stdin |
| `--key-dir` | `-d` | `.` | `ESEC_KEY_DIR` | Directory containing `.esec-keyring` file |

The child process inherits esec's stdio, and esec exits with the child's exit code (or `130` when interrupted with `Ctrl-C`). Works with and without a TTY (e.g. in CI pipelines).

### Debug Mode

Enable detailed logging with the `--debug` flag or the `ESEC_DEBUG` environment variable:

```sh
esec --debug decrypt dev
ESEC_DEBUG=1 esec run dev -- myapp serve
```

---

## File Naming Convention

esec follows a structured naming convention for environment-based encryption files:

| Format | Base Name | With Environment |
|--------|-----------|------------------|
| JSON | `.ejson` | `.ejson.dev`, `.ejson.prod` |
| Dotenv | `.env` | `.env.dev`, `.env.prod` |

### Environment Resolution

When you pass an environment name instead of a filename, esec automatically resolves it:

| Command | Resolves To | Key used |
|---------|-------------|----------|
| `esec encrypt` | `.ejson` | Public key stored in the file |
| `esec encrypt dev` | `.ejson.dev` | Public key stored in the file |
| `esec decrypt prod` | `.ejson.prod` | `ESEC_PRIVATE_KEY_PROD` |
| `esec decrypt dev -f .env` | `.env.dev` | `ESEC_PRIVATE_KEY_DEV` |

---

## Private Key Lookup

When decrypting, an explicit key from `--key-from-stdin` takes priority.
Otherwise, esec searches the following locations in order.
Encryption needs only the public key in the secrets file.

### 1. Environment Variables

```sh
export ESEC_PRIVATE_KEY=your-private-key           # Default environment
export ESEC_PRIVATE_KEY_DEV=your-dev-key           # Dev environment
export ESEC_PRIVATE_KEY_PROD=your-prod-key         # Prod environment
```

### 2. Keyring File (`.esec-keyring`)

If not found in environment variables, esec looks for a `.esec-keyring` file, first in the
key directory (default `.`, or set via `--key-dir` / `ESEC_KEY_DIR`), then in the **global
keyring store**:

1. `~/.config/esec/keyrings/<org>_<repo>.keyring` — when the repo contains an `.esec-project`
   file (`ESEC_PROJECT=org/repo`), looked up from the current directory upward
2. `~/.config/esec/keyrings/default.keyring` — project-independent fallback

Set `ESEC_KEYRING_DIR` to select a different global directory. Otherwise,
`ESEC_VAULT_HOME/keyrings` is used when `ESEC_VAULT_HOME` is set, followed by
`XDG_CONFIG_HOME/esec/keyrings` or the default home path.

`ESEC_KEYRING_PATH` selects one exact keyring file and disables other file
lookups. It does not override a private key supplied through stdin or an
environment variable. The repo-local `.esec-keyring` is read only from the key
directory; esec does not search parents for that file.

### 3. Key names: environment chain and public key

Within each location, esec tries key names most-specific-first:

- `.ejson.prod` → `ESEC_PRIVATE_KEY_PROD`
- `.env.registry.production` (monorepo component) → `ESEC_PRIVATE_KEY_REGISTRY_PRODUCTION`,
  then `ESEC_PRIVATE_KEY_PRODUCTION`
- any file → `ESEC_PRIVATE_KEY_<the file's public key, hex>`

The public-key entry is a fallback after named environment entries in each
location. esec checks that its private key matches the public key.

An earlier named entry can take priority even when it contains the wrong key.
esec does not retry every stored key after decryption fails. Remove or correct
stale overrides instead of relying on the public-key fallback to bypass them.
Use distinct environment names, such as `api.prod` and `worker.prod`, when one
project contains multiple production keys.

The file's public-key field and its encrypted values must use the same key pair.
Changing the public-key field alone does not rotate already encrypted values.

### 4. Monorepos

The nearest `.esec-project` (walking up, never crossing the git root) scopes the global keyring.
One marker at the repo root shares one project across all components; nested markers
(`services/registry/.esec-project` with `ESEC_PROJECT=org/repo/services/registry`) give
subprojects their own keyrings in the global store.

```dotenv
###########################################################
### Private key file - Do not commit to version control ###
###########################################################

### Active Key
ESEC_ACTIVE_ENVIRONMENT=dev

### Private Keys
ESEC_PRIVATE_KEY_DEV=your-dev-private-key
ESEC_PRIVATE_KEY_PROD=your-prod-private-key
```

**Special Variables:**

| Variable | Description |
|----------|-------------|
| `ESEC_ACTIVE_ENVIRONMENT` | Specifies which environment to use (e.g., `dev`, `prod`) |
| `ESEC_ACTIVE_KEY` | Alternative: specifies which key variable to use (e.g., `ESEC_PRIVATE_KEY_DEV`) |

These active-environment variables are used by library environment sniffing.
For CLI commands, pass the environment or file path explicitly. An omitted
environment selects the base file, such as `.ejson`.

---

## File Formats

### JSON Format (`.ejson`)

```json
{
  "_ESEC_PUBLIC_KEY": "493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d",
  "DATABASE_URL": "postgres://localhost/mydb",
  "API_KEY": "secret123",
  "nested": {
    "value": "also encrypted"
  },
  "_metadata": {
    "note": "underscore prefix prevents encryption"
  }
}
```

**Rules:**
- Must have `ESEC_PUBLIC_KEY` or `_ESEC_PUBLIC_KEY` at top level
- All string values are encrypted (except object keys)
- Keys starting with `_` are not encrypted
- Numbers, booleans, and nulls are not encrypted

**Encrypted:**

```json
{
  "_ESEC_PUBLIC_KEY": "493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d",
  "DATABASE_URL": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:gwjm0ng6DE3FlL8F617cRMb8cBeJ2v1b:KryYDmzxT0OxjuLlIgZHx73DhNvE]",
  "API_KEY": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:05gVhGzlZ+uAkDhUQkF/Ek8ketC9ta9f:bxHz36i/Etrl3BSGwCw5CmNix89t]",
  "nested": {
    "value": "ESEC[1:HMvqzjm4wFgQzL0qo6fDsgfiS1e7y1knsTvgskUEvRo=:3Zcx6Quy0mj5MdUDJduNKGgPDqBOLHYB:s9/u1dhQtYoeWGymnZlWogT8UnMR]"
  },
  "_metadata": {
    "note": "underscore prefix prevents encryption"
  }
}
```

### Dotenv Format (`.env`)

```dotenv
# Database configuration
ESEC_PUBLIC_KEY=493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d

DATABASE_URL=postgres://localhost/mydb
API_KEY=secret123
```

**Rules:**
- Must have `ESEC_PUBLIC_KEY` field
- Only values are encrypted, not keys
- Comments and blank lines are preserved
- `ESEC_PUBLIC_KEY` is never encrypted

**Encrypted:**

```dotenv
# Database configuration
ESEC_PUBLIC_KEY=493ffcfba776a045fba526acb0baff44c9639b98b9f27123cca67c808d4e171d

DATABASE_URL=ESEC[1:uFOJzedrCFCn2wBvZJT+5hG/nFY6pDPJ3cP6E2OxHTQ=:dMlog4zL55ar0O2szkZWYPZUWgA5ypRv:CPOF3sboowCHClcvE7hidYh/9PzX]
API_KEY=ESEC[1:uFOJzedrCFCn2wBvZJT+5hG/nFY6pDPJ3cP6E2OxHTQ=:aBcDefGhIjKlMnOpQrStUvWxYz012345:Base64EncryptedValue==]
```

---

## Go Library Usage

### Generate Keypair

```go
package main

import (
    "fmt"
    "github.com/mscno/esec"
)

func main() {
    pub, priv, err := esec.GenerateKeypair()
    if err != nil {
        panic(err)
    }
    fmt.Printf("Public:  %s\nPrivate: %s\n", pub, priv)
}
```

### Encrypt Data

```go
package main

import (
    "bytes"
    "fmt"
    "github.com/mscno/esec"
)

func main() {
    data := []byte(`{"_ESEC_PUBLIC_KEY": "493ffcfba...", "secret": "myvalue"}`)

    var output bytes.Buffer
    _, err := esec.Encrypt(bytes.NewReader(data), &output, esec.FileFormatEjson)
    if err != nil {
        panic(err)
    }

    fmt.Println(output.String())
}
```

### Decrypt Data

```go
package main

import (
    "bytes"
    "fmt"
    "os"
    "github.com/mscno/esec"
)

func main() {
    os.Setenv("ESEC_PRIVATE_KEY", "your-private-key")

    encrypted := []byte(`{"_ESEC_PUBLIC_KEY": "...", "secret": "ESEC[...]"}`)

    var output bytes.Buffer
    _, err := esec.Decrypt(bytes.NewReader(encrypted), &output, "", esec.FileFormatEjson, ".", "")
    if err != nil {
        panic(err)
    }

    fmt.Println(output.String())
}
```

### Decrypt File

```go
package main

import (
    "fmt"
    "os"
    "github.com/mscno/esec"
)

func main() {
    os.Setenv("ESEC_PRIVATE_KEY_DEV", "your-private-key")

    data, err := esec.DecryptFile(".ejson.dev", ".", "")
    if err != nil {
        panic(err)
    }

    fmt.Println(string(data))
}
```

### Decrypt from Embedded Filesystem

```go
package main

import (
    "embed"
    "fmt"
    "log/slog"
    "os"
    "github.com/mscno/esec"
)

//go:embed secrets/*
var vault embed.FS

func main() {
    os.Setenv("ESEC_PRIVATE_KEY_PROD", "your-private-key")

    config := esec.DecryptFromEmbedConfig{
        EnvName: "prod",
        Format:  esec.FileFormatEjson,
        Logger:  slog.Default(),
        Keydir:  ".",
    }

    data, err := esec.DecryptFromEmbedFSWithConfig(vault, config)
    if err != nil {
        panic(err)
    }

    fmt.Println(string(data))
}
```

### Convert to Environment Map

```go
package main

import (
    "fmt"
    "os"
    "github.com/mscno/esec"
)

func main() {
    os.Setenv("ESEC_PRIVATE_KEY", "your-private-key")

    // Decrypt file
    data, err := esec.DecryptFile(".ejson", ".", "")
    if err != nil {
        panic(err)
    }

    // Convert to map (for ejson)
    envMap, err := esec.EjsonToEnv(data)
    if err != nil {
        panic(err)
    }

    // Or for dotenv
    // envMap, err := esec.DotEnvToEnv(data)

    for k, v := range envMap {
        fmt.Printf("%s=%s\n", k, v)
    }
}
```

---

## Security Notes

- **Never commit** `.esec-keyring` or private keys to version control
- Add to `.gitignore`:
  ```
  .esec-keyring
  ```
- Encrypted files (`.ejson`, `.env` with ESEC values) **can** be committed safely
- Use environment-specific keys for different deployments
- `run` starts the command and arguments you provide. Use `--` before the command.

---

## Encryption Format

Encrypted values use the format:

```
ESEC[<version>:<public-key>:<nonce>:<ciphertext>]
```

- **Version**: Schema version (currently `1`)
- **Public key**: Ephemeral public key (base64, 32 bytes)
- **Nonce**: Random nonce (base64, 24 bytes)
- **Ciphertext**: Encrypted data (base64)

Encryption uses NaCl box (Curve25519, XSalsa20, Poly1305).
