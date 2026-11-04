# Esec

Esec encrypts environment files so their encrypted values can live in Git.
It runs as a CLI or Go library on macOS and Linux. The standalone workflow
uses local [age](https://age-encryption.org/) identities and optional
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) hardware.
It needs no Esec server, account, daemon, or menu bar app.

## Install

Download the CLI for your platform from [v0.21.0 releases](https://github.com/mscno/esec/releases/tag/v0.21.0), or:

```sh
go install github.com/mscno/esec/cmd/esec@v0.21.0
# With mise:
mise use -g go:github.com/mscno/esec/cmd/esec@0.21.0
```

The optional **Esec.app** is available in the same release for Apple Silicon
(`arm64`) and Intel (`amd64`), on macOS 14 or later. Unzip it into Applications.
It bundles this version of `esec`, so no separate CLI installation is required
for browsing. The app is ad-hoc signed, **not Developer ID signed or notarized**;
macOS may require approval in System Settings → Privacy & Security on first launch.
The release supplies SHA-256 checksums and GitHub build attestations.

The app remembers local project folders, opens individual files, compares
keys across environments, and saves edits encrypted. Decrypt and Show reveals
values immediately; hide individual values or all values, or Lock to discard
the document. Values are hidden when the app loses focus and discarded on sleep,
window close, or quit. A badge explains the successful read route. Hardware
PINs use a masked prompt over anonymous pipes, never command-line arguments.

There is no helper, broker session, account, sync, or server UI. The app runs
short-lived local CLI commands. It can import the old app's remembered checkout
paths once, but never imports or removes keys. Add Folder can scan a project or
a parent folder. Local raw-key/keyring files still work. Files needing legacy
hardware guards must first be migrated with `esec adopt` using an explicitly
supplied age identity or recovered per-key credential.

The CLI also has no broker client, daemon notifications, server setup, or
service command dispatch. Preserve old keys, encrypted archives, and historical
seals until recovery is verified. See [offline migration](docs/legacy-vault.md).

## Set up a machine

```sh
esec setup
```

The wizard offers to create a software age identity for dev/test/staging and
accepts pasted public age/rage YubiKey recipients (`age1yubikey1...`). You can
paste several recipients without connecting their keys. A public recipient
cannot prove the hardware's touch policy; Esec checks connected slot metadata
when decrypting and refuses YubiKey slots that do not require every touch.
Use `age-plugin-yubikey --generate --touch-policy always` to create a suitable
slot if needed; Esec does not overwrite existing hardware slots.

For scripted setup:

```sh
esec setup --generate-dev --yubikey-recipient "$YUBIKEY_RECIPIENT" --yes
# Import an existing software identity instead of generating one:
esec setup --developer-identity /secure/developer.age --yes
# Add another hardware key or an OFFLINE recovery recipient:
esec setup --recovery-recipient "$OFFLINE_RECIPIENT" --yes
```

Machine preferences live in `~/.config/esec/age.toml`. They contain public
recipients and identity **paths**, never private keys. The generated private
identity lives in `~/.config/esec/identities/developer.age` with mode `0600`.
`ESEC_HOME`, `XDG_CONFIG_HOME`, and `ESEC_CONFIG` relocate configuration.
`ESEC_VAULT_HOME` remains a deprecated **path-only** alias for old local keyring
locations; it never enables a service connection. The age file sits beside
`config.toml`.

A second YubiKey or separately stored recovery identity protects against losing
one hardware key. Native age identities work without plugins. YubiKey access
requires `age-plugin-yubikey` on PATH; Linux also needs its system smart-card
service (`pcscd`). There is no Esec background process.

## Create environments

```sh
esec init --project acme/api --env dev,test,staging --yes
esec init --env production --yes
```

| Environment | Default recipients |
| --- | --- |
| dev/test/staging and other ordinary names | This machine's developer identity, configured YubiKeys, optional recovery recipients |
| prod/production, including dotted suffixes | Configured YubiKeys, configured offline recovery recipients, and explicitly supplied deployment recipients |

Use `--production` for a custom sensitive environment name. Names match exactly;
`prod` and `production` remain separate environments. Treat staging as production
if it contains production data. Development without recovery requires the
explicit `--no-recovery` option; production requires a configured YubiKey.

A missing secrets file gets **only its public key**. Esec never copies an
`.env.example`. For an existing plaintext dotenv file without a public key,
inspect it and explicitly consent to encrypting its existing values:

```sh
esec init --project acme/api --env dev --encrypt-existing --yes
```

Multiline dotenv entries are normalized in memory before encryption. Existing
encrypted files use `esec adopt`, described below.

Commit the encrypted environment files, `esec.toml`, and `.esec/keys/`.
The latter holds age-encrypted Esec environment keys and their public `.age.json`
applied-access records, including immutable old generations for historical recovery. Never commit software private identities,
raw keyrings, or plaintext secrets. Ignore `.esec/.mutation-lock` and
`.esec/pending/`; the latter is a temporary encrypted write journal.
The project label is descriptive, with no server reservation or organisation
membership system. Anyone with the public recipients can encrypt; only a
holder of a matching private identity can decrypt.

## Use secrets and local overrides

```sh
esec encrypt dev                      # Encrypt newly edited values in place
esec decrypt dev                      # Print plaintext; disk stays encrypted
esec get dev DATABASE_URL             # Print one value
esec run dev -- go run ./cmd/server   # Pass values to this child process
esec inspect dev                     # Explain access without opening keys
```

`run` normally uses file values over inherited environment variables. Opt into
specific process overrides for a local database or test service:

```sh
DATABASE_URL=postgres://localhost/local_test \
  esec run --preserve-env DATABASE_URL test -- go test ./...
```

Repeat `--preserve-env`, or comma-separate names. An explicitly set empty value
is preserved too; an unset override keeps the encrypted file's default.
In mise, wrap each dev/test task with `esec run`; keep host-specific overrides
in ignored local configuration. Avoid globally loading production secrets into
every shell or task. Production decryption requires approval at the hardware
key when using its recipient; plaintext handed to a child process remains
accessible to that process.

## Deployment identities

An unattended deployment needs its own software identity. Generate it on a
trusted deployment/provisioning machine, keep the private file in the deployment
secret store, and send only the printed public recipient to the developer:

```sh
esec identity create --out /secure/api-production.age
```

On the project checkout, explicitly grant that public recipient:

```sh
esec init --env production --machine-recipient "$DEPLOY_RECIPIENT" --yes
# Or, for an existing standalone environment:
esec recipients production --add "$DEPLOY_RECIPIENT"
```

Supply the identity to the deployed process through `ESEC_AGE_IDENTITY_FILE`
or `ESEC_AGE_IDENTITY`. Explicit identities replace machine configuration for
that invocation. Production initialization never adds the everyday developer
recipient. **Age recipients are alternatives: any one can decrypt.** A software
deployment or recovery identity therefore does not require YubiKey touch.
Keep those private identities off everyday development machines.

For Go binaries, embed `esec.toml`, the encrypted environment file, and its key
seals (the embed pattern `all:.esec/keys` includes generations). Use
`esec.DecryptFromFS` / `DecryptFromEmbedFSWithConfig` with an explicit `EnvName`
when several environments are embedded. Standalone environments use their age
seal even if a raw Esec key is supplied. Missing or malformed standalone
metadata fails rather than falling back to that raw key.

## New machines, rotation, and recovery

On a new Mac or Linux machine, install Esec and the hardware plugin, clone the
repo, run `esec setup` to create that machine's developer identity, and paste
the same recovery YubiKey recipient. The connected YubiKey can open existing
environments. Grant the new software recipient to each ordinary environment:

```sh
esec recipients dev --add "$NEW_DEVELOPER_RECIPIENT"
esec recipients test --add "$NEW_DEVELOPER_RECIPIENT"
esec recipients staging --add "$NEW_DEVELOPER_RECIPIENT"
```

Inspect public recipients with `esec recipients dev`. Changes to recipients
rotate the Esec environment key and re-encrypt the file. Remove a lost machine
with `--remove "$OLD_RECIPIENT"`; use `esec rotate dev` to rotate without changing
recipients. Rotation does not revoke access to old ciphertext or previously
copied values. Rotate actual database passwords/tokens too after exposure.

Back up the Git history containing encrypted files and `.esec/keys/`. Test
recovery with a different identity before relying on that backup. You do not
need the lost developer private key when a surviving recovery recipient opens
the seals. Keep all old key generations for historical checkouts. Private
identity backups belong in separate protected offline storage; copying their
paths or public recipients is not a private-key backup. There is no automatic
server backup, rclone integration, or escrow in the standalone workflow.

## Review and apply repository access

`esec.toml` is the source of truth for desired public recipients. Private
identities never belong in it. For new environments, omit `key`; Esec writes
and manages it. Keep `key` unchanged when editing an existing environment.
Replace the illustrative recipient strings below with complete public keys:

```toml
project = "acme/api"

[env.dev]
access = "development"
recipients = [
  "age1...",          # developer Mac
  "age1...",          # Linux developer machine
  "age1yubikey1...",   # recovery YubiKey
]

[env.test]
access = "development"
recipients = ["age1...", "age1...", "age1yubikey1..."]

[env.production]
access = "production"
recipients = [
  "age1yubikey1...",   # human access / recovery
  "age1...",          # independent production deployment identity
]
```

```sh
esec plan                  # no decryption, network, or hardware prompt
esec apply                 # review changes and confirm before key access
esec status --check        # exit 0=current, 2=changes needed, 1=invalid
```

`plan` shows added/removed recipients and flags software production access.
Editing TOML does not grant or revoke access until `apply` succeeds. Ordinary
reads warn about unapplied changes while using the existing encrypted key.
`recipients FILE` lists desired recipients; `plan` compares them with applied
records. Public records are bound to the seal hash and checked against the
policy inside the encrypted payload when decrypted. A metadata-only plan is
not proof that a person owns a recipient or that hardware is present.

`apply` prepares and verifies every selected environment before changing active
files. It rotates keys for recipient changes, preserves old generations,
rejects stale edits and symlink destinations, and journals only new ciphertext.
Missing files get only a public-key header. Existing plaintext requires
`--encrypt-existing`; example files are never copied. A deleted environment
entry is flagged, not interpreted as permission to delete files or revoke keys.

Production, recipient removals, and untracked old generations require typing
`apply PROJECT`. Noninteractive use must name the reviewed plan hash, and add
`--approve-sensitive` for those cases:

```sh
esec plan --env dev,test --json
esec apply --env dev,test --yes --plan-hash REVIEWED_HASH
# Add --approve-sensitive only after reviewing a sensitive change.
```

Changing any planned inputs invalidates the hash. Commit `esec.toml`, changed
encrypted files, and `.esec/keys/` together. Removing a recipient cannot revoke
old commits or previously copied values; rotate upstream credentials after
exposure. CI can run `esec status --check` without any private identity.

## Add another developer machine or deployment

On the **new Linux dev machine**, generate its own identity and configure the
public recovery YubiKey recipient (the YubiKey need not be connected):

```sh
esec setup --generate-dev --yubikey-recipient "$YUBIKEY_RECIPIENT" --yes
```

Use `esec identity list` to see the configured public recipients later.
Share only its public developer recipient with an already authorized
machine. On that authorized machine, add it to dev/test in `esec.toml`, then:

```sh
esec plan --env dev,test
esec apply --env dev,test
```

The new machine pulls the updated ciphertext, TOML, and key generations and
can use `esec run dev -- your-command`. Its private identity stays on that
machine. A supported shortcut for a single environment is:

```sh
esec recipients dev --add "$LINUX_DEV_RECIPIENT"
```

The shortcut previews and confirms its explicit change. Scripts can pass
`--yes`; production changes and removals also need `--approve-sensitive`.
It refuses to mix an explicit edit with pre-existing unapplied TOML changes.

Create a **separate deployment identity**, ideally in the target environment:

```sh
esec identity create --out /secure/deployment.age
```

Add its public recipient to production in `esec.toml` and review/apply on an
authorized machine. Configure only that deployment's private identity as
`ESEC_AGE_IDENTITY` or `ESEC_AGE_IDENTITY_FILE` in the deployment environment.
An everyday developer identity cannot also be a production recipient. Explicitly
label offline recovery identities in top-level `recovery_recipients` when sharing
them across dev and production; this label itself grants no access.
Routine local production access uses a configured YubiKey; deployment identities are
independent, explicit unattended access. Use another YubiKey or an offline recovery phrase for
production recovery. Keep the phrase-derived private key off developer machines.

## Offline recovery phrases

Set up two YubiKey public recipients with repeated `--yubikey-recipient` options,
then create a separate recovery phrase in your own terminal:

```sh
esec setup --yubikey-recipient "$YUBIKEY_1" --yubikey-recipient "$YUBIKEY_2" --yes
esec recovery create
```

Creation generates 24 random English BIP39 words, accepts an optional passphrase,
and requires you to re-enter the words before registering the public recipient.
The words are displayed only on the controlling terminal, never stdout. Secret
input is hidden and never accepted in command arguments or environment variables.
Esec saves only the public recovery recipient in `~/.config/esec/age.toml`.
Keep the words, derivation format (`esec-v1`), public recipient, and any passphrase
in your offline backup. Do not reuse a cryptocurrency wallet seed.

Both YubiKeys and the recovery recipient become defaults for **new environments,
including production**. Dev/test also includes the developer identity. These
are independent ways to decrypt: either YubiKey, or the phrase **plus its
passphrase if one was set**, is sufficient. The two YubiKeys are not required
together. A phrase/passphrase is an emergency production route without touch.

```sh
esec init --project acme/api --env dev,test,production --yes
```

The generated project records the recovery role separately from access:

```toml
project = "acme/api"
recovery_recipients = ["age1...recovery..."] # role label only; grants no access

[env.production]
access = "production"
# key = "..." is generated and maintained by Esec
recipients = ["age1yubikey1...one...", "age1yubikey1...two...", "age1...recovery..."]
```

Replace these placeholders with complete public recipients. To make an
existing production environment hardware-only for human access, remove the
recovery recipient from **that environment's `recipients`**, then run:

```sh
esec plan --env production
esec apply --env production
```

The local default and root role label never silently add it back. Merely editing
TOML does not revoke access: apply rotates the environment key and ciphertext.
Old commits and copied secrets remain readable. `esec encrypt` and ordinary
rotation preserve the environment's existing access, rather than merging in
machine defaults. A manually authored TOML declaration is used exactly as written.

Recover without installing any private identity:

```sh
esec recovery verify production       # in-memory check; prints no secrets
esec decrypt production --recovery    # plaintext to stdout; source file unchanged
esec apply --env dev,test --recovery   # recover access by applying a reviewed plan
```

Each asks privately for the words and passphrase. An empty passphrase works only
if none was originally set. A different passphrase derives a different identity;
there is no fallback to an empty passphrase or other local credentials. To restore
a new developer machine, create its identity, add its public recipient to the
appropriate TOML lists, and use `apply --recovery` from a trusted terminal. This
keeps the phrase-derived private identity transient.

Existing phrase and explicit private-key export options:

```sh
esec recovery import                 # register an existing esec-v1 public default
esec recovery recipient              # print only the derived public recipient
esec recovery export --out /secure/recovery.age --expect-recipient "$RECOVERY_RECIPIENT"
```

Import repeats a nonempty passphrase to catch typos and optionally accepts
`--expect-recipient`. Export requires the expected public recipient and a separate
confirmation; it creates a new 0600 file, never overwrites a file, and never adds
it to automatic identity discovery. That exported file is a plaintext private
key: it replaces the need to type the phrase/passphrase, so keep it offline.

For an **old Vault v2 root phrase**, use `--format vault-v2` with the recovery
subcommands, or `--recovery-format vault-v2` with `decrypt --recovery`,
`apply --recovery`, or `adopt --recovery`. This reproduces the old root recipient and its exact passphrase
bytes. It can open age seals addressed to that root; it does not reconstruct the
separate random user identity or decode arbitrary old Vault archives. New
`esec-v1` recovery uses a different, versioned derivation. Do not guess between
formats or assume that the same words mean the same recipient everywhere.

Changing a passphrase changes the public recipient. Add and verify the new
recipient through plan/apply before removing the old one; old commits still need
the old phrase/passphrase. Keep the encrypted files and `.esec/keys/` backed up:
the phrase recovers an identity, not missing ciphertext.

The derivation specification and compatibility details are in
[recovery-format.md](docs/recovery-format.md).

## Migrate older files offline

Configure local age identities, then migrate one environment at a time:

```sh
esec setup
esec adopt dev
esec inspect dev
esec run dev -- your-test-command
```

`adopt` opens the old file with local credentials, creates a new environment
key, re-encrypts its values, and seals the new key to standalone recipients.
Raw keys and old encrypted seals remain available for historical recovery.
For a legacy seal addressed to your old Vault v2 root, use
`esec adopt production --recovery --recovery-format vault-v2`. Otherwise, for
legacy hardware-guarded files, explicitly supply an authorized age identity
through `ESEC_AGE_IDENTITY_FILE` or export a recovered
`ESEC_PRIVATE_KEY_<FILE_PUBLIC_KEY>` credential for that one process. Ordinary
keyring caches do not override a legacy hardware guard. No command contacts a
broker or offers to install one.

Production migration uses configured YubiKeys and only explicitly named
software deployment recipients:

```sh
esec adopt production --machine-recipient "$DEPLOY_RECIPIENT"
```

Keep development machine identities separate from deployment identities.
Configured offline recovery recipients are included when initializing or adopting
new environments, including production. Each environment’s explicit TOML
recipient list is authoritative afterward; removing a recipient and applying
does not re-add it from machine defaults.
Adding a deployment recipient grants that identity unattended decryption; a
local human's normal production route remains their always-touch YubiKey.

Shared-key files and environment aliases require coordinated offline migration
and are refused by single-file adoption. Keep old encrypted backups until every
active environment and deployment can be read independently. Do not delete
historical keys as part of upgrading the tool.

`esec repair` completes an interrupted prepared ciphertext transaction. It
refuses conflicting edits. Preserve a pending journal without a manifest and
investigate it before retrying; it was not prepared for publication.

Existing v0.19 age environments show `untracked` until an approved `esec apply`
rotates them and writes an applied-access record. Reads still work with their
age identities. Public metadata alone cannot prove the old recipient set.
Older readers can open the age payload, but do not enforce the new record
binding or warn about drift; upgrade readers before relying on those checks.

Esec's existing file encryption is based on NaCl box and inspired by
[Shopify EJSON](https://github.com/Shopify/ejson). Age wraps environment keys;
it does not replace the existing per-value file format.
