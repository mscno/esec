# Esec

Esec encrypts environment files so their encrypted values can live in Git.
It runs as a CLI or Go library on macOS and Linux. The standalone workflow
uses local [age](https://age-encryption.org/) identities and optional
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) hardware.
It needs no Esec server, account, daemon, or menu bar app.

## Install

Download the CLI for your platform from [v0.19.0 releases](https://github.com/mscno/esec/releases/tag/v0.19.0), or:

```sh
go install github.com/mscno/esec/cmd/esec@v0.19.0
# With mise:
mise use -g go:github.com/mscno/esec/cmd/esec@0.19.0
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
broker approval must first be migrated with `esec adopt` using their existing
access; the new app does not bypass that policy.

Quit EsecVault before opening Esec, and turn off the old app's Open at Login.
Keep the old app and Vault recovery material until legacy migrations and
historical recovery have been verified. See the [legacy workflow](docs/legacy-vault.md).

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
`XDG_CONFIG_HOME`, `ESEC_VAULT_HOME`, and `ESEC_CONFIG` relocate configuration;
the age file sits beside `config.toml`, so old Vault clients remain usable.

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
| prod/production, including dotted suffixes | Configured YubiKeys, optional recovery recipients, explicitly supplied machine recipients |

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
The latter holds age-encrypted Esec environment keys, including immutable old
generations for historical recovery. Never commit software private identities,
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

## Migrate from Vault

Start with one non-production environment. Leave Vault available for old files
and their existing guard approvals:

```sh
esec setup
esec adopt dev
esec inspect dev
esec run dev -- your-test-command
```

`adopt` opens the legacy file using its existing access rules, generates a new
Esec key, re-encrypts the file, and seals that key to the standalone recipients.
Old raw keys, legacy seals, and backups remain untouched. Production migration
is explicit, including any deployment recipients:

```sh
esec adopt production --machine-recipient "$DEPLOY_RECIPIENT"
```

Migration currently refuses shared-key files or environment aliases: they need
a coordinated migration. Other Esec implementations/editors must understand
this new seal layout before they can decrypt standalone environments. Old
versions retain raw-key compatibility for legacy environments, but cannot open
the new standalone seals.

If interrupted, `esec repair` finishes a prepared encrypted transaction. It
refuses conflicting edits instead of overwriting them. A journal without a
manifest was not prepared: preserve it and inspect the failure before removing
it and retrying. This is recovery from ordinary interrupted writes, not a claim
of guaranteed recovery from every filesystem/power failure.

Retire the legacy Vault server/app/daemon only after every active project and deployment
works independently and recovery of important historical revisions has been
tested. Legacy `esec encrypt`/`decrypt` with raw keys and `.esec-keyring` remain
supported for unmigrated files; the former project wizard is `esec legacy-setup`.

Esec's existing file encryption is based on NaCl box and inspired by
[Shopify EJSON](https://github.com/Shopify/ejson). Age wraps environment keys;
it does not replace the existing per-value file format.
