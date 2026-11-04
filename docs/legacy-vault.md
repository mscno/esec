# Offline compatibility and retirement

Esec no longer includes a broker client, forwarding protocol, daemon wake-ups,
server login/setup wizard, or dispatch to retired service executables. Old
`esec vault`, `legacy-setup`, `broker`, and `daemon` commands fail locally with
migration advice even if stale executables are on PATH.

Supported offline formats remain:

- Existing `.env`, EJSON, YAML, and TOML encrypted values.
- Raw environment variables and ordinary `.esec-keyring` files.
- Legacy encrypted keyrings, opened with their original local cache key.
- Legacy repository `.esec/<environment>.age` envelopes and signed public
  records, opened with an explicitly supplied authorized identity.

Encrypted-keyring compatibility retains the historical OS-keychain service
identifier and local cache-key backend. It does not load the old Vault user
identity for routine reads, contact a server, or require a daemon. The old
`ESEC_VAULT_HOME` setting is only a path alias; prefer `ESEC_HOME` going forward.

A legacy `guard = "touch"` or `guard = "session"` is never silently weakened
into an ordinary keyring lookup. Supply an age reader identity explicitly, or
export a verified recovered credential named `ESEC_PRIVATE_KEY_<PUBLIC_KEY>`
into the one migration process, then run `esec adopt FILE`.

A 24-word Vault recovery phrase is not an age identity string. Esec can derive
the historical v2 root recipient with `esec recovery recipient --format vault-v2`.
For repository age seals addressed to that root, use `esec recovery verify FILE
--format vault-v2` or `esec adopt FILE --recovery --recovery-format vault-v2`.
The hidden prompts accept the phrase and its optional passphrase. Recovery of
arbitrary old Vault archives still requires their offline format converter; do not
paste the phrase into `ESEC_AGE_IDENTITY`, command arguments, or a chat. Preserve
the encrypted archive and matching repository seals until conversion has been
verified. This repository's normal workflow is age identities and YubiKeys.

See the [current migration and access workflow](../README.md#migrate-older-files-offline).
The removed service setup documentation remains in Git history for archival
format investigation, not as instructions for the current CLI.
