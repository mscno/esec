# Configuration and secrets

Esec 0.22 manages encrypted values and access; your application owns its typed
public configuration. Keep normal nested TOML in `config/defaults.toml` and
`config/dev.toml`, `test.toml`, `staging.toml`, `production.toml`. Use native lists
and maps, for example `[server] trusted_proxies = ['127.0.0.1']` and
`[jobs] queues = {default = 10, events = 5}`. Esec does not flatten these public
files or decide their schema. The application should reject unknown keys and
secret fields, then overlay explicitly supplied process variables.

Commit public TOML, `esec.toml`, encrypted `.env.ENV` files and every matching
`.esec/keys/ENV/PUBLIC.age` and `.age.json` generation. Keep private identities,
recovery phrases, ignored `mise.local.toml`, and local overrides outside Git.
Keep shared public defaults in TOML; give each environment its own secret keys.
Do not automatically share production credentials with dev/test.

## Configure injection

In the project's `esec.toml`:

```toml
[run]
environment_variable = "APP_ENV"

[env.dev.run]
preserve_env = ["POSTGRES_CONNECTION_STRING", "POSTGRES_MIGRATION_CONNECTION_STRING"]

[env.test.run]
preserve_env = ["POSTGRES_CONNECTION_STRING", "POSTGRES_MIGRATION_CONNECTION_STRING"]
```

These are opt-in settings. `esec run dev -- COMMAND` sets `APP_ENV=dev` and
refuses a conflicting inherited selection. The binding must not also appear
in the encrypted file. The existing default remains: encrypted values override
inherited values. The configured preserve list keeps explicitly set inherited
values, including empty strings; an unset variable keeps the encrypted value.
Other inherited variables pass through normally.

Automatic preserve lists are refused for production, staging and guarded
environments. A deliberate per-command `--preserve-env NAME` still works there.
Esec credentials and process-loader controls cannot be selected as overrides.
Public settings such as ports normally belong only in TOML; then `SERVER_PORT=8082`
already overrides the application's public default without a preserve rule.

```sh
esec run dev --explain
esec run test --explain --json
esec run dev --preserve-env POSTGRES_CONNECTION_STRING -- ./server
```

Explain lists the selected file, proposed identity route, binding, and the
source of each injected variable. It does not decrypt, open private keys, read
key stdin, execute the command or prove an identity is available. It reports
Esec injection only; it cannot inspect an application's own configuration layers.

## Edit and check

```sh
esec set dev EMAIL_RESEND_API_KEY --create  # hidden prompt and confirmation
esec set dev EMAIL_RESEND_API_KEY          # update existing key
esec set dev TLS_CERT --stdin < protected-input
esec diff dev staging production --keys-only
esec check --ci
```

`set` encrypts with the public key, so it needs no decryption identity or
YubiKey touch. It snapshots the file before prompting and refuses a concurrent
change. It never accepts values as command-line arguments. Stdin is exact,
including a final newline; the limit is 1 MiB. New dotenv/YAML keys require
`--create`. Existing structured fields use dotted paths.

`diff` compares names and presence, never values. Environment-specific keys
are informational, not an error. `--json` gives a presence matrix.

`check` inspects every environment declared in `esec.toml`, including plaintext,
malformed envelopes, missing files/seals, public access-record hash mismatch,
recipient drift and pending writes. Findings exit 2, success exits 0. It needs
no identities and prints no values. It checks ciphertext structure and public
metadata, **not cryptographic authenticity**, and does not scan unrelated or
ignored files. Run it in CI and review recipient changes before `esec apply`.
