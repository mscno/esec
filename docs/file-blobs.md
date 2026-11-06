# Encrypted credential files

Use `esec blob` for Apple `.p8` keys, service-account JSON, keystores, or other
text and binary files up to 1 MiB. Bytes are encoded as `esec-blob-v1:` plus
base64 **inside an encrypted string value**. Base64 alone is not encryption.
Blobs work in dotenv, TOML, JSON and YAML stores, using the environment's existing
recipients, recovery identities, access checks and key rotation.

Keep different purposes in independent stores when their readers differ. For
example, initialize `secrets/mobile-release/` with its own `esec.toml`, environments
and recipients. Give a backend deployment identity access only to its backend
store; it should not also receive mobile signing credentials.

## Import and verify

Run these commands from an initialized mobile-release store:

```bash
esec blob set production APPLE_P8 --create --from ../../AuthKey.p8
esec blob set production GOOGLE_JSON --create --stdin < ../../service-account.json
esec blob set production ANDROID_KEYSTORE --create --from ../../release.keystore
esec check --ci
```

Imports need only the public encryption key and write ciphertext directly.
They never delete or modify the source file. `--create` adds a simple top-level
name starting with a letter, followed by letters, digits or underscores. Omit
`--create` when replacing an existing key; existing nested string fields can be
addressed with dotted paths. Concurrent destination edits abort the save.
New nested paths must be created in the document separately.

Verify exact bytes with an intended decryption identity before deleting the
original plaintext. With Bash:

```bash
set -o pipefail
esec blob get production APPLE_P8 | cmp ../../AuthKey.p8 -
esec blob get production GOOGLE_JSON | cmp ../../service-account.json -
```

`check --ci` validates ciphertext syntax and public policy, without opening keys;
it does not verify decryption. `blob get` authenticates decryption, accepts only
blob values, and prints exact bytes, including binary data and trailing newlines.
Ordinary `get` returns the encoded value. To migrate an existing multiline secret
value, import the original file with `blob set` and verify it before removal.

## Give a tool a temporary filename

```bash
esec blob run production \
  --file GOOGLE_APPLICATION_CREDENTIALS=GOOGLE_JSON \
  -- ./submit-release

esec blob run production --file APPLE_KEY_PATH=APPLE_P8 -- \
  sh -c 'release-tool --private-key "$APPLE_KEY_PATH"'
```

Repeat `--file VARIABLE=KEY` to select more files. Each child variable receives an
absolute filename. Blob contents and other store values are not added to the
child's environment. The child otherwise inherits the calling environment.
The selected document is decrypted in memory; only selected blobs are written.
Filenames are generated locally, never derived from blob content or key paths.

On Unix, the temporary directory has mode 0700 and files have mode 0600 (or
stricter under the caller's umask). Esec removes the directory when the child
exits, fails, or cannot start. SIGINT and SIGTERM are forwarded to the child's
process group; Esec waits up to five seconds, kills remaining processes in that
group if necessary, then cleans up. A second signal forces termination sooner.
Run a foreground tool that waits for its own work; detached/background processes
cannot rely on these filenames remaining available.

SIGKILL, power loss and system crashes cannot run cleanup. Temporary files are
plaintext while the tool runs; use a trusted host and tool. Removal is unlinking,
not secure erasure. For memory-backed storage on Linux, set `TMPDIR` to a private
directory on an appropriately protected tmpfs. Disk materialization fails closed
on Windows, where Unix modes do not establish private ACLs; imports and stdout
exports remain available.

## Deliberate persistent export

```bash
esec blob get production APPLE_P8 --out /secure/restored.p8
```

`--out` creates a new 0600 file on Unix, refuses existing files and symlinks, and
removes partial output on write errors. Its parent directory must already exist;
choose a trusted private directory. This is a persistent plaintext export: remove
it when finished. Stdout output is also plaintext; avoid terminal logs and
unprotected shell redirection.

Esec can hold recoverable copies of credentials used by Expo or another managed
service. Importing a blob does not change the credentials held by that service or
replace its operational credential storage.
