# esec-vault: Implementation Plan

A layered secrets-identity, backup, and sharing system built around `esec`, with a
hard design constraint: **the `esec` core stays slim and auditable**. All new
machinery lives in a separate module (`esec-vault`) that treats core esec as a
library. The contract between the two is file formats, not APIs.

## Goals

1. One personal identity, recoverable from a 24-word BIP39 mnemonic, that unlocks
   all project keys.
2. No plaintext key material in repository working directories.
3. A broker (ssh-agent-style) that holds keys in RAM and answers policy-checked
   decryption requests, so agents never possess key material.
4. Team sharing without a server: git is the transport, GitHub is the identity
   root of trust, NaCl sealed boxes are the payload format.
5. Endgame: no plaintext keyring files at all — ciphertext on disk, keys only in
   broker RAM.

## Non-goals (explicitly deferred)

- HTTP/Postgres auth-injecting proxies (phase 5+, separate plan).
- Multi-tenant server, orgs/teams CRUD, JWT sessions, GitHub App installation
  checks (the archived 2025 design — not coming back).
- Key transparency infrastructure. Small teams use proof-via-GitHub + TOFU
  pinning instead.

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│ esec (core, this repo) — audited boundary                  │
│  - crypto primitives (box, sealed boxes, HKDF derivation)  │
│  - file formats (.ejson/.env/.eyaml...)                    │
│  - key lookup: env vars → keyring file (local or global)   │
│  - subcommand passthrough (esec vault → esec-vault)        │
│  - NO network, NO bip39, NO OS keyring, NO new deps        │
└────────────────────────────────────────────────────────────┘
              ▲ library import (semver-pinned)
┌────────────────────────────────────────────────────────────┐
│ esec-vault (new repo github.com/mscno/esec-vault)          │
│  identity/    mnemonic → master key → identity keypair     │
│  keystore/    central keyring dir (outside repos)          │
│  vaultfile/   sealed vault blob format (backup/restore)    │
│  broker/      unix socket daemon + policy + audit log      │
│  share/       team sharing, GitHub proofs, TOFU pinning    │
└────────────────────────────────────────────────────────────┘
```

**Identity hierarchy** (fixes the no-rotation flaw of the 2025 design):

```
mnemonic (BIP39, 24 words, cold storage / SLIP-39 later)
  └─HKDF(info="esec-master-v1")→ master keypair (deterministic, cold)
       wraps → identity keypair (random, in OS keyring for daily use)
                    seals → vault blob (all project keyrings)
```

Rotating the identity key = generate a new random keypair, re-wrap with master,
re-seal vault blobs. Mnemonic unchanged. Crypto note: NaCl box keys are X25519
and **cannot sign** — signing/proofs use GitHub SSH keys instead (see Phase 3),
keeping core crypto to box + sealed box + HKDF only.

**Storage layout:**

```
~/.config/esec/                      # ($XDG_CONFIG_HOME/esec; override: ESEC_VAULT_HOME)
  keyrings/<org>_<repo>.keyring      # global keyring store, transitional (0600)
  identity.esec                      # identity priv sealed to master key (0600)
  vault.esec                         # all keyrings, sealed to identity (0600)
  agent.sock                         # broker socket (0700 dir)
  audit.log                          # broker audit log (0600)
  policy.toml                        # broker policy

# In each project repo (committed, non-secret):
.esec-project                        # ESEC_PROJECT=org/repo   (exists today)
.esec/vault/<github-login>.esec      # per-member sealed keyring blobs (Phase 3)
```

---

## Phase 0 — Core esec changes (this repo)

Three small, independently shippable changes. Target: esec v0.5.0.

### 0.1 Global keyring folder

Today: `findPrivateKey` (root `esec.go`) tries user-supplied key → env vars →
keyring file, where the keyring path is `ESEC_KEYRING_PATH` or
`<keydir>/.esec-keyring` (keydir defaults to `.`).

Add a global folder lookup so keyrings can live outside repos, keyed by project:

- Global keyring store defaults to `~/.config/esec/keyrings` (respects
  `XDG_CONFIG_HOME`) and is **always active** in the lookup chain;
  `ESEC_KEYRING_DIR` overrides the directory. (Precedent: sops stores keys in
  `~/.config/sops`, age in `~/.config/age`.)
- Reintroduce a minimal `.esec-project` reader as `pkg/projectfile` (a slim
  version of the deleted one, recoverable from `18709f8^:pkg/projectfile/project.go`:
  read `ESEC_PROJECT=org/repo`, validate `^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$`).
- Lookup order becomes:
  1. user-supplied (`-k` stdin / direct)
  2. `ESEC_PRIVATE_KEY[_<ENV>]` env vars
  3. `ESEC_KEYRING_PATH` file
  4. `<keydir>/.esec-keyring` (repo-local, current behavior)
  5. **NEW:** global store `<keyring-dir>/<org>_<repo>.keyring` — project name
     from `.esec-project` in cwd (walk up to repo root), `/` → `_` in filename
  6. global store `default.keyring` (last resort)
- Apply existing `checkKeyringPermissions` to global files too.
- Tests: full precedence chain; missing `.esec-project` ⇒ skip step 5 silently;
  permission warning emitted for world-readable global keyrings.

### 0.2 Subcommand passthrough (the "15-line link")

In `cmd/esec/commands/cli.go`, before `kong.Parse`:

- If `os.Args[1]` is not a builtin command and not a flag, `exec.LookPath(
  "esec-"+arg)`; if found, exec it with `os.Args[2:]`, stdio attached.
- Unix: `syscall.Exec` (process replacement, exit codes propagate naturally).
- Windows: `os/exec` spawn + propagate child exit code via existing `ExitError`.
- Not found ⇒ fall through to kong, which errors with usage as today.
- Tests: fake `esec-foo` on PATH receives args/env/stdio; unknown command
  without a binary errors exactly as before; `esec --help` unaffected.

### 0.3 Crypto helpers in `pkg/crypto`

So vault never implements crypto primitives itself:

- `SealAnonymous(msg []byte, recipientPub *[32]byte) ([]byte, error)` and
  `OpenAnonymous(boxed []byte, pub, priv *[32]byte) ([]byte, error)` — thin
  wrappers over `golang.org/x/crypto/nacl/box.SealAnonymous/OpenAnonymous`
  (x/crypto is already a core dep; no new dependencies).
- `DeriveKey(seed []byte, info string) ([32]byte, error)` — HKDF-SHA256
  (x/crypto/hkdf) with fixed salt, versioned info strings
  (`"esec-master-v1"`, `"esec-identity-v1"`).
- Tests: known-answer vectors, round-trips, wrong-key open fails.

---

## Phase 1 — esec-vault MVP: identity + central store + backup

New repo `github.com/mscno/esec-vault`, module pinned to esec v0.5.0. Reuse
esec's CI/release setup (goreleaser, signing, attestation). Target: v0.1.0.

### 1.1 Identity (`internal/identity`)

- `esec-vault identity init`:
  1. `bip39.NewEntropy(256)` → 24-word mnemonic (dep:
     `github.com/tyler-smith/go-bip39` — vault-side dep, not core).
  2. entropy → core `DeriveKey(seed, "esec-master-v1")` → master keypair.
  3. random identity keypair via core `esec.GenerateKeypair`.
  4. identity private key → `SealAnonymous(priv, masterPub)` →
     `~/.config/esec/identity.esec` (0600).
  5. identity private key (hex) + public key → OS keyring
     (dep: `github.com/zalando/go-keyring`, service `esec-vault`).
  6. Print mnemonic once, require re-entry to confirm. Never log it.
- `esec-vault identity recover`: mnemonic → master → open `identity.esec` →
  re-store in OS keyring. Handles: blob missing (regenerate identity → warn that
  old vault blobs are unrecoverable), OS keyring already populated (confirm
  overwrite).
- `esec-vault identity rotate`: new random identity keypair, re-wrap to master,
  re-seal vault blob (1.3), update OS keyring. Old blobs become garbage by
  design; rotation is the response to identity-key compromise.
- `esec-vault identity show`: print public key fingerprint (SHA-256 of pubkey,
  hex + base32) for out-of-band verification.

### 1.2 Central key store (`internal/keystore`)

- `esec-vault keyring migrate [--dir <repo>]...`:
  - read repo-local `.esec-keyring` (or walk all repos under a root dir),
  - project id from `.esec-project`; if absent, prompt/flag for it and write
    the file,
  - write to the global keyring store (default `~/.config/esec/keyrings`,
    override `ESEC_KEYRING_DIR`) as `<org>_<repo>.keyring` (0600, refuse to
    follow symlinks, fail if target exists unless `--force`),
  - verify core esec can decrypt with the global file (`esec decrypt dev` dry
    run against step 5 of the new lookup chain) **before** deleting the
    repo-local file; deletion is opt-in via `--delete-local` and always
    confirmed interactively,
  - ensure `.esec-keyring` is in the repo's `.gitignore` (append if missing).
- `esec-vault keyring list`: projects, environments, key counts — metadata
  only, never values.

### 1.3 Vault backup/restore (`internal/vaultfile`)

Format (all multi-byte fields little-endian):

```
magic "ESECVLT" | version byte (1) | timestamp unix64 |
sealed box of JSON:
  { "projects": { "org/repo": { "<ESEC_PRIVATE_KEY_DEV>": "<hex>", ... } },
    "sha256": "<hash of canonical projects JSON>" }   // tamper evidence inside
```

- `esec-vault backup`: read all `keyrings/*.keyring` → build index → seal to
  identity pubkey → write `vault.esec` (0600, atomic write via temp+rename).
  `--out <path>` to copy elsewhere (private git repo, USB, synced folder).
- `esec-vault restore [--dir <keyring-dir>]`: open with identity key from OS
  keyring, verify inner sha256, write keyrings 0600. Refuses to overwrite
  existing non-identical keyrings without `--force` (or per-file interactive
  confirm).
- `esec-vault recover`: full cold path = `identity recover` + `restore`.

**Acceptance:** round-trip on temp dirs; fresh-user simulation (new OS keyring
→ recover from mnemonic + `vault.esec` only); corruption tests (truncated blob,
bit flip → inner hash catches it); no plaintext ever outside 0600 files; file
perms asserted in tests.

---

## Phase 2 — Broker + `esec vault run`

Target: esec-vault v0.2.0.

### 2.1 Broker (`esec-vault agent`)

- `esec-vault agent [--ttl 4h] [--policy ~/.config/esec/policy.toml]`
- Holds decrypted keyrings in RAM only: at startup, unlocks identity from OS
  keyring ( Touch ID / keychain prompt is the OS's job), reads central keyrings
  (or opens `vault.esec` directly with `--from-vault`, Phase 4 default).
- Unix socket at `~/.config/esec/agent.sock` (dir 0700, socket 0600),
  override `ESEC_VAULT_SOCK` / `--sock`.
- **Peer authentication on every connection:** Linux `SO_PEERCRED`, macOS
  `LOCAL_PEERCRED`/`getpeereid`. Record uid+pid; policy can match on uid.
- Protocol: newline-delimited JSON requests — enough, and debuggable:
  `{"op":"get_secrets","project":"org/repo","env":"dev"}` →
  `{"ok":true,"env":{"KEY":"value",...}}` or `{"ok":false,"error":"denied: prod requires approval"}`.
  Only two more ops: `list_envs`, `ping`. Broker never returns key material —
  only decrypted secret values, per policy.
- TTL: daemon exits after duration; `SIGHUP`/`esec-vault agent stop` kills.

### 2.2 Policy (`~/.config/esec/policy.toml`)

```toml
default = "deny"
[[rule]]  # first match wins
project = "*"            # or "org/repo", or "org/*"
env     = ["dev", "dev-agent"]
uid     = 501            # optional
action  = "allow"        # allow | ask | deny
```

- `ask` in v1: broker writes a request file and blocks until `esec-vault
  approve <id>` (or OS notification via `osascript` on macOS — nice-to-have).
- Every decision (allow/ask/deny) appended to `audit.log`:
  `ts uid pid project env op decision`.

### 2.3 `esec-vault run`

- `esec-vault run <env> -- cmd args...`:
  1. project id from `.esec-project` (walk up from cwd),
  2. request decrypted env from broker,
  3. spawn child with merged env (reuse spawn/signal/exit-code patterns from
     core `cmd/esec/commands/run_unix.go`/`run_windows.go`),
  4. zero the env map after spawn.
- No broker ⇒ hard error (no silent fallback to local keyring — that's the
  whole point). Explicit opt-out flag `--local-keyring` delegates to core
  behavior for interactive use.
- With the 0.2 passthrough, this is also reachable as `esec vault run ...`.

**Acceptance:** broker never writes key material (strace/fs-watch in tests);
a process running as a *different uid* (docker container or test user) gets
secrets only when policy allows, and only via the socket; audit lines for every
decision; TTL expiry revokes access; `run` forwards signals and exit codes;
agent-compromise simulation: with only socket access and `allow dev` policy,
attacker can decrypt dev values but cannot extract any private key.

---

## Phase 3 — Team sharing (git-native)

Target: esec-vault v0.3.0. For teams of ~2–10; no server.

### 3.1 Member identity proofs

X25519 keys can't sign, so GitHub SSH keys are the root of trust:

- Member publishes a proof: JSON
  `{github_login, github_id, esec_pubkey, created_at}`, **signed with an SSH
  key registered on their GitHub account** (dep: `golang.org/x/crypto/ssh` for
  verify; fetch keys from `https://github.com/<login>.keys` or `gh api`).
- Proof storage: committed to the repo at `.esec/members/<login>.proof` (PR
  from the member's own account = GitHub authenticates authorship) and/or as a
  gist referenced in the proof.
- `esec-vault members verify [--repo <path>]`: fetch GitHub keys, verify
  signatures, print fingerprints.
- TOFU pinning: `esec-vault trust <login> --fingerprint <hex>` records
  first-seen fingerprints in `~/.config/esec/trusted.toml`; any later
  change is a loud, hard failure requiring explicit re-trust. Small teams:
  confirm fingerprints on one call, done forever.

### 3.2 Share / sync

- `esec-vault share --to <login>[,<login>...] [--env dev]...`:
  1. load member proofs from `.esec/members/`, verify against GitHub + pins,
  2. seal the project's keyring entries to each recipient's identity pubkey
     (core `SealAnonymous`),
  3. write `.esec/vault/<login>.esec`:
     `{from, from_fingerprint, ts, payload: <sealed box>}` — sealed payload
     includes inner sha256 for tamper evidence,
  4. commit (user reviews and pushes — vault never runs git mutations itself).
- `esec-vault sync`: find `.esec/vault/<my-login>.esec` in the current repo,
  open with identity key, merge into the central key store (0600, conflict →
  interactive prompt). This is the **clone-and-go flow**:
  `git clone … && esec vault sync && esec run dev -- make dev`.
- Offboarding: delete `.esec/vault/<login>.esec` + rotate the affected
  environment keys (manual; document the runbook) + re-share.

**Acceptance:** two-identity integration test (share → clone-simulation →
sync → decrypt); tampered blob fails on inner hash; changed proof after pinning
fails hard; a member with no proof is skipped with a clear message.

---

## Phase 4 — No-plaintext endgame

- Broker loads straight from `vault.esec` (`--from-vault` becomes default);
  central keyring files become a transitional artifact you can delete.
- Core esec interactive use keeps working by pointing `ESEC_KEYRING_PATH` at a
  restored keyring when wanted — user choice, documented.
- Document the three postures: repo-local keyring (legacy) → central keyring →
  broker-only. New setups start at broker-only.
- Revisit deferred proxies (HTTP header injector first; Postgres relay later)
  in a separate plan.

---

## Cross-cutting

**Security invariants (assert in tests/CI):**

1. Core gains zero new third-party dependencies in Phases 0–4.
2. Vault never implements crypto primitives — only core `pkg/crypto` functions.
3. Plaintext key material exists only in: 0600 keyring files (transitional) and
   broker RAM (endgame). Everything else on disk is sealed ciphertext.
4. Every broker decision is audit-logged.
5. Vault never executes git mutations or network calls except GitHub key/proof
   fetches (Phase 3, read-only, HTTPS).

**Testing:** table-driven unit tests per package; integration tests in
`internal/.../e2e` with temp HOME/XDG dirs and a mock OS keyring (the
`internal/identity` keyring access goes behind an interface, like the 2025
code's `oskeyring.Service`); CI matrix on macOS + Linux (peer-cred code is
platform-specific); Windows supported for CLI but broker is unix-only in v1.

**Risks / decisions to revisit:**

- Passthrough interplay with kong: must run before kong parsing, must not
  swallow `--help`. Low risk, well-tested.
- Peer-uid portability: Linux + macOS fine; Windows broker deferred.
- `ask` UX quality determines whether agents flow or frustrate — start with
  `esec-vault approve`, add OS notifications after.
- SLIP-39 (Shamir) for the mnemonic: deliberately postponed; single mnemonic +
  `identity.esec` + teammate re-share is the recovery story for now.

**Rough effort (evenings/weekends scale):**

| Phase | Scope | Estimate |
|-------|-------|----------|
| 0 | core: global keyring dir, passthrough, crypto helpers | 2–3 sessions |
| 1 | vault: identity, keystore, backup/restore | 3–4 sessions |
| 2 | broker, policy, `vault run` | 4–5 sessions |
| 3 | sharing, proofs, pinning | 3–4 sessions |
| 4 | broker-only posture, docs, hardening | 1–2 sessions |

**Release plan:** esec v0.5.0 (Phase 0) → esec-vault v0.1.0 (Phase 1) →
v0.2.0 (Phase 2) → v0.3.0 (Phase 3) → v1.0.0 after Phase 4 + a focused review
pass of core crypto and the vault format.
