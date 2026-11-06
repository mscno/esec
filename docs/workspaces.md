# Monorepo workspaces

Use a root workspace index to navigate independent stores and check them together.
Each store keeps its existing project label, environments, encrypted documents,
recipients and `.esec/keys/` history. Adding a workspace requires no key rotation,
environment renaming, or changes to application embedding paths.

```text
repo/
  esec.toml
  backend/
    esec.toml
    config/production.etoml
    .esec/keys/...
  secrets/mobile-release/
    esec.toml
    config/production.etoml
    .esec/keys/...
```

The root `esec.toml` contains only the index:

```toml
[workspace.members]
backend = "backend"
mobile = "secrets/mobile-release"
```

Add only stores that exist and need secrets. Create a new member directory and
initialize its store there with `esec init --project acme/repo/mobile --env dev
--yes` before adding it to the index. Each member must have its own regular
`esec.toml`. Use distinct project labels for independent stores.

The index cannot contain project, file naming, environment, run or recovery
settings. There is no policy inheritance, shared key or recipient group. A backend
deployment identity gains no access to a mobile store merely because both are
listed in the same workspace. Member manifests remain authoritative.

## Select a store explicitly

From the repository root:

```bash
esec --member backend get production DATABASE_URL
esec --member backend run production -- ./scripts/start-backend
esec --member mobile blob set production APPLE_P8 --create --from ./AuthKey.p8
esec --member mobile blob run production --file APPLE_KEY_PATH=APPLE_P8 -- ./scripts/release-tool
```

`--member` resolves environment names and secrets filenames in that member.
Explicit secrets filenames must stay within the selected store. It never changes
the working directory: blob input/output paths, encryption output paths, explicit
key directories and child commands stay relative to the calling directory.
Default local keyring lookup uses the selected member directory. Normal machine
and global credential resolution still follows the store's existing access rules.

The flag supports store operations including init, adopt, repair, encrypt,
decrypt, get, export, run, set, blob, inspect, recipients, rotate, diff, check,
plan, status, apply, files and secrets show/update, plus recovery verify. Machine
setup, identity creation and recovery identity management are independent of
workspaces and do not accept `--member`.

From inside `backend/`, existing commands such as `esec get production ...` keep
working unchanged. Explicit `--member mobile` can select a sibling store from
within another member. From the workspace root, an unscoped environment name
fails and requires a selection, even if only one store has that environment. Esec
never guesses a member. An explicit secrets pathname may also select its own
store, as before.

## Inspect the whole workspace without decrypting

```bash
esec check --workspace --ci
esec status --workspace --check
esec plan --workspace
esec files --workspace --json
```

Reports visit declared members in alias order and group output by member. No
identity is opened or hardware touched. Plans display each member's resolved
recipients, sensitive changes and independent plan hash. File listings show paths,
formats and key names; ciphertext does not reveal which values encode blobs.

With `--json`, the report contains `workspace` and a `members` array. Each member
has `member`, `path`, and a command-specific `check`, `plan` or `files` field.
Missing, invalid or unsafe members have a stable `error` code instead. One broken
member does not hide the other members' results. Root index errors abort the
operation. Read-only output never includes secret values or parser source lines.

`check --workspace` exits 2 for findings or invalid members. `status --workspace
--check` exits 2 for unapplied access and 1 for member inspection errors. Plan and
file inspection errors exit 1. `--env` on workspace plan/status filters each
member independently; a member missing the selected environment reports an error.

## Apply one reviewed store at a time

```bash
esec --member mobile plan
esec --member mobile apply
# Scripts: use that member's reviewed hash and existing sensitive-change approval.
esec --member mobile apply --yes --plan-hash REVIEWED_MEMBER_HASH --approve-sensitive
```

Workspace-wide mutation is not supported. `apply --workspace` is an unknown flag;
`--member` and `--workspace` cannot be combined. Existing member plan hashes,
confirmation requirements, revision checks and rotation behavior are unchanged.

## Path and compatibility rules

An index has 1–256 explicit aliases. Names start with a lowercase letter and use
lowercase letters, digits, underscores or hyphens. Paths are relative subdirectories,
with no parent traversal, globs, control characters, `.git` or `.esec` components.
Duplicate and overlapping member paths are rejected. Aliases that resolve to the
same physical directory are rejected, including case variants on case-insensitive
filesystems. Member directories and
manifests must not be symlinks. Paths cannot cross another store, a nested Git
repository or a nested workspace. These checks cover the filesystem at resolution;
use a trusted checkout and do not replace directories concurrently with commands.

Workspace discovery walks upward and stops at a Git boundary. Stores themselves
do not search for or inherit a workspace during ordinary use, so a member copied
or deployed alone continues to work. Workspace operations require Esec v0.24.0
or newer; older versions cannot operate on the root index. Existing standalone
stores and encrypted formats remain compatible with their prior Esec versions.
