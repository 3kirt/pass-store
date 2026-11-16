# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A library crate holding the pass-compatible GPG token store that gitlab-mcp,
netbox-mcp and proxmox-mcp (all under `~/source/repos`, `3kirt` on GitHub)
each carry a copy of today; they move onto this crate one PR per repo. Once
they have, any behavior change here reaches all three apps, so keep every
invariant below, each with a test. A fix belongs here, not in an app.

## Commands

```sh
make check            # pre-release gate: fmt-check lint test deny consumer-smoke
make build            # cargo build --all-features
make test             # scripts/test-changelog.sh, then cargo test once per feature set
make lint             # secrets-scan, clippy (each feature set), fmt --check, rustdoc -D warnings, actionlint + shellcheck
make fmt              # cargo fmt
make deny             # cargo deny check (advisories, bans, sources, licenses)
make msrv             # cargo +<rust-version> test --all-features
make minimal-versions # direct deps at Cargo.toml's lower bounds (nightly resolve), suite on the MSRV
make check-windows    # clippy for x86_64-pc-windows-msvc: the cfg(not(unix)) paths
make coverage         # cargo llvm-cov incl. real gpg; fails under COVERAGE_MIN (97%) lines
make consumer-smoke   # a throwaway crate depending on HEAD through git, as the apps do
make test-real-gpg    # REAL_GPG=1: the real-gpg test (throwaway keys); fails if it skipped or didn't run

cargo test <test_name>   # run a single test
```

Every cargo invocation in the Makefile is `--locked`, except where resolving
is the point: `minimal-versions` re-resolves on purpose, and `consumer-smoke`
builds a fresh throwaway crate. Formatting and lint must be clean before every
commit: `make fmt`, then `make lint`.

**CI/CD** (the same shape as the three apps): the Makefile is the single source of
truth, and the workflows only call its targets.
- `ci.yml` runs lint, test and real-gpg on ubuntu and macos, deny, the
  consumer build, the non-Unix build, coverage and minimal-versions, plus
  msrv except on PRs. `release.yml` calls it as a gate.
- **Distribution:** GitHub only, never crates.io (`publish = false`). A
  release is a `vX.Y.Z` tag on main plus a GitHub release, and the apps pin
  the tag through git. A pushed tag is never moved or reused.
- `release.yml` runs on a `v*` tag. It runs verify (tag == Cargo.toml version,
  the tag is on main, the CHANGELOG has a section), then CI, then a consumer
  build against the tag fetched from GitHub, then a GitHub release with
  notes from `scripts/changelog-section.sh` and a source archive with its
  checksum and provenance attestation. Release with `/release`
  (`.claude/commands/release.md`). It runs pre-flight checks (clean `main`,
  green CI, an unused tag), the full local gate, cargo-semver-checks against
  the previous tag from the second release on, and a consumer build against
  the pushed tag.
- `scheduled.yml` runs weekly: deny, msrv, minimal-versions, stable/beta drift
  and real gpg on ubuntu and macos. A failure opens a `scheduled-failure`
  issue.
- Actions are pinned by commit SHA, with a `# vX.Y.Z` comment.

The toolchain is pinned in `rust-toolchain.toml` (1.100.0). The MSRV is
`rust-version` in Cargo.toml (1.88, the lowest of the three apps); keep it
buildable. cargo-deny bans aws-lc-sys/aws-lc-rs, allows only crates.io as a
source for this crate's own dependencies, and lists only licenses actually in
the tree. A new license must be
GPL-3.0-compatible before it goes into `deny.toml`. The crate is
GPL-3.0-or-later, which fits proxmox and gitlab (GPL-3.0-only) and netbox
(GPL-3.0-or-later). CHANGELOG headings are `## [X.Y.Z] - YYYY-MM-DD`.

**Public API:** keep it small. Everything public is re-exported at the crate
root, except the `agent` module (Unix-only) and `test_support` (feature
`test-support`). Helpers the apps don't call stay private. Fallible public
functions return `PassError` (or `TokenError`), never `String`.

Clippy runs at **pedantic** strictness: the `pedantic`, `nursery`, and `cargo`
lint groups are enabled in `Cargo.toml` under `[lints.clippy]`, with a curated,
commented allow-list (`multiple_crate_versions`, `doc_markdown`,
`redundant_feature_names`). New warnings must be fixed, not silenced, unless
they belong in that list. Public fallible functions document `# Errors`.

## Tests

Every invariant below has a unit test; a fix comes with a regression test.
- **Unit tests** live next to the code: `cargo test <name>` runs one.
- **`tests/public_api.rs`** uses only public items, with the `http` and
  `test-support` features (`required-features` in Cargo.toml), as an app
  would. A new public item gets a line there.
- **The README's Rust example** compiles as a doctest (`ReadmeDoctests` in
  lib.rs).
- **`scripts/test-changelog.sh`** tests `changelog-section.sh` and
  CHANGELOG.md's heading shape.
- **Coverage** is measured with the real-gpg test included. Raise
  `COVERAGE_MIN` in the Makefile when coverage rises; don't lower it to
  get a change through.
- **Lower bounds:** when code starts using a newer dependency API, raise
  that dependency's lower bound in Cargo.toml; `make minimal-versions`
  catches it.
- **The fake gpg** (`test_support`) is one script written once. Decrypt and
  key-listing modes *source* their last argument (the entry file, or a
  snippet passed as the recipient). Encrypt mode records argv in
  `<output>.args`; a `NOPUBKEY` recipient exits without reading stdin, and
  `HANG` hangs. The fake gpgconf next to it sources `<homedir>/gpgconf.sh`
  and exits when that exists, and otherwise answers `--list-dirs
  agent-socket` with `<homedir>/S.gpg-agent`.
- **Never write an executable at test time.** Use the shared fake
  gpg/gpgconf: writing and then executing a script races with other tests'
  spawns (ETXTBSY on Linux). On macOS a just-closed fd or listener can also
  leak briefly into another test's child process.
- A snippet that outlives its timeout must use `exec sleep 10`, not plain
  `sleep`: on macOS an orphaned child can hold another test's pipe open for
  10s.
- **The environment:** `PassStore::resolve` takes a `StoreEnv` and reads
  nothing from the process, so its tests build one: no lock, no `set_var`.
  Only `StoreEnv::from_process`, `env_var`, `home_dir` and `expand_tilde`
  read the process environment. Their tests change it only through
  `test_support::EnvGuard`, which holds `lock_env()` and restores every
  variable on drop, panics included. The apps must use this same lock as
  their only environment lock; proxmox-mcp's migration showed a separate app
  lock races with pass-store's reads. The README's "Testing an app that
  uses it" says so.
- **`real_gpg.rs`** generates a passphrase-less key, a protected key and a
  foreign key in a short GNUPGHOME from TMPDIR (prefix `psg`: macOS limits
  socket paths to 104 bytes). It runs `gpgconf --reload` after keygen and
  `--kill` on drop, and asserts DECRYPTION_OKAY, Locked (85), NoSecretKey
  (17), the agent states, and a successful read once the cache is primed.

## Layout

```
src/
  lib.rs          — re-exports; agent_status() (one status line, any platform)
  store.rs        — Branding, PassStore, PassEntry, PassError, StoreLocation, StoreEnv, read/write/recipients, helpers
  env.rs          — (private, re-exported at the root) env_var / non_blank / is_unset_value / is_unexpanded_placeholder / home_dir / expand_tilde(_in)
  agent.rs        — (unix) gpg-agent Assuan KEYINFO client, used only by `status`; public: state(), AgentState
  token.rs        — (feature http) LazyToken
  test_support.rs — (test or feature test-support) fake gpg and gpgconf, snippets, EnvGuard, lock_env
  real_gpg.rs     — (unix, #[ignore], REAL_GPG=1) the real-gpg classification test
tests/
  public_api.rs   — the public API as an app uses it
scripts/
  changelog-section.sh — release notes for one version (release.yml)
  test-changelog.sh    — its test, and CHANGELOG.md's heading shape
  consumer-smoke.sh    — a throwaway crate depending on a commit or tag through git
```

## Branding

No product name or command is hardcoded. The app builds a
`Branding::new(product, cli)` once. `cli` is a ready, shell-quoted prefix from
`Branding::cli_prefix(program, flag, config)`: proxmox uses `--config-dir`,
netbox and gitlab use `--config`. Keep the Locked message's wording
actionable, as `locked_message_keeps_the_actionable_wording` pins it:
"… token is locked: gpg-agent has no cached passphrase for the key that
decrypts P. Ask the user to unlock it by running `{cli} unlock` (or
`{gpg_decrypt} >/dev/null`) in a terminal, then retry." NotFound says
"run `{cli} login`".

## Invariants (all three apps rely on these)

**Read path (never prompts)**
- A missing entry is `NotFound` ("run `{cli} login`") for both `read_token`
  and `unlock_interactive`, before gpg runs.
- Decrypt runs `gpg --batch --quiet --no-tty --pinentry-mode error --status-fd 2
  --decrypt -- P` with stdin null, under a 10s timeout, with `kill_on_drop`.
- Classify only from the numeric `[GNUPG:] ERROR <loc> <code>` codes, taking the
  low 16 bits: 85 NO_PIN_ENTRY or 99 CANCELED → Locked, 17 NO_SECKEY →
  NoSecretKey, and Locked wins when both appear. Never match gpg's localized
  text. Success needs exit 0 **and** `DECRYPTION_OKAY`.
- The token is the plaintext's first line, trimmed, and must be non-empty.

**Store layout**
- Entry names reject empty names, NUL, backslash, absolute paths, and empty,
  `.` or `..` segments.
- Recipients come from the nearest ancestor `.gpg-id`, stopping at the store
  root, with everything after `#` stripped.
- `init` never overwrites a root `.gpg-id`.
- `resolve(&StoreLocation, &StoreEnv, Branding)` reads nothing from the
  process environment; `StoreEnv::from_process()` is the one snapshot. It
  expands `~/` against `StoreEnv::home` (in configured values and in the
  env's `password_store_dir` / `gnupg_home`) and makes the root and homedir
  absolute (`std::path::absolute`). `from_process` treats blank or `${…}`
  placeholder values as unset.
- gpgconf comes from the same directory as an explicitly configured gpg.

**write_token**
- Claim `.<entry>.gpg.tmp<pid>` with `create_new` at 0600 *before* gpg's
  `--yes --output`, so a planted file or symlink fails the write. Only delete a
  temp file this call created. Chmod it to 0600, then rename it atomically into
  place. Directories it creates are 0700; an existing directory keeps its
  mode.
- It refuses an empty recipient list up front, and a timeout names the
  entry, not the temp file.
- The stdin write and the wait run together under the timeout, and BrokenPipe
  is ignored, so the user sees gpg's own "No public key", not "Broken pipe".

**agent.rs**
- Keygrips come from `--with-colons --with-keygrip --list-secret-keys`. Only a
  lowercase `e` capability counts, and subkeys with validity (field 2) `e`,
  `r`, `d` or `i` are skipped. No recipients means no keygrips: gpg must
  never be asked to list the whole keyring.
- Paths from `gpgconf --list-dirs agent-socket` are percent-unescaped.
- A keygrip is hex-validated before it is sent.
- `ERR` code 27 means "not held".
- A missing socket or a refused connection means NotRunning.
- `summarize` precedence: Unlocked > Unprotected > Smartcard >
  NoSecretKey (empty) > Locked.

**LazyToken (feature `http`)**
- Decrypt on first use under a tokio Mutex, so concurrent callers run gpg once.
- Cache successes only.
- `mark_rejected(sent)` marks the token stale only if `sent` is still the
  current one.
- A failed re-read reuses the old token, so the caller sees the real 401 and
  not "locked", and gpg isn't run again for `REREAD_BACKOFF` (30s).
- The app supplies the header name and value format (`PRIVATE-TOKEN: x`,
  `Authorization: Token x`, `Authorization: PVEAPIToken=x`) and the rejection
  statuses (401 by default; netbox adds 403).
- The rotation retry stays in each app's `send()`, using `retry_value`. Add the
  header per attempt, because reqwest's `.header()` appends.
