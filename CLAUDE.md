# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A library crate holding the pass-compatible GPG token store that gitlab-mcp,
netbox-mcp and proxmox-mcp (all under `~/source/repos`, `3kirt` on GitHub)
each used to carry a copy of. Any behavior change here reaches all three
apps, so keep every invariant below, each with a test. A fix belongs here,
not in an app.

## Commands

```sh
make check          # pre-release gate: fmt-check lint test deny package
make build          # cargo build --all-features
make test           # cargo test, default and --all-features
make lint           # secrets-scan + clippy --all-targets (each feature set) -D warnings + fmt --check
make fmt            # cargo fmt
make deny           # cargo deny check (advisories, bans, sources, licenses)
make msrv           # cargo +<rust-version> test --all-features
make package        # cargo package (PACKAGE_FLAGS=--allow-dirty before committing)
make test-real-gpg  # REAL_GPG=1: classification against the real gpg (makes throwaway keys)

cargo test <test_name>   # run a single test
```

Every cargo invocation in the Makefile is `--locked`. Formatting and lint must be
clean before every commit: `make fmt`, then `make lint`.

**CI/CD** (the same shape as the three apps): the Makefile is the single source of
truth, and the workflows only call its targets.
- `ci.yml` runs lint, test on ubuntu and macos, real-gpg, deny and package,
  plus msrv except on PRs. `release.yml` calls it as a gate.
- `release.yml` runs on a `v*` tag. It runs verify (tag == Cargo.toml version,
  the tag is on main, the CHANGELOG has a section), then CI, then
  `cargo publish` (secret `CARGO_REGISTRY_TOKEN`), then a GitHub release with
  the `.crate`, a checksum, a provenance attestation and notes from
  `scripts/changelog-section.sh`. Release with `/release`
  (`.claude/commands/release.md`).
- `scheduled.yml` runs weekly: deny, msrv, stable/beta drift and real gpg on
  ubuntu and macos. A failure opens a `scheduled-failure` issue.
- Actions are pinned by commit SHA, with a `# vX.Y.Z` comment.

The toolchain is pinned in `rust-toolchain.toml` (1.100.0). The MSRV is
`rust-version` in Cargo.toml (1.88, the lowest of the three apps); keep it
buildable. cargo-deny bans aws-lc-sys/aws-lc-rs, allows crates.io sources only,
and lists only licenses actually in the tree. A new license must be
GPL-3.0-compatible before it goes into `deny.toml`. The crate is
GPL-3.0-or-later, which fits proxmox and gitlab (GPL-3.0-only) and netbox
(GPL-3.0-or-later). CHANGELOG headings are `## [X.Y.Z] - YYYY-MM-DD`.

Clippy runs at **pedantic** strictness: the `pedantic`, `nursery`, and `cargo`
lint groups are enabled in `Cargo.toml` under `[lints.clippy]`, with a curated,
commented allow-list (`multiple_crate_versions`, `doc_markdown`,
`redundant_feature_names`). New warnings must be fixed, not silenced, unless
they belong in that list. Public fallible functions document `# Errors`.

## Layout

```
src/
  lib.rs          — re-exports; agent_status() (one status line, any platform)
  store.rs        — Branding, PassStore, PassEntry, PassError, StoreLocation, read/write/recipients, helpers
  env.rs          — env_var / non_blank / is_unexpanded_placeholder / home_dir / expand_tilde
  agent.rs        — (unix) gpg-agent Assuan KEYINFO client, used only by `status`
  token.rs        — (feature http) LazyToken
  test_support.rs — (test or feature test-support) fake gpg, snippets, lock_env
  real_gpg.rs     — (#[ignore], REAL_GPG=1) the real-gpg classification test
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
- `resolve` expands `~/` and makes the root and homedir absolute
  (`std::path::absolute`). Blank or `${…}` placeholder env vars count as
  unset.
- gpgconf comes from the same directory as an explicitly configured gpg.

**write_token**
- Claim `.<entry>.gpg.tmp<pid>` with `create_new` at 0600 *before* gpg's
  `--yes --output`, so a planted file or symlink fails the write. Only delete a
  temp file this call created. Chmod it to 0600, then rename it atomically into
  place. Directories are 0700.
- The stdin write and the wait run together under the timeout, and BrokenPipe
  is ignored, so the user sees gpg's own "No public key", not "Broken pipe".

**agent.rs**
- Keygrips come from `--with-colons --with-keygrip --list-secret-keys`. Only a
  lowercase `e` capability counts, and subkeys with validity (field 2) `e`,
  `r`, `d` or `i` are skipped.
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

**Tests**
- The fake gpg (`test_support`) is one script written once, which avoids
  ETXTBSY races. Decrypt mode *sources* the entry file; encrypt mode records
  argv in `<output>.args`; a `NOPUBKEY` recipient exits without reading stdin.
- A snippet that outlives its timeout must use `exec sleep 10`, not plain
  `sleep`: on macOS an orphaned child can hold another test's pipe open for
  10s.
- Hold `test_support::lock_env()` around any env mutation, and around anything
  that resolves a store from the environment.
- `real_gpg.rs` generates a passphrase-less key, a protected key and a foreign
  key in a short GNUPGHOME from TMPDIR (prefix `psg`: macOS limits socket
  paths to 104 bytes). It runs `gpgconf --reload` after keygen and `--kill` on
  drop, and asserts DECRYPTION_OKAY, Locked (85), NoSecretKey (17), the agent
  states, and a successful read once the cache is primed.
