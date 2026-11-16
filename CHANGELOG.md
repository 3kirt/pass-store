# Changelog

All notable changes to pass-store are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- The pass-compatible GPG token store from gitlab-mcp, netbox-mcp and
  proxmox-mcp, merged into one crate with every review fix from all three
  copies: `PassStore`, `PassEntry`, `PassError`, `StoreLocation`, and the
  `create_private_dir` / `create_private_file` / `shell_quote` helpers.
- `Branding`: the app passes its product name and CLI prefix in once, so
  "locked" and "not found" messages give advice for that app (for example
  `proxmox-mcp --config-dir '/x' unlock`).
- `agent`: the gpg-agent `KEYINFO` client behind `status`, plus
  `agent::state` and `agent_status` to compose it.
- `env`: the placeholder-aware `env_var`, `non_blank`,
  `is_unexpanded_placeholder`, `home_dir` and `expand_tilde`.
- `http` feature: `LazyToken`, a pass-backed auth header. It is decrypted on
  first use and re-read after a rejection, with a 30s backoff when that
  re-read fails.
- `test-support` feature: the shared fake gpg (`fake_gpg`, `ok_snippet`,
  `LOCKED_SNIPPET`, `NO_SECKEY_SNIPPET`, and a `NOPUBKEY` recipient in encrypt
  mode), plus `lock_env`.
- `test-support`: a fake `gpgconf` next to the fake gpg (it reports
  `<homedir>/S.gpg-agent`), key-listing snippets passed as the recipient, and
  a `HANG` recipient, so apps can test `status` and timeouts without writing
  their own scripts.

### Fixed
- Dependency lower bounds are now ones the crate actually builds with:
  `tokio` 1.26, `tempfile` 3.20 (`TempDir::keep`) and `tracing` 0.1.6. With
  the old `"1"` / `"3"` / `"0.1"`, an app whose lockfile pinned an older
  release failed to compile pass-store.
- `percent-encoding` is a Unix-only dependency, like the agent client that
  uses it, and the non-Unix build is clippy-clean.

### Documentation
- README: how to depend on the crate from git before it is on crates.io,
  including the `version` key and the `deny.toml` entries an app needs, and a
  local-checkout override.

### Internal
- About 50 new unit tests: `unlock_interactive`, `agent::state` and
  `agent_status` end to end against a scripted agent, gpgconf parsing, the
  placeholder warning, the I/O error paths, and the backoff window.
- `tests/public_api.rs` exercises the crate as an app does. The README
  example compiles as a doctest, and `scripts/test-changelog.sh` tests the
  release-notes script.
- New CI jobs:
  - coverage with cargo-llvm-cov, including the real-gpg test (fails under
    97% of lines)
  - minimal-versions (lower bounds, on the MSRV)
  - a Windows-target clippy build
  - real gpg on macOS too
  - rustdoc with warnings as errors
  - actionlint and shellcheck
- Tests run once per feature set.
