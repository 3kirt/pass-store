# Changelog

All notable changes to pass-store are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-16

The first release: the pass-compatible GPG token store that gitlab-mcp,
netbox-mcp and proxmox-mcp each carry a copy of, merged into one crate with
every review fix from all three copies. It is distributed from GitHub only
(apps pin a release tag through git), never crates.io.

### Added
- `PassStore`, `PassEntry` and `StoreLocation`: a `pass`-compatible store
  driven through `gpg`.
  - Reads never prompt: `--pinentry-mode error`, stdin closed, a 10s
    timeout.
  - Failures are classified from gpg's numeric status codes into
    `PassError::{NotFound, Locked, NoSecretKey, Timeout}`. `PassError` is
    `#[non_exhaustive]`.
  - Writes are atomic, through an owner-only temp file claimed before gpg
    writes to it.
  - Recipients come from the nearest `.gpg-id`, and `~/` is expanded in
    configured and environment paths.
- `Branding`: the app passes its product name and CLI prefix in once, so
  "locked" and "not found" messages give advice for that app (for example
  `proxmox-mcp --config-dir '/x' unlock`). `Branding::cli_prefix` builds the
  shell-quoted prefix.
- The `create_private_dir`, `create_private_file` and `shell_quote`
  helpers.
- `agent` (Unix): the gpg-agent `KEYINFO` client behind `status`, with
  `agent::state` for the whole check and `agent_status` for a ready status
  line on any platform.
- Env helpers: `env_var` (blank and unexpanded `${VAR}` placeholders count
  as unset, with a warning), `non_blank`, `is_unset_value`,
  `is_unexpanded_placeholder`, `home_dir` and `expand_tilde`.
- `http` feature: `LazyToken`, an HTTP auth header.
  - It is decrypted on first use, once for concurrent callers.
  - `retry_value` re-reads it after a rejection, so the first request after
    a token rotation can retry once.
  - A failed re-read backs off for 30s and keeps the old token, so the
    caller sees the server's real 401.
- `test-support` feature, for the apps' own tests:
  - a fake gpg whose "ciphertext" is a shell snippet (`ok_snippet`,
    `LOCKED_SNIPPET`, `NO_SECKEY_SNIPPET`), with `NOPUBKEY` and `HANG`
    recipients
  - a matching fake gpgconf for `status` tests
  - `EnvGuard`, which sets environment variables and restores them on drop
  - `lock_env`

### Internal
- About 120 unit tests, plus `tests/public_api.rs` (the API as an app uses
  it), the README example as a doctest, and an opt-in test against the real
  gpg (`make test-real-gpg`, which fails if the test didn't run).
- CI runs the Makefile's targets:
  - lint (clippy pedantic over every feature set, rustdoc, actionlint,
    shellcheck), and the tests on ubuntu and macos
  - real gpg on both, coverage (97% line minimum), and the MSRV (1.88)
  - minimal dependency versions, a Windows-target build, and cargo-deny
  - a consumer crate that depends on the commit through git
- Releases are `vX.Y.Z` tags with a GitHub release (notes, a source archive,
  its checksum and a provenance attestation), driven by `/release`.
