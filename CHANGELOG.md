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
