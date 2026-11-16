# pass-store

A [`pass`](https://www.passwordstore.org/)-compatible GPG token store for MCP
servers. It never prompts. It replaces the copies of this code that
gitlab-mcp, netbox-mcp and proxmox-mcp each carry today.

The token lives in `<store>/<entry>.gpg`, encrypted to the recipients in the
nearest `.gpg-id`, so `pass show` reads it too, though `pass` itself isn't
needed. Reads run `gpg --pinentry-mode error`, so a key whose passphrase
gpg-agent hasn't cached fails at once with an actionable error instead of
hanging on a pinentry nobody can see:

> Proxmox token is locked: gpg-agent has no cached passphrase for the key that
> decrypts /home/me/.password-store/proxmox-mcp/pve.gpg. Ask the user to unlock
> it by running `proxmox-mcp unlock` (or `gpg --decrypt … >/dev/null`) in a
> terminal, then retry.

## Usage

pass-store is distributed from GitHub only, never crates.io. Depend on a
release tag:

```toml
[dependencies]
pass-store = { version = "0.1", git = "https://github.com/3kirt/pass-store", tag = "v0.1.0", features = ["http"] }

[dev-dependencies]
pass-store = { version = "0.1", git = "https://github.com/3kirt/pass-store", tag = "v0.1.0", features = ["test-support"] }
```

```rust,no_run
use pass_store::{Branding, PassStore, StoreLocation};

# async fn demo(config_dir: Option<&std::path::Path>) -> Result<(), pass_store::PassError> {
let branding = Branding::new(
    "Proxmox",
    Branding::cli_prefix("proxmox-mcp", "--config-dir", config_dir),
);
let store = PassStore::resolve(&StoreLocation::default(), branding)?;
let entry = store.entry("proxmox-mcp/pve.example.com")?;
let token = entry.read_token().await?; // never prompts
# Ok(()) }
```

`StoreLocation`'s `gpg`, `store_dir` and `gnupg_home` take the app's own
config values (the apps call them `gpg`, `password_store_dir` and
`gnupg_home`). Each one left unset falls back to `$PASSWORD_STORE_DIR` /
`$GNUPGHOME`, then to the defaults (`~/.password-store`, gpg's own
`~/.gnupg`). A leading `~/` is expanded in all of them.

### Pinning, deny.toml and local builds

Keep the `version` next to `git`: without it cargo-deny's
`wildcards = "deny"` rejects the dependency. Before the first release, or to
try unreleased work, use `rev = "<commit>"` in place of `tag`. `Cargo.lock`
records the exact commit, so `--locked` builds stay reproducible; after
changing the `tag` or `rev`, run `cargo update -p pass-store`. In the app's
`deny.toml`, allow the git source and the crate's license:

```toml
[sources]
allow-git = ["https://github.com/3kirt/pass-store"]

[licenses]
allow = [
    # ...
    "GPL-3.0-or-later",
]
```

To build against a local checkout without editing Cargo.toml, add an
uncommitted `.cargo/config.toml` to the app:

```toml
[patch."https://github.com/3kirt/pass-store"]
pass-store = { path = "../pass-store" }
```

### Cargo features

| Feature        | What it adds |
|----------------|--------------|
| `http`         | `LazyToken`: an HTTP auth header decrypted on first use (one gpg run for concurrent callers). It is re-read when the server rejects it, so the first request after `login` rotates the token can retry once, and it backs off for 30s when that re-read fails. Depends only on `http = "1"`. |
| `test-support` | `test_support::fake_gpg()`, a fake gpg whose "ciphertext" is a shell snippet emitting canned `[GNUPG:]` status lines (`ok_snippet`, `LOCKED_SNIPPET`, `NO_SECKEY_SNIPPET`), with a matching fake gpgconf for `status` tests, plus `EnvGuard` (and `lock_env()`) for tests that touch the environment. Make `lock_env()` the app's only environment lock (see below). |

### Testing an app that uses it

pass-store reads `HOME`, `PASSWORD_STORE_DIR` and `GNUPGHOME`, so an app's
tests that change the environment must exclude pass-store's reads too. A
separate lock in the app doesn't: make `pass_store::test_support::lock_env()`
the app's one environment lock (e.g. `pub use
pass_store::test_support::lock_env;` where your tests expect it), or set
variables through `EnvGuard`, which holds it. Hold it in any test that
reaches config loading or `PassStore::resolve()`, even one that only reads.
The guard can't be held across an `.await`: in an async test that needs it,
use a sync `#[test]` that takes the lock and `block_on`s its own runtime.

## Development

```sh
make check            # fmt-check, lint, test, deny, consumer-smoke (the pre-release gate)
make msrv             # the test suite on rust-version (1.88)
make test-real-gpg    # classification against the real gpg (throwaway keys)
make coverage         # line coverage, real gpg included (needs cargo-llvm-cov)
make minimal-versions # the suite with Cargo.toml's lowest allowed dependencies
make check-windows    # the non-Unix code paths compile and lint clean
```

See [CLAUDE.md](CLAUDE.md) for the invariants the apps rely on.

## License

GPL-3.0-or-later.
