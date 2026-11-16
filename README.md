# pass-store

A [`pass`](https://www.passwordstore.org/)-compatible GPG token store for MCP
servers. It never prompts. It is shared by gitlab-mcp, netbox-mcp and
proxmox-mcp.

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

```toml
[dependencies]
pass-store = { version = "0.1", features = ["http"] }

[dev-dependencies]
pass-store = { version = "0.1", features = ["test-support"] }
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

`StoreLocation` takes the `gpg`, `password_store_dir` and `gnupg_home` from the
app's config. Each one left unset falls back to `$PASSWORD_STORE_DIR` /
`$GNUPGHOME`, then to the defaults (`~/.password-store`, gpg's own
`~/.gnupg`).

### Using it from git

Until the crate is on crates.io, depend on it from GitHub, pinned to a
commit or tag:

```toml
[dependencies]
pass-store = { version = "0.1", git = "https://github.com/3kirt/pass-store", rev = "<commit>", features = ["http"] }

[dev-dependencies]
pass-store = { version = "0.1", git = "https://github.com/3kirt/pass-store", rev = "<commit>", features = ["test-support"] }
```

Keep the `version` next to `git`: without it cargo-deny's
`wildcards = "deny"` rejects the dependency. `Cargo.lock` records the exact
commit, so `--locked` builds stay reproducible; `cargo update -p pass-store`
moves to a new `rev`. In the app's `deny.toml`, allow the git source and the
crate's license:

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

Moving to crates.io later only means dropping `git` and `rev`.

### Cargo features

| Feature        | What it adds |
|----------------|--------------|
| `http`         | `LazyToken`: an HTTP auth header decrypted on first use (one gpg run for concurrent callers). It is re-read when the server rejects it, so the first request after `login` rotates the token can retry once, and it backs off for 30s when that re-read fails. Depends only on `http = "1"`. |
| `test-support` | `test_support::fake_gpg()`, a fake gpg whose "ciphertext" is a shell snippet emitting canned `[GNUPG:]` status lines (`ok_snippet`, `LOCKED_SNIPPET`, `NO_SECKEY_SNIPPET`), plus `lock_env()` for tests that touch the environment. |

## Development

```sh
make check          # fmt-check, lint, test, deny, package (the pre-release gate)
make msrv           # the test suite on rust-version (1.88)
make test-real-gpg  # classification against the real gpg (throwaway keys)
```

See [CLAUDE.md](CLAUDE.md) for the invariants the apps rely on.

## License

GPL-3.0-or-later.
