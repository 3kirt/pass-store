//! GPG-encrypted token storage in a `pass`-compatible password store, shared
//! by gitlab-mcp, netbox-mcp and proxmox-mcp.
//!
//! The token lives in `<store>/<entry>.gpg`, encrypted to the recipients
//! listed in the nearest `.gpg-id` (the same layout `pass` uses, so `pass
//! show` reads it too, but `pass` itself is not required). Decryption goes
//! through the `gpg` binary with `--pinentry-mode error`, so a passphrase
//! that gpg-agent hasn't cached fails immediately instead of prompting: an
//! MCP server has no TTY, and a pinentry nobody is watching would hang the
//! request. Failures are classified from gpg's machine-readable
//! `--status-fd` output (numeric gpg-error codes), not its localized human
//! messages, so a locked key becomes a [`PassError::Locked`] the MCP client
//! can act on ("ask the user to unlock, then retry").
//!
//! The app names itself once, with a [`Branding`], so every message gives
//! advice for that app (`proxmox-mcp --config-dir '/x' unlock`).
//!
//! Cargo features:
//! - `http`: [`LazyToken`], a pass-backed HTTP auth header that is decrypted
//!   on first use and re-read when the server rejects it.
//! - `test-support`: [`test_support`], the shared fake `gpg` for the apps'
//!   own tests.

#[cfg(unix)]
pub mod agent;
pub mod env;
#[cfg(all(test, unix))]
mod real_gpg;
mod store;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(feature = "http")]
mod token;

// Compiles the README's Rust example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub use env::{env_var, home_dir, is_unexpanded_placeholder, non_blank};
pub use store::{
    Branding, GPG_TIMEOUT, PassEntry, PassError, PassStore, StoreLocation, create_private_dir,
    create_private_file, shell_quote,
};
#[cfg(feature = "http")]
pub use token::{LazyToken, REREAD_BACKOFF, TokenError};

/// One line for a `status` command: can gpg-agent decrypt for `recipients`
/// without a prompt? (See [`agent::state`].)
///
/// Never fails: an error becomes "unknown (…)", and on non-Unix platforms,
/// where the agent query isn't supported, it says so.
// Async on every platform, so callers don't need their own `cfg`.
#[cfg_attr(not(unix), allow(clippy::unused_async))]
pub async fn agent_status(store: &PassStore, recipients: &[String]) -> String {
    #[cfg(unix)]
    {
        agent::state(store, recipients)
            .await
            .map_or_else(|e| format!("unknown ({e})"), |s| s.describe(store.cli()))
    }
    #[cfg(not(unix))]
    {
        let _ = (store, recipients);
        "unknown (gpg-agent query is only supported on Unix)".into()
    }
}
