//! A fake `gpg` and `gpgconf` for tests (cargo feature `test-support`).
//!
//! Each is one shared script, written once, so no test ever executes a file
//! another thread is still writing (the ETXTBSY race).
//!
//! [`fake_gpg`]:
//! - Encrypt mode (`--encrypt`) copies stdin to `--output` and records its
//!   arguments next to it in `<output>.args`. A recipient named `NOPUBKEY`
//!   makes it exit like a real gpg with no public key: an error, without
//!   reading stdin. A recipient named `HANG` makes it hang (for timeouts).
//! - Every other invocation (`--decrypt`, `--list-secret-keys`, …) *sources*
//!   its last argument. For a decrypt that's the entry file, so each test's
//!   "ciphertext" is a shell snippet producing the canned stdout,
//!   `[GNUPG:]` status lines and exit code it wants (see [`ok_snippet`],
//!   [`LOCKED_SNIPPET`]). For a key listing it's the last recipient, so
//!   pass a snippet's path as the recipient. A snippet can read the
//!   space-joined argv from `$all`.
//!
//! The matching `gpgconf` sits next to it, so a store using the fake gpg
//! runs it (see [`crate::PassStore::gpgconf`]). It needs the store's
//! `--homedir H`: it sources `H/gpgconf.sh` when that exists, and otherwise
//! answers `--list-dirs agent-socket` with `H/S.gpg-agent`.
//!
//! In a snippet that can outlive its test's timeout, use `exec sleep 10`, not
//! a plain `sleep`: killing the fake must kill the sleep too, or on macOS
//! (where spawn isn't atomic with CLOEXEC) the orphan can hold another
//! test's pipe open for the full 10s.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

const FAKE_GPG: &str = r#"#!/bin/sh
mode=decrypt
out=
last=
all=
while [ $# -gt 0 ]; do
  case "$1" in
    --encrypt) mode=encrypt ;;
    --output) shift; out="$1" ;;
  esac
  all="$all $1"
  last="$1"
  shift
done
if [ "$mode" = encrypt ]; then
  case "$all" in
    *" NOPUBKEY"*)
      # Like a real gpg with no public key: exit without reading stdin.
      echo "gpg: NOPUBKEY: skipped: No public key" >&2
      exit 2 ;;
    *" HANG"*)
      exec sleep 10 ;;
  esac
  cat > "$out"
  echo "$all" > "$out.args"
  exit 0
fi
. "$last"
"#;

const FAKE_GPGCONF: &str = r#"#!/bin/sh
home=
all=
while [ $# -gt 0 ]; do
  case "$1" in
    --homedir) shift; home="$1" ;;
  esac
  all="$all $1"
  shift
done
if [ -z "$home" ]; then
  echo "fake gpgconf: needs --homedir" >&2
  exit 1
fi
if [ -f "$home/gpgconf.sh" ]; then
  . "$home/gpgconf.sh"
fi
case "$all" in
  *" --list-dirs agent-socket"*) echo "$home/S.gpg-agent" ;;
esac
exit 0
"#;

/// The fake gpg's path. Pass it as the store's gpg program.
///
/// # Panics
///
/// When the script can't be written to a temp dir.
pub fn fake_gpg() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        // gpgconf first: by the time anyone has the gpg path, both exist.
        write_script(&dir.join("gpgconf"), FAKE_GPGCONF);
        let path = dir.join("gpg");
        write_script(&path, FAKE_GPG);
        path
    })
}

fn write_script(path: &Path, body: &str) {
    std::fs::write(path, body).expect("write fake script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake script");
    }
}

/// A decrypt that prints `plaintext` (quoted, so any text is safe) with the
/// status lines a real GnuPG 2.4 emits on success.
#[must_use]
pub fn ok_snippet(plaintext: &str) -> String {
    format!(
        "printf '%s\\n' {}\n\
         echo '[GNUPG:] BEGIN_DECRYPTION' >&2\n\
         echo '[GNUPG:] DECRYPTION_OKAY' >&2\n\
         exit 0\n",
        crate::shell_quote(plaintext)
    )
}

/// What GnuPG 2.4 emits for a key whose passphrase isn't cached under
/// `--pinentry-mode error` (captured from a real run).
pub const LOCKED_SNIPPET: &str = "\
echo '[GNUPG:] ENC_TO D8936DA9BE6E9ED2 18 0' >&2
echo '[GNUPG:] NO_SECKEY D8936DA9BE6E9ED2' >&2
echo 'gpg: public key decryption failed: No pinentry' >&2
echo '[GNUPG:] ERROR pkdecrypt_failed 67108949' >&2
echo '[GNUPG:] DECRYPTION_FAILED' >&2
echo '[GNUPG:] FAILURE gpg-exit 33554433' >&2
exit 2
";

/// What GnuPG 2.4 emits when no key in the keyring can decrypt the entry.
pub const NO_SECKEY_SNIPPET: &str = "\
echo '[GNUPG:] ENC_TO D8936DA9BE6E9ED2 18 0' >&2
echo '[GNUPG:] NO_SECKEY D8936DA9BE6E9ED2' >&2
echo '[GNUPG:] ERROR pkdecrypt_failed 33554449' >&2
echo 'gpg: decryption failed: No secret key' >&2
echo '[GNUPG:] DECRYPTION_FAILED' >&2
exit 2
";

/// Serializes tests that read or write the process environment.
///
/// Cargo runs tests on several threads of one process, so hold this for the
/// whole test body around any `set_var` (`HOME`, `PASSWORD_STORE_DIR`,
/// `GNUPGHOME`, …), and around anything that resolves a store from the
/// environment.
pub fn lock_env() -> MutexGuard<'static, ()> {
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The branding the crate's own tests use.
#[cfg(test)]
pub(crate) fn branding() -> crate::Branding {
    crate::Branding::new("Test", "test-mcp")
}

/// A store at `root` driven by the fake gpg.
#[cfg(test)]
pub(crate) fn store(root: &Path) -> crate::PassStore {
    crate::PassStore::new(root, fake_gpg(), branding())
}
