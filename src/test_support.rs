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
//! `--homedir H`: when `H/gpgconf.sh` exists it sources that snippet and
//! exits with its status; otherwise it answers `--list-dirs agent-socket`
//! with `H/S.gpg-agent`.
//!
//! [`EnvGuard`] sets environment variables for one test and restores them
//! afterwards, even when the test panics.
//!
//! In a snippet that can outlive its test's timeout, use `exec sleep 10`, not
//! a plain `sleep`: killing the fake must kill the sleep too, or on macOS
//! (where spawn isn't atomic with CLOEXEC) the orphan can hold another
//! test's pipe open for the full 10s.

use std::ffi::{OsStr, OsString};
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
  exit
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

/// Sets environment variables for one test and puts every one back (or
/// removes it again) when dropped, panics included.
///
/// It holds [`lock_env`] for its whole life, so tests that change the
/// environment never overlap with each other or with tests that read it
/// under the same lock.
///
/// ```
/// # use pass_store::test_support::EnvGuard;
/// let mut env = EnvGuard::new();
/// env.set("PASSWORD_STORE_DIR", "/tmp/store").remove("GNUPGHOME");
/// assert_eq!(std::env::var("PASSWORD_STORE_DIR").unwrap(), "/tmp/store");
/// drop(env); // both restored
/// ```
pub struct EnvGuard {
    saved: Vec<(String, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    /// Takes [`lock_env`]; nothing is changed yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            saved: Vec::new(),
            _lock: lock_env(),
        }
    }

    /// Set `name` to `value` until the guard drops.
    pub fn set(&mut self, name: &str, value: impl AsRef<OsStr>) -> &mut Self {
        self.save(name);
        // SAFETY: this guard holds lock_env(), which serializes every test
        // that touches the environment.
        unsafe { std::env::set_var(name, value) };
        self
    }

    /// Unset `name` until the guard drops.
    pub fn remove(&mut self, name: &str) -> &mut Self {
        self.save(name);
        // SAFETY: as in `set`.
        unsafe { std::env::remove_var(name) };
        self
    }

    fn save(&mut self, name: &str) {
        if !self.saved.iter().any(|(n, _)| n == name) {
            self.saved.push((name.to_string(), std::env::var_os(name)));
        }
    }
}

impl Default for EnvGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, value) in self.saved.drain(..).rev() {
            // SAFETY: the lock is still held: fields drop after this runs.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(&name, v),
                    None => std::env::remove_var(&name),
                }
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const VAR: &str = "PASS_STORE_TEST_ENV_GUARD";

    #[test]
    fn env_guard_restores_on_drop() {
        {
            let mut env = EnvGuard::new();
            env.set(VAR, "a").set(VAR, "b");
            assert_eq!(std::env::var(VAR).unwrap(), "b");
        }
        assert_eq!(
            std::env::var_os(VAR),
            None,
            "an unset variable is removed again"
        );

        let lock = lock_env();
        // SAFETY: lock_env() serializes every test that touches the environment.
        unsafe { std::env::set_var(VAR, "before") };
        drop(lock);
        {
            let mut env = EnvGuard::new();
            env.set(VAR, "a").remove(VAR);
            assert_eq!(std::env::var_os(VAR), None);
        }
        let _lock = lock_env();
        assert_eq!(
            std::env::var(VAR).unwrap(),
            "before",
            "the first saved value wins"
        );
        // SAFETY: as above.
        unsafe { std::env::remove_var(VAR) };
    }

    #[test]
    fn env_guard_restores_after_a_panic() {
        let result = std::panic::catch_unwind(|| {
            let mut env = EnvGuard::new();
            env.set(VAR, "panicking");
            panic!("test failure");
        });
        assert!(result.is_err());
        let _lock = lock_env();
        assert_eq!(std::env::var_os(VAR), None);
    }

    #[tokio::test]
    async fn fake_gpgconf_snippet_replaces_the_default_answer() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("gpgconf.sh"), "echo custom\n").unwrap();
        let gpgconf = fake_gpg().with_file_name("gpgconf");
        let out = tokio::process::Command::new(gpgconf)
            .arg("--homedir")
            .arg(home.path())
            .args(["--list-dirs", "agent-socket"])
            .output()
            .await
            .unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "custom\n");
    }
}
