//! Classification against the *real* `gpg`, not the fake one: catches drift
//! in GnuPG's status codes (the `DECRYPTION_OKAY` marker, code 85 for a
//! locked key, 17 for a missing secret key), which every other test only
//! replays from a capture. Opt-in (`make test-real-gpg`, i.e. `REAL_GPG=1
//! cargo test -- --ignored real_gpg`) because it generates keys and starts a
//! gpg-agent; it never touches the user's keyring.
//!
//! The GnuPG home is a fresh temp dir with a short name: gpg-agent's socket
//! lives inside it, and macOS limits socket paths to 104 bytes.

//! Unix-only, like the agent client it also exercises.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::test_support::branding;
use crate::{PassError, PassStore, agent};

const TOKEN: &str = "real-gpg-test-token";
const PASSPHRASE: &str = "real-gpg-test-passphrase";

fn gpg_bin() -> PathBuf {
    std::env::var_os("GPG").map_or_else(|| PathBuf::from("gpg"), PathBuf::from)
}

fn run(cmd: &mut Command) {
    let out = cmd.output().expect("run gpg (is GnuPG installed?)");
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A short-path GnuPG home; its agent is killed on drop.
struct Home(tempfile::TempDir);

impl Home {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("psg")
            .tempdir()
            .expect("temp GnuPG home");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        self.0.path()
    }

    fn gpg(&self) -> Command {
        let mut cmd = Command::new(gpg_bin());
        cmd.arg("--homedir")
            .arg(self.path())
            .args(["--batch", "--no-tty"]);
        cmd
    }

    /// `uid` with an encryption subkey, protected by `passphrase` ("" = none).
    fn gen_key(&self, uid: &str, passphrase: &str) {
        run(self.gpg().args([
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            passphrase,
            "--quick-gen-key",
            uid,
            "default",
            "default",
            "never",
        ]));
    }

    fn gpgconf(&self, arg: &str) {
        let gpgconf = PassStore::new("/", gpg_bin(), branding()).gpgconf();
        let _ = Command::new(gpgconf)
            .arg("--homedir")
            .arg(self.path())
            .arg(arg)
            .arg("gpg-agent")
            .status();
    }

    fn store(&self, root: &Path) -> PassStore {
        PassStore::new(root, gpg_bin(), branding()).with_homedir(Some(self.path().into()))
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        self.gpgconf("--kill");
    }
}

/// An entry encrypted to a key whose secret half lives only in another
/// keyring (its public half is imported into `home`).
fn foreign_entry(home: &Home, store: &PassStore) -> crate::PassEntry {
    let foreign = Home::new();
    foreign.gen_key("Foreign <foreign@example.invalid>", "");
    let public = foreign
        .gpg()
        .args(["--armor", "--export", "foreign@example.invalid"])
        .output()
        .unwrap()
        .stdout;
    pipe(
        home.gpg()
            .arg("--import")
            .stderr(std::process::Stdio::null()),
        &public,
    );
    // The imported key isn't trusted, so encrypt to it directly.
    let entry = store.entry("foreign").unwrap();
    pipe(
        home.gpg()
            .args(["--trust-model", "always", "--encrypt", "--recipient"])
            .arg("foreign@example.invalid")
            .arg("--output")
            .arg(entry.path()),
        format!("{TOKEN}\n").as_bytes(),
    );
    entry
}

/// Run `cmd` with `input` on its stdin; it must succeed.
fn pipe(cmd: &mut Command, input: &[u8]) {
    let mut child = cmd.stdin(std::process::Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), input).unwrap();
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success(), "{cmd:?} failed");
}

#[tokio::test]
#[ignore = "needs a real gpg; run with `make test-real-gpg`"]
async fn real_gpg_status_codes_classify_as_expected() {
    if std::env::var_os("REAL_GPG").is_none_or(|v| v != "1") {
        eprintln!("REAL_GPG=1 not set; skipping");
        return;
    }
    let home = Home::new();
    home.gen_key("Open <open@example.invalid>", "");
    home.gen_key("Locked <locked@example.invalid>", PASSPHRASE);

    let store_dir = tempfile::tempdir().unwrap();
    let store = home.store(store_dir.path());

    let open = store.entry("open").unwrap();
    open.write_token(TOKEN, &["open@example.invalid".into()])
        .await
        .unwrap();
    let locked = store.entry("app/locked").unwrap();
    locked
        .write_token(TOKEN, &["locked@example.invalid".into()])
        .await
        .unwrap();
    let mode = std::fs::metadata(locked.path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "real gpg's output mode: {mode:o}");
    let foreign_entry = foreign_entry(&home, &store);

    // Generating with a loopback passphrase may have cached it: forget it.
    home.gpgconf("--reload");

    assert_eq!(
        open.read_token().await.unwrap(),
        TOKEN,
        "DECRYPTION_OKAY path"
    );
    let err = locked.read_token().await.unwrap_err();
    assert!(
        matches!(err, PassError::Locked { .. }),
        "expected Locked (code 85), got {err}"
    );
    let err = foreign_entry.read_token().await.unwrap_err();
    assert!(
        matches!(err, PassError::NoSecretKey { .. }),
        "expected NoSecretKey (code 17), got {err}"
    );

    // What a `status` command reports for each, from the agent itself.
    let state = |who: &'static str| {
        let store = store.clone();
        async move { agent::state(&store, &[who.to_string()]).await.unwrap() }
    };
    assert_eq!(
        state("open@example.invalid").await,
        agent::AgentState::Unprotected
    );
    assert_eq!(
        state("locked@example.invalid").await,
        agent::AgentState::Locked
    );
    assert_eq!(
        state("foreign@example.invalid").await,
        agent::AgentState::NoSecretKey
    );

    // Prime the agent cache the way `unlock` would (loopback instead of a
    // pinentry); then the same non-interactive read succeeds. gpg writes
    // `<output>.part` first, so the output can't be /dev/null.
    let plaintext = home.path().join("plaintext");
    run(home
        .gpg()
        .args(["--quiet", "--pinentry-mode", "loopback", "--passphrase"])
        .arg(PASSPHRASE)
        .arg("--output")
        .arg(&plaintext)
        .arg("--decrypt")
        .arg(locked.path()));
    assert_eq!(locked.read_token().await.unwrap(), TOKEN);
    assert_eq!(
        state("locked@example.invalid").await,
        agent::AgentState::Unlocked
    );
}
