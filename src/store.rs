//! The store itself: entries, decryption, encryption and recipients.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::env::{env_var, expand_tilde_in, home_dir};

/// How long a non-interactive decrypt (or an encrypt) may take. With
/// `--pinentry-mode error` gpg never waits on a human, so this only bounds a
/// wedged gpg/agent.
pub const GPG_TIMEOUT: Duration = Duration::from_secs(10);

/// gpg-error codes (the low 16 bits of the `ERROR` status line's code; the
/// high bits are the error *source*, e.g. 4 = gpg-agent). Verified against
/// GnuPG 2.4: a locked key reports `ERROR pkdecrypt_failed 67108949`, i.e.
/// source 4, code 85.
const GPG_ERR_NO_SECKEY: u32 = 17;
const GPG_ERR_NO_PIN_ENTRY: u32 = 85;
const GPG_ERR_CANCELED: u32 = 99;

/// Most stderr text forwarded in an unclassified gpg failure.
const MAX_GPG_MESSAGE: usize = 300;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PassError {
    /// `cli` is the command prefix that reaches the app's own config (see
    /// [`Branding`]), so the advice works for a non-default config.
    #[error(
        "no {product} token stored at pass entry '{entry}' ({} does not exist); \
         run `{cli} login` to store one",
        path.display()
    )]
    NotFound {
        product: String,
        entry: String,
        path: PathBuf,
        cli: String,
    },
    /// `cli` and `gpg_decrypt` are paste-ready, shell-quoted commands for the
    /// app's config and this store's keyring (`--homedir`).
    #[error(
        "{product} token is locked: gpg-agent has no cached passphrase for the key that \
         decrypts {}. Ask the user to unlock it by running `{cli} unlock` (or \
         `{gpg_decrypt} >/dev/null`) in a terminal, then retry.",
        path.display()
    )]
    Locked {
        product: String,
        path: PathBuf,
        cli: String,
        gpg_decrypt: String,
    },
    #[error("no secret key in this GnuPG keyring can decrypt {}", path.display())]
    NoSecretKey { path: PathBuf },
    /// `operation` is what gpg was doing: "decrypting" or "encrypting".
    #[error(
        "gpg did not finish {operation} {} within {}s",
        path.display(),
        timeout.as_secs()
    )]
    Timeout {
        operation: &'static str,
        path: PathBuf,
        timeout: Duration,
    },
    #[error("{0}")]
    Other(String),
}

/// How the app names itself in user-facing advice. Passed in once, when the
/// store is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branding {
    product: String,
    cli: String,
}

impl Branding {
    /// `product` names the token ("Proxmox" → "Proxmox token is locked");
    /// `cli` is a ready, shell-quoted command prefix that reaches the app's
    /// config, e.g. `proxmox-mcp --config-dir '/x'` (see [`Self::cli_prefix`]).
    pub fn new(product: impl Into<String>, cli: impl Into<String>) -> Self {
        Self {
            product: product.into(),
            cli: cli.into(),
        }
    }

    /// `program`, plus `flag <value>` (shell-quoted) when the app was started
    /// with a non-default config, e.g. `cli_prefix("netbox-mcp", "--config",
    /// Some(path))`.
    #[must_use]
    pub fn cli_prefix(program: &str, flag: &str, value: Option<&Path>) -> String {
        value.map_or_else(
            || program.to_string(),
            |v| format!("{program} {flag} {}", shell_quote(&v.to_string_lossy())),
        )
    }

    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    #[must_use]
    pub fn cli(&self) -> &str {
        &self.cli
    }
}

/// A `pass`-compatible password store: a directory of `.gpg` files plus
/// `.gpg-id` recipient lists, driven through the `gpg` binary.
#[derive(Debug, Clone)]
pub struct PassStore {
    root: PathBuf,
    gpg: PathBuf,
    /// GnuPG home passed as `--homedir` to gpg/gpgconf; `None` leaves gpg's
    /// own lookup (`$GNUPGHOME`, else `~/.gnupg`).
    homedir: Option<PathBuf>,
    branding: Branding,
    timeout: Duration,
}

/// Where the store and keyring live, as configured.
///
/// Each `None` falls back to the environment ([`StoreEnv`]), then the default. The
/// config values exist because MCP clients launched from a GUI (e.g. from
/// the macOS Dock) don't inherit shell-only `PASSWORD_STORE_DIR` /
/// `GNUPGHOME` exports; `login` records what it used so the server reads the
/// same store and keyring.
#[derive(Debug, Default, Clone)]
pub struct StoreLocation<'a> {
    /// gpg binary (default: `gpg` from `PATH`, which a minimal client
    /// `PATH` may lack, e.g. `/opt/homebrew/bin`).
    pub gpg: Option<&'a str>,
    /// Store root (else `$PASSWORD_STORE_DIR`, else `~/.password-store`,
    /// the same lookup `pass` does).
    pub store_dir: Option<&'a str>,
    /// GnuPG home (else `$GNUPGHOME`, else gpg's default `~/.gnupg`).
    pub gnupg_home: Option<&'a str>,
}

/// The environment values [`PassStore::resolve`] falls back to, passed in
/// rather than read from the process, so resolving never races with a test
/// that changes the environment.
///
/// Production code takes a snapshot with [`StoreEnv::from_process`]; tests
/// build one directly:
///
/// ```
/// # use pass_store::StoreEnv;
/// let env = StoreEnv {
///     home: Some("/home/me".into()),
///     ..StoreEnv::default()
/// };
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StoreEnv {
    /// The home directory, for `~/` and the default `~/.password-store`.
    pub home: Option<PathBuf>,
    /// `$PASSWORD_STORE_DIR`.
    pub password_store_dir: Option<String>,
    /// `$GNUPGHOME`.
    pub gnupg_home: Option<String>,
}

impl StoreEnv {
    /// A snapshot of this process's `HOME` (else `USERPROFILE`),
    /// `PASSWORD_STORE_DIR` and `GNUPGHOME`, with blank values and
    /// unexpanded `${…}` placeholders counting as unset (see
    /// [`crate::env_var`]).
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            home: home_dir().ok(),
            password_store_dir: env_var("PASSWORD_STORE_DIR"),
            gnupg_home: env_var("GNUPGHOME"),
        }
    }
}

impl PassStore {
    /// The store at `loc`, falling back to `env` (in production
    /// [`StoreEnv::from_process`]). `~/` is expanded against `env.home`, in
    /// configured values and in `$PASSWORD_STORE_DIR` / `$GNUPGHOME` (which a
    /// GUI client's config may hold unexpanded). The root and homedir are
    /// made absolute, so the paths `login` records mean the same thing to a
    /// server started from another working directory. This reads nothing
    /// from the process environment.
    ///
    /// # Errors
    ///
    /// When the home directory is needed but `env.home` is `None`, or a path
    /// can't be made absolute.
    pub fn resolve(
        loc: &StoreLocation<'_>,
        env: &StoreEnv,
        branding: Branding,
    ) -> Result<Self, PassError> {
        let path_err = |e: std::io::Error| PassError::Other(format!("resolving the store: {e}"));
        let home = env.home.as_deref();
        let expand = |v: &str| expand_tilde_in(v, home).map_err(path_err);
        let configured = |value: Option<&str>, fallback: Option<&str>| {
            value.or(fallback).map(expand).transpose()
        };
        let root = match configured(loc.store_dir, env.password_store_dir.as_deref())? {
            Some(dir) => dir,
            None => expand("~/.password-store")?,
        };
        let homedir = configured(loc.gnupg_home, env.gnupg_home.as_deref())?;
        let root = std::path::absolute(&root).map_err(path_err)?;
        let homedir = homedir
            .map(std::path::absolute)
            .transpose()
            .map_err(path_err)?;
        let gpg = loc.gpg.map_or_else(|| Ok(PathBuf::from("gpg")), expand)?;
        Ok(Self::new(root, gpg, branding).with_homedir(homedir))
    }

    /// A store at `root` driven by `gpg`, taken as given (see
    /// [`Self::resolve`] for the configured/environment lookup).
    pub fn new(root: impl Into<PathBuf>, gpg: impl Into<PathBuf>, branding: Branding) -> Self {
        Self {
            root: root.into(),
            gpg: gpg.into(),
            homedir: None,
            branding,
            timeout: GPG_TIMEOUT,
        }
    }

    #[must_use]
    pub fn with_homedir(mut self, homedir: Option<PathBuf>) -> Self {
        self.homedir = homedir;
        self
    }

    /// Bound each gpg run by `timeout` instead of [`GPG_TIMEOUT`].
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub const fn branding(&self) -> &Branding {
        &self.branding
    }

    /// The app's command prefix for user-facing advice (see [`Branding`]).
    #[must_use]
    pub fn cli(&self) -> &str {
        self.branding.cli()
    }

    /// The GnuPG home this store pins gpg to, if any.
    #[must_use]
    pub fn homedir(&self) -> Option<&Path> {
        self.homedir.as_deref()
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The gpg program this store runs (as configured; may be a bare name
    /// looked up on `PATH`).
    #[must_use]
    pub fn gpg(&self) -> &Path {
        &self.gpg
    }

    /// A `gpg` command with `--homedir` applied.
    #[must_use]
    pub fn gpg_command(&self) -> Command {
        self.command_with_homedir(&self.gpg)
    }

    /// A `gpgconf` command with `--homedir` applied (so the agent socket it
    /// reports belongs to the same keyring).
    #[must_use]
    pub fn gpgconf_command(&self) -> Command {
        self.command_with_homedir(&self.gpgconf())
    }

    fn command_with_homedir(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        if let Some(home) = &self.homedir {
            cmd.arg("--homedir").arg(home);
        }
        cmd
    }

    /// `gpgconf` from the same directory as an explicitly located `gpg`
    /// (so a `gpg` override covers both), else `gpgconf` from `PATH`.
    #[must_use]
    pub fn gpgconf(&self) -> PathBuf {
        match self.gpg.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join("gpgconf"),
            _ => PathBuf::from("gpgconf"),
        }
    }

    /// A paste-ready `gpg [--homedir H] --decrypt <path>` for `path`.
    #[must_use]
    pub fn gpg_decrypt_command(&self, path: &Path) -> String {
        let mut cmd = shell_quote(&self.gpg.to_string_lossy());
        if let Some(home) = &self.homedir {
            cmd.push_str(" --homedir ");
            cmd.push_str(&shell_quote(&home.to_string_lossy()));
        }
        cmd.push_str(" --decrypt ");
        cmd.push_str(&shell_quote(&path.to_string_lossy()));
        cmd
    }

    /// The entry named `name` (e.g. `proxmox-mcp/pve.example.com`).
    ///
    /// # Errors
    ///
    /// When `name` is empty, contains NUL or a backslash, is absolute, or has
    /// an empty, `.` or `..` segment.
    pub fn entry(&self, name: &str) -> Result<PassEntry, PassError> {
        validate_entry_name(name)?;
        Ok(PassEntry {
            store: self.clone(),
            name: name.to_string(),
        })
    }

    /// Initialise an empty store for `gpg_id` (writes `<root>/.gpg-id`, like
    /// `pass init`).
    ///
    /// # Errors
    ///
    /// When the key ID is blank or multi-line, a root `.gpg-id` already
    /// exists (it is never overwritten), or the file can't be written.
    pub fn init(&self, gpg_id: &str) -> Result<(), PassError> {
        let gpg_id = gpg_id.trim();
        if gpg_id.is_empty() || gpg_id.contains('\n') {
            return Err(PassError::Other(format!("invalid GPG key ID {gpg_id:?}")));
        }
        create_private_dir(&self.root)?;
        let id_file = self.root.join(".gpg-id");
        let mut file = create_private_file(&id_file)?;
        std::io::Write::write_all(&mut file, format!("{gpg_id}\n").as_bytes())
            .map_err(|e| io_err("writing", &id_file, &e))
    }

    fn not_found(&self, entry: &str, path: PathBuf) -> PassError {
        PassError::NotFound {
            product: self.branding.product.clone(),
            entry: entry.to_string(),
            path,
            cli: self.branding.cli.clone(),
        }
    }

    fn locked(&self, path: PathBuf) -> PassError {
        PassError::Locked {
            product: self.branding.product.clone(),
            gpg_decrypt: self.gpg_decrypt_command(&path),
            cli: self.branding.cli.clone(),
            path,
        }
    }

    const fn timeout(&self, operation: &'static str, path: PathBuf) -> PassError {
        PassError::Timeout {
            operation,
            path,
            timeout: self.timeout,
        }
    }
}

/// One token entry in a [`PassStore`].
#[derive(Debug, Clone)]
pub struct PassEntry {
    store: PassStore,
    name: String,
}

impl PassEntry {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn store(&self) -> &PassStore {
        &self.store
    }

    /// `<store>/<name>.gpg`.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.store.root.join(format!("{}.gpg", self.name))
    }

    /// Decrypt the entry without ever prompting, returning its first line,
    /// trimmed (the `pass` convention: line one is the secret, the rest is
    /// metadata).
    ///
    /// # Errors
    ///
    /// [`PassError::NotFound`] when the entry doesn't exist,
    /// [`PassError::Locked`] when gpg-agent has no cached passphrase,
    /// [`PassError::NoSecretKey`] when no key in the keyring can decrypt it,
    /// [`PassError::Timeout`] when gpg hangs, and [`PassError::Other`] for
    /// anything else, including an empty first line.
    pub async fn read_token(&self) -> Result<String, PassError> {
        let path = self.existing_path().await?;

        let child = self
            .store
            .gpg_command()
            .args([
                "--batch",
                "--quiet",
                "--no-tty",
                "--pinentry-mode",
                "error",
                "--status-fd",
                "2",
                "--decrypt",
                "--",
            ])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // A timed-out (dropped) wait kills gpg instead of leaking it.
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| spawn_err(&self.store.gpg, &e))?;
        let output = tokio::time::timeout(self.store.timeout, child.wait_with_output())
            .await
            .map_err(|_| self.store.timeout("decrypting", path.clone()))?
            .map_err(|e| io_err("waiting for gpg on", &path, &e))?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        match classify_decrypt(output.status.success(), &stderr) {
            DecryptOutcome::Ok => {}
            DecryptOutcome::Locked => return Err(self.store.locked(path)),
            DecryptOutcome::NoSecretKey => return Err(PassError::NoSecretKey { path }),
            DecryptOutcome::Failed => {
                return Err(PassError::Other(format!(
                    "gpg failed to decrypt {}: {}",
                    path.display(),
                    human_message(&stderr)
                )));
            }
        }

        let plaintext = String::from_utf8(output.stdout).map_err(|_| {
            PassError::Other(format!("{} does not decrypt to UTF-8 text", path.display()))
        })?;
        let token = plaintext.lines().next().unwrap_or("").trim();
        if token.is_empty() {
            return Err(PassError::Other(format!(
                "{} decrypts to an empty first line; run `{} login` to store a token",
                path.display(),
                self.store.cli()
            )));
        }
        Ok(token.to_string())
    }

    /// The entry's path, or [`PassError::NotFound`] when there is no file.
    async fn existing_path(&self) -> Result<PathBuf, PassError> {
        let path = self.path();
        if tokio::fs::try_exists(&path)
            .await
            .map_err(|e| io_err("checking", &path, &e))?
        {
            Ok(path)
        } else {
            Err(self.store.not_found(&self.name, path))
        }
    }

    /// Recipients from the nearest `.gpg-id`, walking up from the entry's
    /// directory to the store root (as `pass` does). `None` when the store
    /// has no `.gpg-id` anywhere on that path.
    ///
    /// # Errors
    ///
    /// When the nearest `.gpg-id` can't be read or lists no key IDs.
    pub fn recipients(&self) -> Result<Option<Vec<String>>, PassError> {
        let entry_path = self.path();
        let mut dir = entry_path.parent();
        while let Some(d) = dir {
            let id_file = d.join(".gpg-id");
            if id_file.is_file() {
                let contents = std::fs::read_to_string(&id_file)
                    .map_err(|e| io_err("reading", &id_file, &e))?;
                // Like pass 1.7.3+: everything from `#` on is a comment, so
                // `KEYID # work key` names KEYID.
                let ids: Vec<String> = contents
                    .lines()
                    .map(|l| l.split('#').next().unwrap_or("").trim())
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect();
                if ids.is_empty() {
                    return Err(PassError::Other(format!(
                        "{} lists no GPG key IDs",
                        id_file.display()
                    )));
                }
                return Ok(Some(ids));
            }
            if d == self.store.root {
                break;
            }
            dir = d.parent();
        }
        Ok(None)
    }

    /// Encrypt `token` to `recipients` and atomically (temp file + rename)
    /// replace the entry. Encryption needs only public keys, so no pinentry.
    ///
    /// The temp file is `.<entry>.gpg.tmp<pid>`, so two writes of the same
    /// entry from one process at once fail the second with "creating …";
    /// separate processes (e.g. two `login` runs) don't collide.
    ///
    /// # Errors
    ///
    /// When `recipients` is empty, a directory or the temp file can't be
    /// created (including when something is already at the temp path), gpg
    /// fails (its own message, e.g. "No public key", is forwarded) or times
    /// out, or the rename fails.
    pub async fn write_token(&self, token: &str, recipients: &[String]) -> Result<(), PassError> {
        let path = self.path();
        if recipients.is_empty() {
            return Err(PassError::Other(format!(
                "no GPG recipients to encrypt {} to",
                path.display()
            )));
        }
        let dir = path
            .parent()
            .ok_or_else(|| PassError::Other(format!("{} has no parent", path.display())))?;
        create_private_dir(dir)?;
        let file_name = path
            .file_name()
            .map_or_else(|| "entry".into(), |n| n.to_string_lossy().into_owned());
        let tmp = dir.join(format!(".{file_name}.tmp{}", std::process::id()));
        // Claim the predictable temp path exclusively (owner-only) before gpg
        // writes to it, so a planted file or symlink there fails the write
        // instead of being followed by gpg's `--yes --output`. On that
        // failure nothing is deleted: whatever is there isn't ours.
        drop(create_private_file(&tmp)?);

        let outcome = self
            .encrypt_to(&tmp, &path, token, recipients)
            .await
            .and_then(|()| {
                restrict(&tmp)?;
                std::fs::rename(&tmp, &path).map_err(|e| io_err("replacing", &path, &e))
            });
        if outcome.is_err() {
            // Ours (created above), so safe to remove.
            let _ = std::fs::remove_file(&tmp);
        }
        outcome
    }

    /// Run `gpg --encrypt` for `recipients` into `out` (the temp file for
    /// `entry`, which errors name), the stdin write and the wait both under
    /// the timeout. A gpg that exits early (e.g. no public key for a
    /// recipient) closes its stdin; that broken pipe is ignored so the caller
    /// sees gpg's own error from stderr instead.
    async fn encrypt_to(
        &self,
        out: &Path,
        entry: &Path,
        token: &str,
        recipients: &[String],
    ) -> Result<(), PassError> {
        let mut cmd = self.store.gpg_command();
        cmd.args(["--batch", "--quiet", "--yes", "--no-tty", "--encrypt"]);
        for r in recipients {
            cmd.arg("--recipient").arg(r);
        }
        cmd.arg("--output")
            .arg(out)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // A timed-out (dropped) exchange kills gpg instead of leaking it.
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| spawn_err(&self.store.gpg, &e))?;
        let stdin = child.stdin.take();
        let exchange = async move {
            if let Some(mut stdin) = stdin {
                match stdin.write_all(format!("{token}\n").as_bytes()).await {
                    Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
                        return Err(io_err("writing to gpg for", entry, &e));
                    }
                    _ => {}
                }
                // Close stdin so gpg sees EOF.
                drop(stdin);
            }
            child
                .wait_with_output()
                .await
                .map_err(|e| io_err("waiting for gpg on", entry, &e))
        };
        let output = tokio::time::timeout(self.store.timeout, exchange)
            .await
            .map_err(|_| self.store.timeout("encrypting", entry.to_path_buf()))??;
        if output.status.success() {
            Ok(())
        } else {
            Err(PassError::Other(format!(
                "gpg failed to encrypt to {}: {}",
                recipients.join(", "),
                human_message(&String::from_utf8_lossy(&output.stderr))
            )))
        }
    }

    /// Delete the entry's `.gpg` file.
    ///
    /// # Errors
    ///
    /// [`PassError::NotFound`] when there is no such entry; otherwise the
    /// I/O error.
    pub fn remove(&self) -> Result<(), PassError> {
        let path = self.path();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(self.store.not_found(&self.name, path))
            }
            Err(e) => Err(io_err("removing", &path, &e)),
        }
    }

    /// Decrypt interactively (normal pinentry, inherited terminal) and discard
    /// the plaintext — the point is the side effect of gpg-agent caching the
    /// passphrase so the server's non-interactive reads succeed.
    ///
    /// # Errors
    ///
    /// [`PassError::NotFound`] when the entry doesn't exist; otherwise when
    /// gpg can't be run or doesn't decrypt.
    pub async fn unlock_interactive(&self) -> Result<(), PassError> {
        let path = self.existing_path().await?;
        let status = self
            .store
            .gpg_command()
            .args(["--quiet", "--decrypt", "--"])
            .arg(&path)
            .stdout(Stdio::null())
            .status()
            .await
            .map_err(|e| spawn_err(&self.store.gpg, &e))?;
        if status.success() {
            Ok(())
        } else {
            Err(PassError::Other(format!(
                "gpg could not decrypt {} (if no passphrase prompt appeared, \
                 try `export GPG_TTY=$(tty)` and run this again)",
                path.display()
            )))
        }
    }
}

/// Reject names that would escape the store or address something other than
/// a file inside it.
fn validate_entry_name(name: &str) -> Result<(), PassError> {
    let bad = name.is_empty()
        || name.contains('\0')
        || name.contains('\\')
        || name
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..");
    if bad {
        return Err(PassError::Other(format!(
            "invalid pass entry name {name:?}: use a relative path like app-mcp/host.example.com"
        )));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum DecryptOutcome {
    Ok,
    Locked,
    NoSecretKey,
    Failed,
}

/// Classify a decrypt from its exit status and `--status-fd` lines.
/// Success additionally requires `DECRYPTION_OKAY`, which gpg emits only
/// once integrity (MDC/AEAD) has been verified. Failures are classified
/// only from numeric gpg-error codes, never gpg's (localized) human text.
fn classify_decrypt(success: bool, stderr: &str) -> DecryptOutcome {
    let status: Vec<&str> = stderr
        .lines()
        .filter_map(|l| l.strip_prefix("[GNUPG:] "))
        .collect();
    if success && status.contains(&"DECRYPTION_OKAY") {
        return DecryptOutcome::Ok;
    }
    // `ERROR <location> <code>`; with several recipients there can be one per
    // key, so prefer the actionable "locked" over "no secret key".
    let codes: Vec<u32> = status
        .iter()
        .filter_map(|s| s.strip_prefix("ERROR "))
        .filter_map(|rest| rest.split_whitespace().nth(1)?.parse::<u32>().ok())
        .map(|code| code & 0xFFFF)
        .collect();
    if codes
        .iter()
        .any(|c| matches!(*c, GPG_ERR_NO_PIN_ENTRY | GPG_ERR_CANCELED))
    {
        DecryptOutcome::Locked
    } else if codes.contains(&GPG_ERR_NO_SECKEY) {
        DecryptOutcome::NoSecretKey
    } else {
        DecryptOutcome::Failed
    }
}

/// gpg's human-readable stderr (status lines removed), truncated.
fn human_message(stderr: &str) -> String {
    let msg = stderr
        .lines()
        .filter(|l| !l.starts_with("[GNUPG:] ") && !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    if msg.is_empty() {
        return "no error output".into();
    }
    match msg.char_indices().nth(MAX_GPG_MESSAGE) {
        Some((cut, _)) => format!("{}…", &msg[..cut]),
        None => msg,
    }
}

/// Create `path` exclusively (fails if anything, including a symlink, is
/// already there), owner-only (0600) on Unix.
///
/// # Errors
///
/// When anything already exists at `path`, or it can't be created.
pub fn create_private_file(path: &Path) -> Result<std::fs::File, PassError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map_err(|e| io_err("creating", path, &e))
}

/// Create `dir` and its parents, owner-only (0700) on Unix.
///
/// # Errors
///
/// When the directory can't be created.
pub fn create_private_dir(dir: &Path) -> Result<(), PassError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| io_err("creating", dir, &e))
}

/// Owner-only (0600), whatever gpg's `--output` left behind.
#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), PassError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| io_err("restricting", path, &e))
}

/// Unix permissions don't apply elsewhere.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // same signature as the Unix version
const fn restrict(_: &Path) -> Result<(), PassError> {
    Ok(())
}

/// Quote `s` for a POSIX shell, unless it's made only of characters that
/// never need quoting (so `~`, spaces, `$`, quotes … can't change the
/// command a user pastes).
#[must_use]
pub fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._+-:@%=,".contains(&b));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

fn io_err(action: &str, path: &Path, e: &std::io::Error) -> PassError {
    PassError::Other(format!("{action} {}: {e}", path.display()))
}

fn spawn_err(gpg: &Path, e: &std::io::Error) -> PassError {
    if e.kind() == std::io::ErrorKind::NotFound {
        PassError::Other(format!(
            "gpg program {} not found; install GnuPG or set \"gpg\" in the config to its \
             full path",
            gpg.display()
        ))
    } else {
        PassError::Other(format!("running {}: {e}", gpg.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        EnvGuard, LOCKED_SNIPPET, NO_SECKEY_SNIPPET, branding, fake_gpg, ok_snippet, store,
    };

    fn store_with(name: &str, snippet: &str) -> (tempfile::TempDir, PassEntry) {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry(name).unwrap();
        std::fs::create_dir_all(entry.path().parent().unwrap()).unwrap();
        std::fs::write(entry.path(), snippet).unwrap();
        (dir, entry)
    }

    fn args_file(dir: &Path) -> String {
        let path = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().ends_with(".args"))
            .unwrap();
        std::fs::read_to_string(path).unwrap()
    }

    #[tokio::test]
    async fn read_token_returns_first_line() {
        let (_dir, entry) = store_with("app-mcp/host.example.com", &ok_snippet("tok-abc"));
        assert_eq!(entry.read_token().await.unwrap(), "tok-abc");
    }

    #[tokio::test]
    async fn read_token_ignores_metadata_lines_and_trims() {
        let snippet = "printf '  tok-abc \\nuser: me\\n'\n\
                       echo '[GNUPG:] DECRYPTION_OKAY' >&2\nexit 0\n";
        let (_dir, entry) = store_with("t", snippet);
        assert_eq!(entry.read_token().await.unwrap(), "tok-abc");
    }

    #[tokio::test]
    async fn ok_snippet_survives_shell_metacharacters() {
        let token = "it's $HOME `x`";
        let (_dir, entry) = store_with("t", &ok_snippet(token));
        assert_eq!(entry.read_token().await.unwrap(), token);
    }

    #[tokio::test]
    async fn read_path_never_prompts() {
        // The fake records nothing in decrypt mode, so make the "ciphertext"
        // dump the argv and stdin it was given.
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        let seen = dir.path().join("seen");
        std::fs::write(
            entry.path(),
            format!(
                "echo \"$all\" > '{0}'\n\
                 if read -r line; then echo stdin-open >> '{0}'; fi\n{1}",
                seen.display(),
                ok_snippet("tok")
            ),
        )
        .unwrap();
        entry.read_token().await.unwrap();
        let seen = std::fs::read_to_string(seen).unwrap();
        assert!(
            seen.contains(
                "--batch --quiet --no-tty --pinentry-mode error --status-fd 2 --decrypt --"
            ),
            "{seen}"
        );
        assert!(!seen.contains("stdin-open"), "stdin must be null: {seen}");
    }

    #[tokio::test]
    async fn locked_key_is_reported_as_locked() {
        let (_dir, entry) = store_with("t", LOCKED_SNIPPET);
        let err = entry.read_token().await.unwrap_err();
        assert!(matches!(err, PassError::Locked { .. }), "{err}");
        let msg = err.to_string();
        assert!(msg.starts_with("Test token is locked: "), "{msg}");
        assert!(msg.contains("`test-mcp unlock`"), "{msg}");
        assert!(msg.contains("retry"), "{msg}");
    }

    #[tokio::test]
    async fn locked_message_keeps_the_actionable_wording() {
        let dir = tempfile::tempdir().unwrap();
        let store = PassStore::new(dir.path(), "/usr/bin/gpg", branding());
        let path = dir.path().join("t.gpg");
        let err = PassError::Locked {
            product: "Proxmox".into(),
            gpg_decrypt: store.gpg_decrypt_command(&path),
            cli: "proxmox-mcp".into(),
            path: path.clone(),
        };
        assert_eq!(
            err.to_string(),
            format!(
                "Proxmox token is locked: gpg-agent has no cached passphrase for the key \
                 that decrypts {p}. Ask the user to unlock it by running `proxmox-mcp unlock` \
                 (or `/usr/bin/gpg --decrypt {p} >/dev/null`) in a terminal, then retry.",
                p = path.display()
            )
        );
    }

    #[tokio::test]
    async fn no_seckey_is_reported_as_no_secret_key() {
        let (_dir, entry) = store_with("t", NO_SECKEY_SNIPPET);
        let err = entry.read_token().await.unwrap_err();
        assert!(matches!(err, PassError::NoSecretKey { .. }), "{err}");
    }

    #[tokio::test]
    async fn missing_entry_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("nope").unwrap();
        let err = entry.read_token().await.unwrap_err();
        assert!(matches!(err, PassError::NotFound { .. }), "{err}");
        let msg = err.to_string();
        assert!(msg.starts_with("no Test token stored"), "{msg}");
        assert!(msg.contains("run `test-mcp login`"), "{msg}");
    }

    #[tokio::test]
    async fn exit_zero_without_decryption_okay_is_rejected() {
        // E.g. an integrity failure gpg still exits 0 on: never trust stdout.
        let (_dir, entry) = store_with("t", "echo tok-abc\nexit 0\n");
        let err = entry.read_token().await.unwrap_err();
        assert!(matches!(err, PassError::Other(_)), "{err}");
    }

    #[tokio::test]
    async fn decryption_okay_with_nonzero_exit_is_rejected() {
        let snippet = "echo tok-abc\necho '[GNUPG:] DECRYPTION_OKAY' >&2\nexit 2\n";
        let (_dir, entry) = store_with("t", snippet);
        let err = entry.read_token().await.unwrap_err();
        assert!(matches!(err, PassError::Other(_)), "{err}");
    }

    #[tokio::test]
    async fn unclassified_failure_forwards_gpg_message() {
        let snippet = "echo 'gpg: no valid OpenPGP data found.' >&2\n\
                       echo '[GNUPG:] NODATA 1' >&2\nexit 2\n";
        let (_dir, entry) = store_with("t", snippet);
        let msg = entry.read_token().await.unwrap_err().to_string();
        assert!(msg.contains("no valid OpenPGP data found"), "{msg}");
        assert!(!msg.contains("[GNUPG:]"), "{msg}");
    }

    #[test]
    fn long_gpg_messages_are_truncated_on_a_char_boundary() {
        let msg = human_message(&"€".repeat(400));
        assert_eq!(msg.chars().count(), MAX_GPG_MESSAGE + 1);
        assert!(msg.ends_with('…'));
        assert_eq!(human_message("[GNUPG:] NODATA 1\n\n"), "no error output");
    }

    #[tokio::test]
    async fn empty_plaintext_is_rejected() {
        let (_dir, entry) = store_with("t", &ok_snippet(""));
        let msg = entry.read_token().await.unwrap_err().to_string();
        assert!(msg.contains("empty"), "{msg}");
        assert!(msg.contains("`test-mcp login`"), "{msg}");
    }

    #[tokio::test]
    async fn whitespace_only_first_line_is_rejected() {
        let (_dir, entry) = store_with("t", &ok_snippet("   "));
        let msg = entry.read_token().await.unwrap_err().to_string();
        assert!(msg.contains("empty"), "{msg}");
    }

    #[tokio::test]
    async fn hung_gpg_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).with_timeout(Duration::from_millis(200));
        let entry = store.entry("t").unwrap();
        // `exec`, so killing gpg kills the sleep too. A plain `sleep` child
        // outlives the killed shell and, since spawn isn't atomic with CLOEXEC
        // on macOS, can hold another test's pipe open for the full 10s.
        std::fs::write(entry.path(), "exec sleep 10\n").unwrap();
        let start = std::time::Instant::now();
        let err = entry.read_token().await.unwrap_err();
        assert!(matches!(err, PassError::Timeout { .. }), "{err}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn missing_gpg_binary_names_the_config_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = PassStore::new(dir.path(), dir.path().join("no-such-gpg"), branding());
        let entry = store.entry("t").unwrap();
        std::fs::write(entry.path(), "").unwrap();
        let msg = entry.read_token().await.unwrap_err().to_string();
        assert!(msg.contains("\"gpg\""), "{msg}");
        assert!(msg.contains("not found"), "{msg}");
    }

    #[test]
    fn classify_prefers_locked_over_no_seckey() {
        let stderr = "[GNUPG:] ERROR pkdecrypt_failed 33554449\n\
                      [GNUPG:] ERROR pkdecrypt_failed 67108949\n";
        assert_eq!(classify_decrypt(false, stderr), DecryptOutcome::Locked);
    }

    #[test]
    fn classify_maps_codes() {
        let line = |code: u32| format!("[GNUPG:] ERROR pkdecrypt_failed {code}\n");
        // No pinentry (source 4, code 85), captured from GnuPG 2.4.
        assert_eq!(
            classify_decrypt(false, &line(67_108_949)),
            DecryptOutcome::Locked
        );
        // Cancelled pinentry (source 4, code 99), captured from GnuPG 2.4.
        assert_eq!(
            classify_decrypt(false, &line(67_108_963)),
            DecryptOutcome::Locked
        );
        // No secret key (source 2, code 17), captured from GnuPG 2.4.
        assert_eq!(
            classify_decrypt(false, &line(33_554_449)),
            DecryptOutcome::NoSecretKey
        );
        // Bare codes (no source bits) classify the same.
        assert_eq!(classify_decrypt(false, &line(85)), DecryptOutcome::Locked);
        assert_eq!(classify_decrypt(false, ""), DecryptOutcome::Failed);
        // Human text alone never classifies — only numeric status codes do.
        assert_eq!(
            classify_decrypt(false, "gpg: decryption failed: No pinentry\n"),
            DecryptOutcome::Failed
        );
        assert_eq!(
            classify_decrypt(false, "gpg: decryption failed: No secret key\n"),
            DecryptOutcome::Failed
        );
        // Success needs both exit 0 and DECRYPTION_OKAY.
        assert_eq!(
            classify_decrypt(true, "[GNUPG:] DECRYPTION_OKAY\n"),
            DecryptOutcome::Ok
        );
        assert_eq!(classify_decrypt(true, ""), DecryptOutcome::Failed);
    }

    #[test]
    fn entry_names_cannot_escape_the_store() {
        let store = PassStore::new("/s", "gpg", branding());
        for bad in [
            "", "/abs", "../x", "a/../b", "a//b", "a/", "./a", "a/.", "a\\b", "a\0b", "..",
        ] {
            assert!(store.entry(bad).is_err(), "{bad:?} accepted");
        }
        for good in [
            "t",
            "app-mcp/host.example.com",
            "a/b/c.example_8080",
            "a..b",
        ] {
            assert!(store.entry(good).is_ok(), "{good:?} rejected");
        }
    }

    #[test]
    fn recipients_come_from_nearest_gpg_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = PassStore::new(dir.path(), "gpg", branding());
        let entry = store.entry("a/b/tok").unwrap();
        assert!(entry.recipients().unwrap().is_none());

        std::fs::write(dir.path().join(".gpg-id"), "ROOT\n").unwrap();
        assert_eq!(entry.recipients().unwrap().unwrap(), vec!["ROOT"]);

        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        std::fs::write(
            dir.path().join("a/.gpg-id"),
            "# comment\nK1 # work key\n\nK2\n   # indented comment\n",
        )
        .unwrap();
        assert_eq!(entry.recipients().unwrap().unwrap(), vec!["K1", "K2"]);

        std::fs::write(dir.path().join("a/.gpg-id"), "# only a comment\n").unwrap();
        assert!(entry.recipients().is_err());
    }

    #[test]
    fn recipients_stop_at_the_store_root() {
        let dir = tempfile::tempdir().unwrap();
        // A .gpg-id *above* the store must not be used.
        std::fs::write(dir.path().join(".gpg-id"), "OUTSIDE\n").unwrap();
        let store = PassStore::new(dir.path().join("store"), "gpg", branding());
        assert!(
            store
                .entry("a/tok")
                .unwrap()
                .recipients()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn init_writes_root_gpg_id_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = PassStore::new(dir.path().join("store"), "gpg", branding());
        assert!(store.init("  ").is_err());
        assert!(store.init("A\nB").is_err());
        store.init("ABCD1234").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("store/.gpg-id")).unwrap(),
            "ABCD1234\n"
        );
        assert!(store.init("OTHER").is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("store/.gpg-id")).unwrap(),
            "ABCD1234\n"
        );
    }

    #[tokio::test]
    async fn write_token_encrypts_to_every_recipient_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("app-mcp/host.example.com").unwrap();
        entry
            .write_token("tok-new", &["K1".into(), "K2".into()])
            .await
            .unwrap();
        // The fake "encrypts" by copying stdin.
        assert_eq!(std::fs::read_to_string(entry.path()).unwrap(), "tok-new\n");
        let parent = entry.path().parent().unwrap().to_path_buf();
        let args = args_file(&parent);
        assert!(args.contains("--recipient K1 --recipient K2"), "{args}");
        assert!(args.contains("--yes"), "{args}");
        // Only the entry remains: the temp file was renamed.
        assert_eq!(names(&parent), vec!["host.example.com.gpg"]);
        #[cfg(unix)]
        {
            assert_eq!(mode(&entry.path()), 0o600);
            assert_eq!(mode(&parent), 0o700);
        }
    }

    #[tokio::test]
    async fn early_gpg_exit_reports_gpgs_error_not_a_broken_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        // Bigger than a pipe buffer, so the write is still in flight when the
        // fake gpg exits without reading it.
        let token = "x".repeat(1 << 20);
        let msg = entry
            .write_token(&token, &["NOPUBKEY".into()])
            .await
            .unwrap_err()
            .to_string();
        assert!(msg.contains("No public key"), "{msg}");
        assert!(!msg.contains("Broken pipe"), "{msg}");
        assert!(!entry.path().exists());
        // No temp file left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn hung_encrypt_times_out_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).with_timeout(Duration::from_secs(1));
        let entry = store.entry("t").unwrap();
        let start = std::time::Instant::now();
        // Bigger than a pipe buffer: the stdin write itself must be bounded.
        let err = entry
            .write_token(&"x".repeat(1 << 20), &["HANG".into()])
            .await
            .unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(5));
        // Names the entry, not the temp file, and what gpg was doing.
        assert_eq!(
            err.to_string(),
            format!(
                "gpg did not finish encrypting {} within 1s",
                entry.path().display()
            )
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_token_refuses_a_planted_temp_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "precious").unwrap();
        let tmp = dir.path().join(format!(".t.gpg.tmp{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();
        let err = entry
            .write_token("tok-x", &["K1".into()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("creating"), "{err}");
        // Neither followed nor deleted: we didn't create it.
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        assert!(tmp.symlink_metadata().is_ok());
        assert!(!entry.path().exists());
    }

    #[tokio::test]
    async fn write_token_refuses_a_planted_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        let tmp = dir.path().join(format!(".t.gpg.tmp{}", std::process::id()));
        std::fs::write(&tmp, "theirs").unwrap();
        assert!(entry.write_token("tok-x", &["K1".into()]).await.is_err());
        assert_eq!(std::fs::read_to_string(&tmp).unwrap(), "theirs");
    }

    #[test]
    fn remove_deletes_and_missing_entry_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let entry = PassStore::new(dir.path(), "gpg", branding())
            .entry("t")
            .unwrap();
        assert!(matches!(entry.remove(), Err(PassError::NotFound { .. })));
        std::fs::write(entry.path(), "x").unwrap();
        entry.remove().unwrap();
        assert!(!entry.path().exists());
    }

    #[tokio::test]
    async fn homedir_is_passed_to_gpg() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).with_homedir(Some(dir.path().join("gnupg")));
        let entry = store.entry("t").unwrap();
        entry.write_token("tok-x", &["K1".into()]).await.unwrap();
        let args = args_file(dir.path());
        let want = format!("--homedir {}", dir.path().join("gnupg").display());
        assert!(args.contains(&want), "{args}");
    }

    #[tokio::test]
    async fn locked_advice_names_the_config_and_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let cli = Branding::cli_prefix("test-mcp", "--config", Some(Path::new("~/work cfg.json")));
        let store = PassStore::new(dir.path(), fake_gpg(), Branding::new("Test", cli))
            .with_homedir(Some(PathBuf::from("/keys/my gnupg")));
        let entry = store.entry("t").unwrap();
        std::fs::write(entry.path(), LOCKED_SNIPPET).unwrap();

        let msg = entry.read_token().await.unwrap_err().to_string();
        // The app's own --config (quoted: `~` and the space) and keyring, so
        // the advice unlocks the agent this server uses.
        assert!(
            msg.contains("`test-mcp --config '~/work cfg.json' unlock`"),
            "{msg}"
        );
        assert!(
            msg.contains("--homedir '/keys/my gnupg' --decrypt"),
            "{msg}"
        );
        assert!(msg.contains(" >/dev/null`"), "{msg}");

        std::fs::remove_file(entry.path()).unwrap();
        let msg = entry.read_token().await.unwrap_err().to_string();
        assert!(
            msg.contains("`test-mcp --config '~/work cfg.json' login`"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn default_config_advice_is_plain_unlock() {
        let (_dir, entry) = store_with("t", LOCKED_SNIPPET);
        let msg = entry.read_token().await.unwrap_err().to_string();
        assert!(msg.contains("`test-mcp unlock`"), "{msg}");
        assert!(!msg.contains("--homedir"), "{msg}");
    }

    #[test]
    fn cli_prefix_quotes_the_config_value() {
        assert_eq!(
            Branding::cli_prefix("proxmox-mcp", "--config-dir", None),
            "proxmox-mcp"
        );
        assert_eq!(
            Branding::cli_prefix("proxmox-mcp", "--config-dir", Some(Path::new("/etc/p mcp"))),
            "proxmox-mcp --config-dir '/etc/p mcp'"
        );
        assert_eq!(
            Branding::cli_prefix("netbox-mcp", "--config", Some(Path::new("/x.json"))),
            "netbox-mcp --config /x.json"
        );
    }

    #[test]
    fn shell_quote_quotes_only_when_needed() {
        assert_eq!(shell_quote("/a/b-c_d.gpg"), "/a/b-c_d.gpg");
        assert_eq!(shell_quote("/a b"), "'/a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("~/x"), "'~/x'");
        assert_eq!(shell_quote("$HOME"), "'$HOME'");
        assert_eq!(shell_quote(""), "''");
    }

    /// A `StoreEnv` with only a home directory.
    fn env_with_home(home: &str) -> StoreEnv {
        StoreEnv {
            home: Some(home.into()),
            ..StoreEnv::default()
        }
    }

    #[test]
    fn relative_store_paths_are_made_absolute() {
        let store = PassStore::resolve(
            &StoreLocation {
                gpg: None,
                store_dir: Some("rel-store"),
                gnupg_home: Some("rel-gnupg"),
            },
            &StoreEnv::default(),
            branding(),
        )
        .unwrap();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(store.root(), cwd.join("rel-store"));
        assert_eq!(store.homedir(), Some(cwd.join("rel-gnupg").as_path()));
        assert_eq!(store.gpg(), Path::new("gpg"));
    }

    #[test]
    fn configured_location_beats_environment() {
        let env = StoreEnv {
            home: Some("/home/me".into()),
            password_store_dir: Some("/env/store".into()),
            gnupg_home: Some("/env/gnupg".into()),
        };
        let store = PassStore::resolve(
            &StoreLocation {
                gpg: Some("/opt/gpg/bin/gpg"),
                store_dir: Some("/stores/pass"),
                gnupg_home: Some("/keys/gnupg"),
            },
            &env,
            branding(),
        )
        .unwrap();
        assert_eq!(store.root(), Path::new("/stores/pass"));
        assert_eq!(store.homedir(), Some(Path::new("/keys/gnupg")));
        assert_eq!(store.gpgconf(), PathBuf::from("/opt/gpg/bin/gpgconf"));
        let store = PassStore::resolve(&StoreLocation::default(), &env, branding()).unwrap();
        assert_eq!(store.root(), Path::new("/env/store"));
        assert_eq!(store.homedir(), Some(Path::new("/env/gnupg")));
    }

    #[test]
    fn an_empty_environment_uses_the_defaults() {
        let store = PassStore::resolve(
            &StoreLocation::default(),
            &env_with_home("/home/me"),
            branding(),
        )
        .unwrap();
        assert_eq!(store.root(), Path::new("/home/me/.password-store"));
        // gpg's own lookup decides; nothing is passed as --homedir.
        assert_eq!(store.homedir(), None);
        assert_eq!(store.gpg(), Path::new("gpg"));
    }

    #[test]
    fn tilde_paths_expand_to_home() {
        let store = PassStore::resolve(
            &StoreLocation {
                gpg: Some("~/bin/gpg"),
                store_dir: Some("~/.password-store"),
                gnupg_home: Some("~/.gnupg"),
            },
            &env_with_home("/home/me"),
            branding(),
        )
        .unwrap();
        assert_eq!(store.root(), Path::new("/home/me/.password-store"));
        assert_eq!(store.homedir(), Some(Path::new("/home/me/.gnupg")));
        assert_eq!(store.gpg(), Path::new("/home/me/bin/gpg"));
    }

    #[test]
    fn gpgconf_sits_next_to_an_explicit_gpg() {
        assert_eq!(
            PassStore::new("/s", "/opt/homebrew/bin/gpg", branding()).gpgconf(),
            PathBuf::from("/opt/homebrew/bin/gpgconf")
        );
        assert_eq!(
            PassStore::new("/s", "gpg", branding()).gpgconf(),
            PathBuf::from("gpgconf")
        );
    }

    /// Entry names under `dir`, minus the fake's `.args` records.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| Path::new(n).extension().is_none_or(|e| e != "args"))
            .collect();
        names.sort();
        names
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn unlock_interactive_uses_the_normal_pinentry() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        let seen = dir.path().join("seen");
        std::fs::write(
            entry.path(),
            format!("echo \"$all\" > '{}'\nexit 0\n", seen.display()),
        )
        .unwrap();
        entry.unlock_interactive().await.unwrap();
        let seen = std::fs::read_to_string(seen).unwrap();
        assert!(seen.contains(" --quiet --decrypt -- "), "{seen}");
        // Interactive on purpose: a pinentry may prompt here.
        assert!(!seen.contains("--pinentry-mode"), "{seen}");
        assert!(!seen.contains("--batch"), "{seen}");
    }

    #[tokio::test]
    async fn unlock_interactive_failure_suggests_gpg_tty() {
        let (_dir, entry) = store_with("t", "exit 2\n");
        let msg = entry.unlock_interactive().await.unwrap_err().to_string();
        assert!(msg.contains("GPG_TTY"), "{msg}");
        assert!(msg.contains(&entry.path().display().to_string()), "{msg}");
    }

    #[tokio::test]
    async fn non_utf8_plaintext_is_rejected() {
        let snippet = "printf '\\377\\376\\n'\necho '[GNUPG:] DECRYPTION_OKAY' >&2\nexit 0\n";
        let (_dir, entry) = store_with("t", snippet);
        let msg = entry.read_token().await.unwrap_err().to_string();
        assert!(msg.contains("UTF-8"), "{msg}");
    }

    #[tokio::test]
    async fn timeout_message_names_the_entry_and_limit() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).with_timeout(Duration::from_secs(1));
        let entry = store.entry("t").unwrap();
        std::fs::write(entry.path(), "exec sleep 10\n").unwrap();
        let msg = entry.read_token().await.unwrap_err().to_string();
        assert_eq!(
            msg,
            format!(
                "gpg did not finish decrypting {} within 1s",
                entry.path().display()
            )
        );
    }

    #[test]
    fn error_messages() {
        let path = PathBuf::from("/s/t.gpg");
        assert_eq!(
            PassError::NoSecretKey { path: path.clone() }.to_string(),
            "no secret key in this GnuPG keyring can decrypt /s/t.gpg"
        );
        assert_eq!(
            PassError::NotFound {
                product: "NetBox".into(),
                entry: "t".into(),
                path,
                cli: "netbox-mcp".into(),
            }
            .to_string(),
            "no NetBox token stored at pass entry 't' (/s/t.gpg does not exist); \
             run `netbox-mcp login` to store one"
        );
    }

    #[tokio::test]
    async fn write_token_replaces_an_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        entry.write_token("tok-old", &["K1".into()]).await.unwrap();
        entry.write_token("tok-new", &["K1".into()]).await.unwrap();
        assert_eq!(std::fs::read_to_string(entry.path()).unwrap(), "tok-new\n");
        assert_eq!(names(dir.path()), vec!["t.gpg"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_token_creates_every_new_directory_private() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        let entry = PassStore::new(&root, fake_gpg(), branding())
            .entry("a/b/c")
            .unwrap();
        entry.write_token("tok", &["K1".into()]).await.unwrap();
        for d in [root.clone(), root.join("a"), root.join("a/b")] {
            assert_eq!(mode(&d), 0o700, "{}", d.display());
        }
        assert_eq!(mode(&entry.path()), 0o600);
    }

    #[tokio::test]
    async fn write_token_with_a_missing_gpg_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let store = PassStore::new(dir.path(), dir.path().join("no-such-gpg"), branding());
        let entry = store.entry("t").unwrap();
        let msg = entry
            .write_token("tok", &["K1".into()])
            .await
            .unwrap_err()
            .to_string();
        assert!(msg.contains("not found"), "{msg}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_executable_gpg_is_a_spawn_error_not_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let gpg = dir.path().join("gpg");
        // Never executable, so no ETXTBSY race with concurrently spawned tests.
        std::fs::write(&gpg, "").unwrap();
        let store = PassStore::new(dir.path(), &gpg, branding());
        let entry = store.entry("t").unwrap();
        std::fs::write(entry.path(), "").unwrap();
        let msg = entry.read_token().await.unwrap_err().to_string();
        assert!(
            msg.starts_with(&format!("running {}: ", gpg.display())),
            "{msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn init_creates_a_private_store() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        PassStore::new(&root, "gpg", branding())
            .init(" ABCD ")
            .unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join(".gpg-id")), 0o600);
        assert_eq!(
            std::fs::read_to_string(root.join(".gpg-id")).unwrap(),
            "ABCD\n"
        );
    }

    #[test]
    fn create_private_file_never_reuses_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        drop(create_private_file(&path).unwrap());
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
        let err = create_private_file(&path).unwrap_err().to_string();
        assert!(err.starts_with("creating "), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn create_private_dir_is_owner_only_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("x/y");
        create_private_dir(&d).unwrap();
        create_private_dir(&d).unwrap();
        assert_eq!(mode(&d), 0o700);
        assert_eq!(mode(&dir.path().join("x")), 0o700);
    }

    #[test]
    fn gpg_decrypt_command_quotes_every_part() {
        let store = PassStore::new("/s", "/opt/my gpg/gpg", branding())
            .with_homedir(Some(PathBuf::from("/k/it's")));
        assert_eq!(
            store.gpg_decrypt_command(Path::new("/s/a b.gpg")),
            r"'/opt/my gpg/gpg' --homedir '/k/it'\''s' --decrypt '/s/a b.gpg'"
        );
        assert_eq!(
            PassStore::new("/s", "gpg", branding()).gpg_decrypt_command(Path::new("/s/t.gpg")),
            "gpg --decrypt /s/t.gpg"
        );
    }

    #[test]
    fn malformed_status_lines_never_classify() {
        for stderr in [
            "[GNUPG:] ERROR pkdecrypt_failed\n",
            "[GNUPG:] ERROR pkdecrypt_failed locked\n",
            "[GNUPG:] ERROR\n",
            "[GNUPG:]ERROR pkdecrypt_failed 67108949\n",
            "gpg: [GNUPG:] ERROR pkdecrypt_failed 67108949\n",
            "[GNUPG:] ERROR pkdecrypt_failed -85\n",
        ] {
            assert_eq!(
                classify_decrypt(false, stderr),
                DecryptOutcome::Failed,
                "{stderr:?}"
            );
        }
        // Other codes, even sharing high bits with a known one, don't count.
        assert_eq!(
            classify_decrypt(false, "[GNUPG:] ERROR x 67108950\n"),
            DecryptOutcome::Failed
        );
    }

    #[test]
    fn recipients_skip_a_gpg_id_that_is_not_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = PassStore::new(dir.path(), "gpg", branding());
        std::fs::write(dir.path().join(".gpg-id"), "ROOT\n").unwrap();
        std::fs::create_dir_all(dir.path().join("a/.gpg-id")).unwrap();
        let entry = store.entry("a/tok").unwrap();
        assert_eq!(entry.recipients().unwrap().unwrap(), vec!["ROOT"]);
        // A top-level entry reads the root .gpg-id directly.
        assert_eq!(
            store.entry("tok").unwrap().recipients().unwrap().unwrap(),
            vec!["ROOT"]
        );
    }

    #[test]
    fn resolve_without_a_home_needs_explicit_paths() {
        let no_home = StoreEnv::default();
        let msg = PassStore::resolve(&StoreLocation::default(), &no_home, branding())
            .unwrap_err()
            .to_string();
        assert!(msg.contains("home directory"), "{msg}");
        let tilde = StoreLocation {
            store_dir: Some("~/store"),
            ..StoreLocation::default()
        };
        assert!(PassStore::resolve(&tilde, &no_home, branding()).is_err());
        let explicit = StoreLocation {
            store_dir: Some("/stores/pass"),
            ..StoreLocation::default()
        };
        assert_eq!(
            PassStore::resolve(&explicit, &no_home, branding())
                .unwrap()
                .root(),
            Path::new("/stores/pass")
        );
    }

    #[test]
    fn environment_paths_expand_tilde() {
        let env = StoreEnv {
            home: Some("/home/me".into()),
            password_store_dir: Some("~/env-store".into()),
            gnupg_home: Some("~/env-gnupg".into()),
        };
        let store = PassStore::resolve(&StoreLocation::default(), &env, branding()).unwrap();
        assert_eq!(store.root(), Path::new("/home/me/env-store"));
        // Not `<cwd>/~/env-gnupg`: gpg itself would expand `~/` here.
        assert_eq!(store.homedir(), Some(Path::new("/home/me/env-gnupg")));
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn from_process_snapshots_the_environment() {
        let mut env = EnvGuard::new();
        env.set("HOME", "/home/me")
            .set("PASSWORD_STORE_DIR", "~/store")
            .set("GNUPGHOME", "/keys");
        assert_eq!(
            StoreEnv::from_process(),
            StoreEnv {
                home: Some("/home/me".into()),
                password_store_dir: Some("~/store".into()),
                gnupg_home: Some("/keys".into()),
            }
        );
        // Blank and unexpanded placeholders count as unset.
        env.set("PASSWORD_STORE_DIR", "${PASSWORD_STORE_DIR}")
            .set("GNUPGHOME", "  ")
            .remove("HOME")
            .remove("USERPROFILE");
        assert_eq!(StoreEnv::from_process(), StoreEnv::default());
    }

    #[test]
    fn accessors_report_what_was_configured() {
        let store = PassStore::new("/s", "/bin/gpg", Branding::new("P", "p-mcp"));
        assert_eq!(store.cli(), "p-mcp");
        assert_eq!(store.branding().product(), "P");
        assert_eq!(store.gpg(), Path::new("/bin/gpg"));
        assert_eq!(store.homedir(), None);
        let entry = store.entry("a/b").unwrap();
        assert_eq!(entry.name(), "a/b");
        assert_eq!(entry.path(), Path::new("/s/a/b.gpg"));
        assert_eq!(entry.store().root(), Path::new("/s"));
    }

    #[test]
    fn gpg_and_gpgconf_commands_carry_the_homedir() {
        let store = PassStore::new("/s", "/opt/bin/gpg", branding())
            .with_homedir(Some(PathBuf::from("/k")));
        for (cmd, program) in [
            (store.gpg_command(), "/opt/bin/gpg"),
            (store.gpgconf_command(), "/opt/bin/gpgconf"),
        ] {
            let cmd = cmd.as_std();
            assert_eq!(cmd.get_program(), program);
            let args: Vec<_> = cmd.get_args().collect();
            assert_eq!(args, ["--homedir", "/k"]);
        }
        let bare = PassStore::new("/s", "gpg", branding());
        assert_eq!(bare.gpg_command().as_std().get_args().count(), 0);
    }

    #[test]
    fn remove_reports_other_io_errors() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        // A directory where the entry file should be.
        std::fs::create_dir(entry.path()).unwrap();
        let err = entry.remove().unwrap_err();
        assert!(matches!(err, PassError::Other(_)), "{err}");
        assert!(err.to_string().starts_with("removing "), "{err}");
    }

    #[test]
    fn unreadable_gpg_id_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gpg-id"), b"\xff\xfe\n").unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        let err = entry.recipients().unwrap_err().to_string();
        assert!(err.starts_with("reading "), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unsearchable_store_is_an_error_not_not_found() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let entry = store(&locked).entry("a/t").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = entry.read_token().await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root ignores permissions, so this only means something otherwise.
        if !matches!(result, Err(PassError::NotFound { .. })) {
            let err = result.unwrap_err().to_string();
            assert!(err.starts_with("checking "), "{err}");
        }
    }

    #[tokio::test]
    async fn unlock_with_a_missing_gpg_names_the_config_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = PassStore::new(dir.path(), dir.path().join("no-such-gpg"), branding());
        let entry = store.entry("t").unwrap();
        std::fs::write(entry.path(), "").unwrap();
        let msg = entry.unlock_interactive().await.unwrap_err().to_string();
        assert!(msg.contains("\"gpg\""), "{msg}");
    }

    #[tokio::test]
    async fn unlock_of_a_missing_entry_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = store(dir.path())
            .entry("nope")
            .unwrap()
            .unlock_interactive()
            .await
            .unwrap_err();
        assert!(matches!(err, PassError::NotFound { .. }), "{err}");
        assert!(err.to_string().contains("`test-mcp login`"), "{err}");
    }

    #[tokio::test]
    async fn write_token_needs_a_recipient() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        let msg = entry.write_token("tok", &[]).await.unwrap_err().to_string();
        assert!(msg.starts_with("no GPG recipients"), "{msg}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
