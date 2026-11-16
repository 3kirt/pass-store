//! A minimal client for gpg-agent's Assuan protocol, used to report whether
//! the token's decryption key is unlocked *without* decrypting anything.
//!
//! This is deliberately diagnostic only (an app's `status` command): the
//! server's token reads go straight to a `--pinentry-mode error` decrypt,
//! because "not cached" is not the same as "can't decrypt" — a
//! passphrase-less key or a smartcard key reports uncached yet decrypts fine.
//!
//! Assuan is line-based: the agent greets with `OK …`, and each command is
//! answered by any number of `S` (status), `D` (data) and `#` (comment) lines,
//! terminated by `OK` or `ERR <code> <description>`.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::PassStore;

const AGENT_TIMEOUT: Duration = Duration::from_secs(5);

/// gpg-error code for "Not found" (the agent holds no such key).
const GPG_ERR_NOT_FOUND: u32 = 27;

/// The `KEYINFO` fields this crate cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInfo {
    /// `D` = key stored on disk, `T` = smartcard, `X` = unknown.
    pub kind: char,
    /// Passphrase currently in gpg-agent's cache.
    pub cached: bool,
    /// `P` = passphrase-protected, `C` = not protected, `-` = unknown.
    pub protection: char,
}

/// Summary of whether the token's key can decrypt without a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentState {
    Unlocked,
    Unprotected,
    Locked,
    Smartcard,
    NotRunning,
    NoSecretKey,
}

impl AgentState {
    /// A one-line description for a `status` command, with `cli` (the app's
    /// command prefix, see [`crate::Branding`]) in the unlock advice.
    #[must_use]
    pub fn describe(self, cli: &str) -> String {
        match self {
            Self::Unlocked => "unlocked (passphrase cached in gpg-agent)".into(),
            Self::Unprotected => "unlocked (key has no passphrase)".into(),
            Self::Locked => format!("locked (run `{cli} unlock`)"),
            Self::Smartcard => "smartcard key (gpg-agent does not report PIN state)".into(),
            Self::NotRunning => {
                format!("locked (gpg-agent is not running; run `{cli} unlock`)")
            }
            Self::NoSecretKey => "no secret key for the store's recipients in this keyring".into(),
        }
    }
}

/// The agent's state for the keys that can decrypt for `recipients`: the
/// whole keygrip → socket → `KEYINFO` → [`summarize`] sequence a `status`
/// command runs.
///
/// # Errors
///
/// When gpg, gpgconf or the agent fails or times out.
pub async fn state(store: &PassStore, recipients: &[String]) -> Result<AgentState, String> {
    let grips = encryption_keygrips(store, recipients).await?;
    if grips.is_empty() {
        return Ok(AgentState::NoSecretKey);
    }
    let socket = agent_socket(store).await?;
    Ok(query_socket(&socket, &grips)
        .await?
        .map_or(AgentState::NotRunning, |infos| summarize(&infos)))
}

/// Reduce per-keygrip results (`None` = agent doesn't hold that key) to one
/// state. Any usable key wins, since gpg tries every recipient.
#[must_use]
pub fn summarize(infos: &[Option<KeyInfo>]) -> AgentState {
    let held: Vec<&KeyInfo> = infos.iter().flatten().collect();
    if held.iter().any(|k| k.cached) {
        AgentState::Unlocked
    } else if held.iter().any(|k| k.protection == 'C') {
        AgentState::Unprotected
    } else if held.iter().any(|k| k.kind == 'T') {
        AgentState::Smartcard
    } else if held.is_empty() {
        AgentState::NoSecretKey
    } else {
        AgentState::Locked
    }
}

/// Keygrips of the encryption-capable (sub)keys for `recipients`, from
/// `gpg --list-secret-keys --with-colons --with-keygrip`. No recipients
/// means no keygrips (gpg would list the whole keyring).
///
/// # Errors
///
/// When gpg can't be run or times out.
pub async fn encryption_keygrips(
    store: &PassStore,
    recipients: &[String],
) -> Result<Vec<String>, String> {
    if recipients.is_empty() {
        return Ok(Vec::new());
    }
    let mut cmd = store.gpg_command();
    cmd.args([
        "--batch",
        "--no-tty",
        "--with-colons",
        "--with-keygrip",
        "--list-secret-keys",
        "--",
    ])
    .args(recipients);
    let output = run(cmd, "gpg", "listing secret keys").await?;
    // A recipient with no secret key makes gpg exit non-zero while still
    // listing the others, so parse whatever came out rather than failing.
    Ok(parse_encryption_keygrips(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// In colon listings a `grp` record carries the keygrip (field 10) of the
/// `sec`/`ssb` record before it, whose field 12 lists its capabilities;
/// a lowercase `e` means that specific (sub)key can encrypt. Field 2 is its
/// validity: an expired (`e`), revoked (`r`), disabled (`d`) or invalid (`i`)
/// subkey is skipped, since gpg won't decrypt with it, so its cached
/// passphrase must not make `status` report "unlocked".
fn parse_encryption_keygrips(colons: &str) -> Vec<String> {
    let mut grips = Vec::new();
    let mut want = false;
    for line in colons.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.first().copied() {
            Some("sec" | "ssb") => {
                let usable = !fields
                    .get(1)
                    .is_some_and(|v| matches!(*v, "e" | "r" | "d" | "i"));
                want = usable && fields.get(11).is_some_and(|caps| caps.contains('e'));
            }
            Some("grp") => {
                if want && let Some(grip) = fields.get(9).filter(|g| !g.is_empty()) {
                    grips.push((*grip).to_string());
                }
                want = false;
            }
            _ => {}
        }
    }
    grips
}

/// The agent's socket path, from `gpgconf --list-dirs agent-socket`.
///
/// # Errors
///
/// When gpgconf can't be run, fails or times out.
pub async fn agent_socket(store: &PassStore) -> Result<PathBuf, String> {
    let mut cmd = store.gpgconf_command();
    cmd.args(["--list-dirs", "agent-socket"]);
    let output = run(cmd, "gpgconf", "running gpgconf").await?;
    if !output.status.success() {
        return Err("gpgconf --list-dirs failed".into());
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    Ok(PathBuf::from(percent_unescape(raw.trim())))
}

/// Run `cmd` (the `program`) under [`AGENT_TIMEOUT`], killing it on timeout.
/// `doing` describes it for the timeout error.
async fn run(
    mut cmd: tokio::process::Command,
    program: &str,
    doing: &str,
) -> Result<Output, String> {
    tokio::time::timeout(AGENT_TIMEOUT, cmd.kill_on_drop(true).output())
        .await
        .map_err(|_| format!("timed out {doing}"))?
        .map_err(|e| format!("running {program}: {e}"))
}

/// `gpgconf` percent-escapes some characters (e.g. `:` as `%3a`) in paths.
fn percent_unescape(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Query `KEYINFO` for each keygrip over the agent socket. `Ok(None)` means
/// the agent isn't running (no socket / connection refused) — which also
/// means nothing is cached.
///
/// # Errors
///
/// On any other connection error, a protocol error, an unexpected `ERR`
/// reply, an invalid keygrip, or a timeout.
pub async fn query_socket(
    socket: &Path,
    grips: &[String],
) -> Result<Option<Vec<Option<KeyInfo>>>, String> {
    let stream =
        match tokio::time::timeout(AGENT_TIMEOUT, tokio::net::UnixStream::connect(socket)).await {
            Err(_) => return Err("timed out connecting to gpg-agent".into()),
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(None);
            }
            Ok(Err(e)) => return Err(format!("connecting to {}: {e}", socket.display())),
            Ok(Ok(s)) => s,
        };
    tokio::time::timeout(AGENT_TIMEOUT, keyinfo(stream, grips))
        .await
        .map_err(|_| "timed out talking to gpg-agent".to_string())?
        .map(Some)
}

/// The Assuan exchange itself, over any stream (unit-tested with an
/// in-memory duplex).
async fn keyinfo<S>(stream: S, grips: &[String]) -> Result<Vec<Option<KeyInfo>>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = BufReader::new(read).lines();
    read_response(&mut lines, |_| {})
        .await?
        .map_err(|e| format!("agent greeting: {e}"))?;

    let mut out = Vec::with_capacity(grips.len());
    for grip in grips {
        if grip.is_empty() || !grip.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("invalid keygrip {grip:?}"));
        }
        write
            .write_all(format!("KEYINFO {grip}\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut info = None;
        let result = read_response(&mut lines, |status| {
            if let Some(rest) = status.strip_prefix("KEYINFO ") {
                info = parse_keyinfo(rest);
            }
        })
        .await?;
        match result {
            Ok(()) => out.push(info),
            Err(code) if code & 0xFFFF == GPG_ERR_NOT_FOUND => out.push(None),
            Err(code) => return Err(format!("gpg-agent KEYINFO failed with error code {code}")),
        }
    }
    let _ = write.write_all(b"BYE\n").await;
    Ok(out)
}

/// Read one response, passing each `S` line's payload to `on_status`.
/// Outer `Err` = protocol/IO failure; inner `Err(code)` = an `ERR` reply.
async fn read_response<R>(
    lines: &mut tokio::io::Lines<R>,
    mut on_status: impl FnMut(&str),
) -> Result<Result<(), u32>, String>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    loop {
        let line = lines
            .next_line()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("gpg-agent closed the connection")?;
        if line == "OK" || line.starts_with("OK ") {
            return Ok(Ok(()));
        }
        if let Some(rest) = line.strip_prefix("ERR ") {
            let code = rest
                .split_whitespace()
                .next()
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            return Ok(Err(code));
        }
        if let Some(status) = line.strip_prefix("S ") {
            on_status(status);
        }
        // `D` data and `#` comment lines carry nothing KEYINFO needs.
    }
}

/// `<grip> <type> <serialno> <idstr> <cached> <protection> …`
fn parse_keyinfo(rest: &str) -> Option<KeyInfo> {
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ch = |i: usize| f.get(i).and_then(|s| s.chars().next());
    Some(KeyInfo {
        kind: ch(1)?,
        cached: f.get(4)? == &"1",
        protection: ch(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRIP_A: &str = "0884A1089616245A3434A61E59FFC6C0A7CE8E60";
    const GRIP_B: &str = "DA8860143E78BEEF72E4C9232E98A0E2C7014E13";

    /// Real GnuPG 2.4 `--with-colons --with-keygrip --list-secret-keys`
    /// output for an ed25519 primary (sign/cert) + cv25519 encryption subkey.
    const COLONS: &str = "\
sec:u:255:22:F8EDFF4A32799371:1794667539:::u:::scESC:::+::ed25519:::0:
fpr:::::::::FD0E69EB3924E8BB360A120DF8EDFF4A32799371:
grp:::::::::0884A1089616245A3434A61E59FFC6C0A7CE8E60:
uid:u::::1794667539::531F78EF29C64193253D34BEFB1E2049F5A4A492::Test <t@example.invalid>::::::::::0:
ssb:u:255:18:D8936DA9BE6E9ED2:1794667539::::::e:::+::cv25519::
fpr:::::::::072C6325E520F5883F6F4889D8936DA9BE6E9ED2:
grp:::::::::DA8860143E78BEEF72E4C9232E98A0E2C7014E13:
";

    #[test]
    fn expired_revoked_disabled_or_invalid_subkeys_are_skipped() {
        for validity in ["e", "r", "d", "i"] {
            let colons = COLONS.replace("ssb:u:", &format!("ssb:{validity}:"));
            assert!(
                parse_encryption_keygrips(&colons).is_empty(),
                "validity {validity} selected"
            );
        }
    }

    #[test]
    fn unusable_encryption_subkeys_are_skipped() {
        // Same key plus an expired and a revoked encryption subkey (validity
        // `e` / `r` in field 2): only the usable subkey's grip counts.
        let colons = format!(
            "{COLONS}\
ssb:e:255:18:1111111111111111:1700000000:1710000000:::::e:::+::cv25519::
grp:::::::::{GRIP_A}:
ssb:r:255:18:2222222222222222:1700000000::::::e:::+::cv25519::
grp:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:
"
        );
        assert_eq!(parse_encryption_keygrips(&colons), vec![GRIP_B]);
    }

    #[test]
    fn describe_names_the_apps_cli() {
        let cli = "netbox-mcp --config '/x y.json'";
        assert_eq!(
            AgentState::Locked.describe(cli),
            "locked (run `netbox-mcp --config '/x y.json' unlock`)"
        );
        assert!(AgentState::NotRunning.describe(cli).contains(cli));
        assert!(!AgentState::Unlocked.describe(cli).contains("unlock`"));
    }

    #[tokio::test]
    async fn refused_connection_means_not_running() {
        // A socket file nobody listens on (a stale agent socket).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("S.gpg-agent");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        // On macOS a process another test spawns at that moment can inherit
        // the listener (spawn isn't atomic with CLOEXEC there) and keep it
        // accepting until its exec. Let that window pass.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let got = query_socket(&path, &[GRIP_B.into()]).await.unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn only_encryption_subkey_grips_are_selected() {
        // The primary's `scESC` has no lowercase `e`: it can't encrypt itself.
        assert_eq!(parse_encryption_keygrips(COLONS), vec![GRIP_B]);
    }

    #[test]
    fn keyinfo_line_parses() {
        // Captured from a real agent after an unlock.
        let rest = format!("{GRIP_B} D - - 1 P - - -");
        assert_eq!(
            parse_keyinfo(&rest),
            Some(KeyInfo {
                kind: 'D',
                cached: true,
                protection: 'P'
            })
        );
        assert_eq!(parse_keyinfo(GRIP_B), None);
    }

    /// Script an agent on one end of an in-memory duplex.
    async fn run_agent(
        replies: &'static str,
        grips: &[&str],
    ) -> Result<Vec<Option<KeyInfo>>, String> {
        let (client, server) = tokio::io::duplex(4096);
        let (sr, mut sw) = tokio::io::split(server);
        let agent = tokio::spawn(async move {
            let mut lines = BufReader::new(sr).lines();
            let mut replies = replies.split("---\n");
            sw.write_all(b"OK Pleased to meet you, process 1\n")
                .await
                .unwrap();
            let mut seen = Vec::new();
            while let Ok(Some(cmd)) = lines.next_line().await {
                if cmd == "BYE" {
                    break;
                }
                seen.push(cmd);
                sw.write_all(replies.next().unwrap().as_bytes())
                    .await
                    .unwrap();
            }
            seen
        });
        let grips: Vec<String> = grips.iter().map(|g| (*g).to_string()).collect();
        let result = keyinfo(client, &grips).await;
        let seen = agent.await.unwrap();
        if result.is_ok() {
            let want: Vec<String> = grips.iter().map(|g| format!("KEYINFO {g}")).collect();
            assert_eq!(seen, want);
        }
        result
    }

    #[tokio::test]
    async fn keyinfo_exchange_reports_cached_and_missing_keys() {
        let replies = "\
# a comment the client must skip
S KEYINFO DA8860143E78BEEF72E4C9232E98A0E2C7014E13 D - - 1 P - - -
OK
---
ERR 67108891 Not found <GPG Agent>
";
        let infos = run_agent(replies, &[GRIP_B, GRIP_A]).await.unwrap();
        assert_eq!(
            infos,
            vec![
                Some(KeyInfo {
                    kind: 'D',
                    cached: true,
                    protection: 'P'
                }),
                None
            ]
        );
        assert_eq!(summarize(&infos), AgentState::Unlocked);
    }

    #[tokio::test]
    async fn unexpected_agent_error_is_surfaced() {
        let err = run_agent("ERR 67108865 General error\n", &[GRIP_B])
            .await
            .unwrap_err();
        assert!(err.contains("67108865"), "{err}");
    }

    #[tokio::test]
    async fn malformed_keygrip_is_never_sent() {
        let (client, server) = tokio::io::duplex(64);
        let (_r, mut w) = tokio::io::split(server);
        w.write_all(b"OK hi\n").await.unwrap();
        let err = keyinfo(client, &["ABC\nKILLAGENT".into()])
            .await
            .unwrap_err();
        assert!(err.contains("invalid keygrip"), "{err}");
    }

    #[tokio::test]
    async fn absent_socket_means_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let got = query_socket(&dir.path().join("S.gpg-agent"), &[GRIP_B.into()])
            .await
            .unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn summarize_precedence() {
        let k = |kind, cached, protection| {
            Some(KeyInfo {
                kind,
                cached,
                protection,
            })
        };
        assert_eq!(summarize(&[k('D', false, 'P')]), AgentState::Locked);
        assert_eq!(summarize(&[k('D', false, 'C')]), AgentState::Unprotected);
        assert_eq!(summarize(&[k('T', false, '-')]), AgentState::Smartcard);
        assert_eq!(summarize(&[None]), AgentState::NoSecretKey);
        assert_eq!(summarize(&[]), AgentState::NoSecretKey);
        assert_eq!(
            summarize(&[k('D', false, 'P'), k('D', true, 'P')]),
            AgentState::Unlocked
        );
    }

    #[test]
    fn gpgconf_paths_are_unescaped() {
        assert_eq!(
            percent_unescape("/x/a%3ab/S.gpg-agent"),
            "/x/a:b/S.gpg-agent"
        );
    }

    /// A store on the fake gpg/gpgconf whose GnuPG home is a fresh temp dir
    /// (so the fake gpgconf reports `<home>/S.gpg-agent`).
    fn agent_store() -> (tempfile::TempDir, PassStore) {
        let home = tempfile::tempdir().unwrap();
        let store =
            crate::test_support::store(home.path()).with_homedir(Some(home.path().to_path_buf()));
        (home, store)
    }

    /// A key-listing snippet for the fake gpg: pass its path as the
    /// recipient. Exits 2 like a real gpg missing one of several keys.
    fn listing(dir: &Path, colons: &str) -> String {
        snippet(dir, &listing_body(colons))
    }

    fn listing_body(colons: &str) -> String {
        format!("cat <<'EOF'\n{colons}EOF\nexit 2\n")
    }

    /// Write `body` as a snippet for the fake gpg and return its path.
    fn snippet(dir: &Path, body: &str) -> String {
        let path = dir.join("list.sh");
        std::fs::write(&path, body).unwrap();
        path.display().to_string()
    }

    /// A one-connection agent on `socket` answering each `KEYINFO <grip>`
    /// with `reply(grip)`.
    fn serve_agent(
        socket: &Path,
        reply: fn(&str) -> String,
    ) -> tokio::task::JoinHandle<Vec<String>> {
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (r, mut w) = tokio::io::split(stream);
            w.write_all(b"OK Pleased to meet you\n").await.unwrap();
            let mut lines = BufReader::new(r).lines();
            let mut seen = Vec::new();
            while let Ok(Some(cmd)) = lines.next_line().await {
                if cmd == "BYE" {
                    break;
                }
                let grip = cmd.strip_prefix("KEYINFO ").unwrap_or_default().to_string();
                seen.push(cmd);
                w.write_all(reply(&grip).as_bytes()).await.unwrap();
            }
            seen
        })
    }

    #[tokio::test]
    async fn keygrips_are_listed_for_the_recipients_even_when_gpg_fails() {
        let (home, store) = agent_store();
        let seen = home.path().join("seen");
        let recipient = snippet(
            home.path(),
            &format!(
                "echo \"$all\" > '{}'\n{}",
                seen.display(),
                listing_body(COLONS)
            ),
        );
        let grips = encryption_keygrips(&store, std::slice::from_ref(&recipient))
            .await
            .unwrap();
        assert_eq!(grips, vec![GRIP_B]);
        let seen = std::fs::read_to_string(seen).unwrap();
        assert!(
            seen.contains(&format!(
                "--batch --no-tty --with-colons --with-keygrip --list-secret-keys -- {recipient}"
            )),
            "{seen}"
        );
    }

    #[tokio::test]
    async fn no_recipients_never_lists_the_whole_keyring() {
        // A missing gpg would error, so Ok means gpg never ran.
        let dir = tempfile::tempdir().unwrap();
        let store = PassStore::new(
            dir.path(),
            dir.path().join("no-gpg"),
            crate::test_support::branding(),
        );
        assert_eq!(
            encryption_keygrips(&store, &[]).await.unwrap(),
            [] as [std::string::String; 0]
        );
        assert_eq!(state(&store, &[]).await.unwrap(), AgentState::NoSecretKey);
    }

    #[tokio::test]
    async fn missing_gpg_is_an_error_for_status() {
        let dir = tempfile::tempdir().unwrap();
        let store = PassStore::new(
            dir.path(),
            dir.path().join("no-gpg"),
            crate::test_support::branding(),
        );
        let err = encryption_keygrips(&store, &["K".into()])
            .await
            .unwrap_err();
        assert!(err.starts_with("running gpg: "), "{err}");
        let line = crate::agent_status(&store, &["K".into()]).await;
        assert!(line.starts_with("unknown (running gpg: "), "{line}");
    }

    #[tokio::test]
    async fn agent_socket_comes_from_gpgconf_unescaped() {
        let (home, store) = agent_store();
        assert_eq!(
            agent_socket(&store).await.unwrap(),
            home.path().join("S.gpg-agent")
        );
        std::fs::write(
            home.path().join("gpgconf.sh"),
            "echo /run/a%3ab/S.gpg-agent\nexit 0\n",
        )
        .unwrap();
        assert_eq!(
            agent_socket(&store).await.unwrap(),
            PathBuf::from("/run/a:b/S.gpg-agent")
        );
        std::fs::write(home.path().join("gpgconf.sh"), "exit 1\n").unwrap();
        let err = agent_socket(&store).await.unwrap_err();
        assert!(err.contains("gpgconf --list-dirs failed"), "{err}");
    }

    #[tokio::test]
    async fn state_without_an_encryption_key_is_no_secret_key() {
        let (home, store) = agent_store();
        let recipient = listing(home.path(), "");
        assert_eq!(
            state(&store, &[recipient]).await.unwrap(),
            AgentState::NoSecretKey
        );
    }

    #[tokio::test]
    async fn state_without_an_agent_is_not_running() {
        let (home, store) = agent_store();
        let recipient = listing(home.path(), COLONS);
        assert_eq!(
            state(&store, std::slice::from_ref(&recipient))
                .await
                .unwrap(),
            AgentState::NotRunning
        );
        let line = crate::agent_status(&store, &[recipient]).await;
        assert_eq!(
            line,
            "locked (gpg-agent is not running; run `test-mcp unlock`)"
        );
    }

    #[tokio::test]
    async fn state_asks_the_running_agent() {
        let (home, store) = agent_store();
        let recipient = listing(home.path(), COLONS);
        let agent = serve_agent(&home.path().join("S.gpg-agent"), |grip| {
            format!("S KEYINFO {grip} D - - 1 P - - -\nOK\n")
        });
        let line = crate::agent_status(&store, &[recipient]).await;
        assert_eq!(line, "unlocked (passphrase cached in gpg-agent)");
        assert_eq!(agent.await.unwrap(), vec![format!("KEYINFO {GRIP_B}")]);
    }

    #[tokio::test]
    async fn query_socket_reports_uncached_keys_as_locked() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("S.gpg-agent");
        let agent = serve_agent(&socket, |grip| {
            if grip == GRIP_A {
                "ERR 67108891 Not found <GPG Agent>\n".into()
            } else {
                format!("S KEYINFO {grip} D - - - P - - -\nOK\n")
            }
        });
        let infos = query_socket(&socket, &[GRIP_A.into(), GRIP_B.into()])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(infos[0], None);
        assert_eq!(summarize(&infos), AgentState::Locked);
        assert_eq!(agent.await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn greeting_error_is_surfaced() {
        let (client, server) = tokio::io::duplex(64);
        let (_r, mut w) = tokio::io::split(server);
        w.write_all(b"ERR 67108865 General error\n").await.unwrap();
        let err = keyinfo(client, &[GRIP_B.into()]).await.unwrap_err();
        assert!(err.starts_with("agent greeting: "), "{err}");
    }

    #[tokio::test]
    async fn agent_hanging_up_mid_reply_is_an_error() {
        let (client, server) = tokio::io::duplex(256);
        let agent = tokio::spawn(async move {
            let (r, mut w) = tokio::io::split(server);
            w.write_all(b"OK hi\n").await.unwrap();
            let mut lines = BufReader::new(r).lines();
            lines.next_line().await.unwrap();
            // Half a reply, then hang up.
            w.write_all(b"S KEYINFO x D - - 1 P - - -\n").await.unwrap();
        });
        let err = keyinfo(client, &[GRIP_B.into()]).await.unwrap_err();
        assert!(err.contains("closed the connection"), "{err}");
        agent.await.unwrap();
    }

    #[tokio::test]
    async fn err_without_a_numeric_code_is_an_error() {
        let err = run_agent("ERR oops\n", &[GRIP_B]).await.unwrap_err();
        assert!(err.contains("error code 0"), "{err}");
    }

    #[test]
    fn smartcard_keyinfo_parses() {
        let rest = format!("{GRIP_B} T D2760001240100000006 OPENPGP.2 - - - - -");
        let info = parse_keyinfo(&rest).unwrap();
        assert_eq!(info.kind, 'T');
        assert!(!info.cached);
        assert_eq!(summarize(&[Some(info)]), AgentState::Smartcard);
    }

    #[test]
    fn stray_or_empty_grp_records_are_ignored() {
        // A grp with no preceding sec/ssb, and an encryption subkey whose grp
        // has no keygrip field.
        let colons = format!(
            "grp:::::::::{GRIP_A}:\n\
             ssb:u:255:18:D8936DA9BE6E9ED2:1794667539::::::e:::+::cv25519::\n\
             grp:::::::::\n\
             uid:u::::::::x\n"
        );
        assert_eq!(
            parse_encryption_keygrips(&colons),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            parse_encryption_keygrips(""),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn describe_covers_every_state() {
        for state in [
            AgentState::Unlocked,
            AgentState::Unprotected,
            AgentState::Locked,
            AgentState::Smartcard,
            AgentState::NotRunning,
            AgentState::NoSecretKey,
        ] {
            let text = state.describe("x-mcp");
            assert_ne!(text, "");
            let advises = text.contains("`x-mcp unlock`");
            assert_eq!(
                advises,
                matches!(state, AgentState::Locked | AgentState::NotRunning),
                "{state:?}: {text}"
            );
        }
    }

    #[tokio::test]
    async fn agent_hanging_up_after_the_greeting_is_an_error() {
        let (client, server) = tokio::io::duplex(64);
        let (r, mut w) = tokio::io::split(server);
        w.write_all(b"OK hi\n").await.unwrap();
        drop((r, w));
        assert!(keyinfo(client, &[GRIP_B.into()]).await.is_err());
    }
}
