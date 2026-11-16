//! The crate as an app sees it: only public items, through the features the
//! apps enable (`http` for the server, `test-support` for their tests).

#![cfg(all(unix, feature = "http", feature = "test-support"))]

use std::path::Path;

use http::{HeaderName, StatusCode};
use pass_store::test_support::{LOCKED_SNIPPET, NO_SECKEY_SNIPPET, fake_gpg, ok_snippet};
use pass_store::{Branding, LazyToken, PassError, PassStore, StoreEnv, StoreLocation, TokenError};

fn branding(config: Option<&Path>) -> Branding {
    Branding::new(
        "Example",
        Branding::cli_prefix("example-mcp", "--config", config),
    )
}

fn store(root: &Path, config: Option<&Path>) -> PassStore {
    let root = root.to_str().unwrap();
    let gpg = fake_gpg().to_str().unwrap();
    // An app's tests build the environment instead of changing the process's.
    let env = StoreEnv {
        home: Some("/home/example".into()),
        ..StoreEnv::default()
    };
    PassStore::resolve(
        &StoreLocation {
            gpg: Some(gpg),
            store_dir: Some(root),
            gnupg_home: None,
        },
        &env,
        branding(config),
    )
    .unwrap()
}

#[tokio::test]
async fn login_then_read_then_logout() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path(), None);
    store.init("KEYID").unwrap();
    let entry = store.entry("example-mcp/host.example.com").unwrap();
    let recipients = entry.recipients().unwrap().unwrap();
    assert_eq!(recipients, vec!["KEYID"]);

    entry.write_token("tok-1", &recipients).await.unwrap();
    assert!(entry.path().is_file());

    // The fake can't decrypt its own "ciphertext": stand in for gpg.
    std::fs::write(entry.path(), ok_snippet("tok-1")).unwrap();
    assert_eq!(entry.read_token().await.unwrap(), "tok-1");

    entry.remove().unwrap();
    let err = entry.read_token().await.unwrap_err();
    assert!(matches!(err, PassError::NotFound { .. }));
    assert!(err.to_string().contains("run `example-mcp login`"), "{err}");
}

#[tokio::test]
async fn errors_carry_the_apps_advice() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path(), Some(Path::new("/etc/example mcp.json")));
    let entry = store.entry("t").unwrap();
    std::fs::write(entry.path(), LOCKED_SNIPPET).unwrap();
    let msg = entry.read_token().await.unwrap_err().to_string();
    assert!(msg.starts_with("Example token is locked"), "{msg}");
    assert!(
        msg.contains("`example-mcp --config '/etc/example mcp.json' unlock`"),
        "{msg}"
    );
    std::fs::write(entry.path(), NO_SECKEY_SNIPPET).unwrap();
    assert!(matches!(
        entry.read_token().await,
        Err(PassError::NoSecretKey { .. })
    ));
}

#[tokio::test]
async fn lazy_token_with_an_app_header() {
    let dir = tempfile::tempdir().unwrap();
    let entry = store(dir.path(), None).entry("t").unwrap();
    std::fs::write(entry.path(), ok_snippet("glpat-old")).unwrap();
    let token = LazyToken::new(
        entry.clone(),
        HeaderName::from_static("private-token"),
        std::string::ToString::to_string,
    );
    let sent = token.value().await.unwrap();
    assert_eq!(sent, "glpat-old");

    std::fs::write(entry.path(), ok_snippet("glpat-new")).unwrap();
    let fresh = token
        .retry_value(StatusCode::UNAUTHORIZED, &sent)
        .await
        .unwrap();
    assert_eq!(fresh.unwrap(), "glpat-new");

    let err: TokenError = LazyToken::new(
        store(dir.path(), None).entry("missing").unwrap(),
        HeaderName::from_static("authorization"),
        |t| format!("Token {t}"),
    )
    .value()
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no Example token stored"), "{err}");
}

#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn env_helpers_are_public() {
    assert!(pass_store::is_unexpanded_placeholder("${EXAMPLE_TOKEN}"));
    assert_eq!(pass_store::non_blank(Some("  ".into())), None);
    assert_eq!(
        pass_store::env_var("PASS_STORE_SURELY_UNSET_VARIABLE"),
        None
    );
    assert!(pass_store::is_unset_value(" ${EXAMPLE_TOKEN:-} "));
    assert_eq!(pass_store::shell_quote("a b"), "'a b'");
    let mut env = pass_store::test_support::EnvGuard::new();
    env.set("HOME", "/home/example");
    assert_eq!(pass_store::home_dir().unwrap(), Path::new("/home/example"));
    assert_eq!(
        pass_store::expand_tilde("~/x").unwrap(),
        Path::new("/home/example/x")
    );
    assert_eq!(
        StoreEnv::from_process().home.unwrap(),
        Path::new("/home/example")
    );
    assert_eq!(
        pass_store::expand_tilde_in("~/y", Some(Path::new("/h"))).unwrap(),
        Path::new("/h/y")
    );
}

#[tokio::test]
async fn agent_status_is_one_line() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path(), None).with_homedir(Some(dir.path().into()));
    let list = dir.path().join("list.sh");
    std::fs::write(&list, "exit 2\n").unwrap();
    let line = pass_store::agent_status(&store, &[list.display().to_string()]).await;
    assert_eq!(
        line,
        "no secret key for the store's recipients in this keyring"
    );
}
