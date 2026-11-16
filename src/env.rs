//! The one "is this value set?" rule for env vars and config values, shared
//! by the store and by the apps' own config loading.
//!
//! Blank counts as unset, and so does an unexpanded `${VAR}` placeholder.
//! MCP clients substitute `${GITLAB_TOKEN}`-style placeholders in a shared
//! config from the user's environment, and when the variable isn't exported
//! Claude Code passes the placeholder through *literally*. Taking that as a
//! real token would shadow a `pass_entry` and fail every call with a 401;
//! treating it as unset falls through to the config file, as an empty value
//! does.

use std::path::{Path, PathBuf};

/// `v` unless it is blank or an unexpanded `${…}` placeholder.
#[must_use]
pub fn non_blank(v: Option<String>) -> Option<String> {
    v.filter(|s| !is_unset_value(s))
}

/// Whether `s` (trimmed) is blank or an unexpanded `${…}` placeholder.
#[must_use]
pub fn is_unset_value(s: &str) -> bool {
    let t = s.trim();
    t.is_empty() || is_unexpanded_placeholder(t)
}

/// `${NAME}` or `${NAME:-…}` exactly, as left behind by a client that didn't
/// substitute it. No real token or URL has this shape.
#[must_use]
pub fn is_unexpanded_placeholder(t: &str) -> bool {
    t.strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .is_some_and(|inner| {
            let name = inner.split_once(":-").map_or(inner, |(n, _)| n);
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// An environment variable, treating blank values and unexpanded `${…}`
/// placeholders as unset (see [`non_blank`]).
///
/// A placeholder is logged as a warning, since it means the MCP client's
/// config references a variable its environment lacks.
#[must_use]
pub fn env_var(name: &str) -> Option<String> {
    let raw = std::env::var(name).ok()?;
    if is_unexpanded_placeholder(raw.trim()) {
        tracing::warn!(
            variable = name,
            "ignoring unexpanded placeholder (the MCP client did not substitute it; \
             the variable is not set in its environment)"
        );
        return None;
    }
    non_blank(Some(raw))
}

/// `$HOME`, else `%USERPROFILE%`; an empty value counts as unset.
///
/// # Errors
///
/// [`std::io::ErrorKind::NotFound`] when neither variable is set.
pub fn home_dir() -> std::io::Result<PathBuf> {
    let set = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    set("HOME")
        .or_else(|| set("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(no_home)
}

/// Expand a leading `~/` (config values are often hand-written that way)
/// against [`home_dir`].
///
/// # Errors
///
/// When the path starts with `~` and [`home_dir`] fails.
pub fn expand_tilde(path: &str) -> std::io::Result<PathBuf> {
    expand_tilde_in(path, home_dir().ok().as_deref())
}

/// Expand a leading `~/` against `home` (`None` = unknown).
///
/// # Errors
///
/// When the path starts with `~` and `home` is `None`.
pub fn expand_tilde_in(path: &str, home: Option<&Path>) -> std::io::Result<PathBuf> {
    let home = || home.map(Path::to_path_buf).ok_or_else(no_home);
    match path.strip_prefix("~/") {
        Some(rest) => Ok(home()?.join(rest)),
        None if path == "~" => home(),
        None => Ok(PathBuf::from(path)),
    }
}

fn no_home() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "cannot determine home directory (HOME is not set)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{EnvGuard, lock_env};

    #[test]
    // `${X:-}` etc. are shell-style placeholders under test, not format args.
    #[allow(clippy::literal_string_with_formatting_args)]
    fn unexpanded_placeholders_are_recognised() {
        for p in [
            "${GITLAB_TOKEN}",
            "${GITLAB_URL:-https://gitlab.com}",
            "${A_1}",
            "${X:-}",
        ] {
            assert!(is_unexpanded_placeholder(p), "{p}");
        }
        for v in [
            "glpat-abc",
            "https://gitlab.com",
            "${}",
            "$GITLAB_TOKEN",
            "${GITLAB_TOKEN",
            "x${GITLAB_TOKEN}",
            "${not valid}",
        ] {
            assert!(!is_unexpanded_placeholder(v), "{v}");
        }
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn non_blank_drops_blank_and_placeholders() {
        assert_eq!(non_blank(None), None);
        assert_eq!(non_blank(Some(String::new())), None);
        assert_eq!(non_blank(Some("  \t".into())), None);
        assert_eq!(non_blank(Some(" ${TOKEN} ".into())), None);
        assert_eq!(non_blank(Some("tok".into())), Some("tok".into()));
        // The value itself is kept untrimmed: only the test trims.
        assert_eq!(non_blank(Some(" tok ".into())), Some(" tok ".into()));
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn env_var_treats_placeholders_and_blanks_as_unset() {
        const VAR: &str = "PASS_STORE_TEST_ENV_VAR";
        let mut env = EnvGuard::new();
        let cases = [
            ("${PASS_STORE_TEST_ENV_VAR}", None),
            ("${PASS_STORE_TEST_ENV_VAR:-x}", None),
            ("   ", None),
            ("value", Some("value")),
        ];
        for (raw, want) in cases {
            env.set(VAR, raw);
            assert_eq!(env_var(VAR).as_deref(), want, "{raw:?}");
        }
        env.remove(VAR);
        assert_eq!(env_var(VAR), None);
    }

    #[test]
    fn tilde_expands_to_home() {
        let _guard = lock_env();
        let home = home_dir().unwrap();
        assert_eq!(
            expand_tilde("~/.password-store").unwrap(),
            home.join(".password-store")
        );
        assert_eq!(expand_tilde("~").unwrap(), home);
        assert_eq!(expand_tilde("/abs").unwrap(), PathBuf::from("/abs"));
        assert_eq!(expand_tilde("a/~/b").unwrap(), PathBuf::from("a/~/b"));
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn unset_values() {
        for v in ["", " ", "\t\n", "${X}", " ${X:-y} "] {
            assert!(is_unset_value(v), "{v:?}");
        }
        for v in ["x", " x ", "${X} y", "$X"] {
            assert!(!is_unset_value(v), "{v:?}");
        }
    }

    #[test]
    fn home_dir_falls_back_to_userprofile_and_ignores_empty() {
        let mut env = EnvGuard::new();
        env.remove("HOME").set("USERPROFILE", "/profile");
        assert_eq!(home_dir().unwrap(), PathBuf::from("/profile"));
        // An empty HOME counts as unset, so USERPROFILE still applies.
        env.set("HOME", "");
        assert_eq!(home_dir().unwrap(), PathBuf::from("/profile"));
        env.set("USERPROFILE", "");
        assert_eq!(home_dir().unwrap_err().kind(), std::io::ErrorKind::NotFound);
        assert!(expand_tilde("~/x").is_err());
        // A path without `~` never needs the home directory.
        assert_eq!(expand_tilde("/abs").unwrap(), PathBuf::from("/abs"));
    }

    #[test]
    fn only_a_leading_tilde_slash_expands() {
        let _guard = lock_env();
        // `~user` is shell syntax this crate doesn't resolve: taken literally.
        assert_eq!(expand_tilde("~user/x").unwrap(), PathBuf::from("~user/x"));
        assert_eq!(expand_tilde("./~").unwrap(), PathBuf::from("./~"));
    }

    /// Counts WARN events naming a `variable` field.
    #[derive(Default)]
    struct Warnings(std::sync::Mutex<Vec<String>>);

    impl tracing::Subscriber for Warnings {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Var(Option<String>);
            impl tracing::field::Visit for Var {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "variable" {
                        self.0 = Some(value.to_string());
                    }
                }
                fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
            }
            if *event.metadata().level() == tracing::Level::WARN {
                let mut var = Var(None);
                event.record(&mut var);
                if let Some(v) = var.0 {
                    self.0.lock().unwrap().push(v);
                }
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn a_placeholder_warns_but_a_blank_does_not() {
        const VAR: &str = "PASS_STORE_TEST_WARN_VAR";
        let mut env = EnvGuard::new();
        let warnings = std::sync::Arc::new(Warnings::default());
        let mut read = |raw: &str| {
            env.set(VAR, raw);
            tracing::subscriber::with_default(warnings.clone(), || env_var(VAR))
        };
        assert_eq!(read("${PASS_STORE_TEST_WARN_VAR}"), None);
        assert_eq!(read("   "), None);
        assert_eq!(read("set"), Some("set".into()));
        assert_eq!(*warnings.0.lock().unwrap(), vec![VAR.to_string()]);
    }

    #[test]
    fn expand_tilde_in_uses_the_given_home_only() {
        let home = Path::new("/home/me");
        assert_eq!(
            expand_tilde_in("~/x", Some(home)).unwrap(),
            PathBuf::from("/home/me/x")
        );
        assert_eq!(
            expand_tilde_in("~", Some(home)).unwrap(),
            PathBuf::from("/home/me")
        );
        assert_eq!(
            expand_tilde_in("/abs", None).unwrap(),
            PathBuf::from("/abs")
        );
        assert_eq!(
            expand_tilde_in("~/x", None).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
}
