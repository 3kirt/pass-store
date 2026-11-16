//! A pass-backed HTTP auth header, decrypted on first use (cargo feature
//! `http`).
//!
//! Failures are *not* cached: while the GPG key is locked every request fails
//! fast with a [`PassError::Locked`] explaining how to unlock, and the first
//! request after the user unlocks succeeds, with no server restart. Once
//! decrypted the token is held in memory, so gpg-agent's cache TTL no longer
//! matters for the process.
//!
//! When the server rejects the token (by default a 401), the app calls
//! [`LazyToken::retry_value`]: it marks the token stale and re-reads the
//! entry, and when the entry now holds a *different* token (rotated with
//! `login`) it returns it, so the app can retry the request once. If that
//! re-read fails (typically gpg-agent's cache has expired since the first
//! decrypt), the rejected token is kept so the caller sees the server's real
//! auth error rather than a misleading "locked", and gpg isn't run again
//! until a [backoff](LazyToken::with_backoff) has passed.
//!
//! ```ignore
//! // In the app's send(), with reqwest. The header is added per attempt:
//! // `RequestBuilder::header` appends, so it must not go on the shared builder.
//! let sent = token.value().await?;
//! let retry = builder.try_clone();
//! let resp = builder.header(token.header_name(), sent.clone()).send().await?;
//! let (Some(retry), Some(fresh)) = (retry, token.retry_value(resp.status(), &sent).await?)
//! else {
//!     return Ok(resp);
//! };
//! let resp = retry.header(token.header_name(), fresh.clone()).send().await?;
//! if token.is_rejection(resp.status()) {
//!     token.mark_rejected(&fresh).await;
//! }
//! Ok(resp)
//! ```

use std::time::{Duration, Instant};

use http::{HeaderName, HeaderValue, StatusCode};

use crate::{PassEntry, PassError};

/// How long to keep reusing a rejected token after re-reading it failed.
pub const REREAD_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    #[error(transparent)]
    Pass(#[from] PassError),
    #[error(
        "{product} token from pass entry {entry} contains characters not valid in an \
         HTTP header (it must be visible ASCII)"
    )]
    InvalidHeader { product: String, entry: String },
}

type Format = dyn Fn(&str) -> String + Send + Sync;

/// A token decrypted from a pass entry on demand, as a ready header value.
pub struct LazyToken {
    entry: PassEntry,
    header: HeaderName,
    format: Box<Format>,
    rejections: Vec<StatusCode>,
    backoff: Duration,
    // Held across the decrypt so concurrent requests run gpg once, not N times.
    state: tokio::sync::Mutex<State>,
}

#[derive(Default)]
struct State {
    value: Option<HeaderValue>,
    /// The server rejected `value`: re-read the entry before the next
    /// request, in case the token was rotated with `login`.
    stale: bool,
    /// A re-read after a rejection failed: don't run gpg again before this,
    /// so a revoked token with a locked key doesn't put a decrypt in front
    /// of every request.
    retry_at: Option<Instant>,
}

impl std::fmt::Debug for LazyToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the token itself.
        f.debug_struct("LazyToken")
            .field("entry", &self.entry.name())
            .field("header", &self.header)
            .field("rejections", &self.rejections)
            .field("backoff", &self.backoff)
            .finish_non_exhaustive()
    }
}

impl LazyToken {
    /// A token for `entry`, sent as `header: format(token)`, e.g.
    /// `(AUTHORIZATION, |t| format!("PVEAPIToken={t}"))` or
    /// `(HeaderName::from_static("private-token"), str::to_string)`.
    /// A 401 counts as a rejection (see [`Self::rejecting`]), and a failed
    /// re-read backs off for [`REREAD_BACKOFF`].
    pub fn new(
        entry: PassEntry,
        header: HeaderName,
        format: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        Self {
            entry,
            header,
            format: Box::new(format),
            rejections: vec![StatusCode::UNAUTHORIZED],
            backoff: REREAD_BACKOFF,
            state: tokio::sync::Mutex::new(State::default()),
        }
    }

    /// The statuses that mean "this token was rejected" (e.g. NetBox answers
    /// 403 for an invalid token: `&[UNAUTHORIZED, FORBIDDEN]`).
    #[must_use]
    pub fn rejecting(mut self, statuses: &[StatusCode]) -> Self {
        self.rejections = statuses.to_vec();
        self
    }

    /// How long a rejected token is reused, without running gpg, after a
    /// re-read failed.
    #[must_use]
    pub const fn with_backoff(mut self, backoff: Duration) -> Self {
        self.backoff = backoff;
        self
    }

    #[must_use]
    pub const fn header_name(&self) -> &HeaderName {
        &self.header
    }

    #[must_use]
    pub const fn entry(&self) -> &PassEntry {
        &self.entry
    }

    /// Whether `status` means the server rejected the token.
    #[must_use]
    pub fn is_rejection(&self, status: StatusCode) -> bool {
        self.rejections.contains(&status)
    }

    /// The header value to send: the cached one, or a fresh decrypt on first
    /// use and after a rejection.
    ///
    /// # Errors
    ///
    /// When no token has been read yet and the read fails (locked key,
    /// missing entry, …), or the token isn't a valid header value.
    pub async fn value(&self) -> Result<HeaderValue, TokenError> {
        let mut state = self.state.lock().await;
        if let Some(value) = state.value.as_ref()
            && (!state.stale || state.retry_at.is_some_and(|t| Instant::now() < t))
        {
            return Ok(value.clone());
        }
        let result = match (self.entry.read_token().await, state.value.as_ref()) {
            (Ok(token), _) => {
                let value = self.header_value(&token)?;
                tracing::debug!(entry = self.entry.name(), "decrypted token from pass");
                state.value = Some(value.clone());
                state.stale = false;
                state.retry_at = None;
                Ok(value)
            }
            // The re-read after a rejection failed. Keep sending the rejected
            // token so the caller sees the server's real auth error, not a
            // misleading "locked"; re-read again after the backoff.
            (Err(e), Some(old)) => {
                tracing::debug!(error = %e, "re-reading rejected token failed; reusing it");
                let old = old.clone();
                state.retry_at = Some(Instant::now() + self.backoff);
                Ok(old)
            }
            (Err(e), None) => Err(e.into()),
        };
        drop(state);
        result
    }

    /// The server rejected a request sent with `sent`. Mark the token for
    /// re-reading, but only if it's still the current one, so a rejection of
    /// an already-replaced token can't discard its fresh successor.
    pub async fn mark_rejected(&self, sent: &HeaderValue) {
        let mut state = self.state.lock().await;
        if state.value.as_ref() == Some(sent) {
            state.stale = true;
        }
    }

    /// After a response with `status` to a request sent with `sent`: when
    /// `status` is a rejection, mark the token stale and re-read it, and
    /// return the new value if the token changed (retry the request once
    /// with it). `None` means the response stands.
    ///
    /// # Errors
    ///
    /// When the re-read token isn't a valid header value.
    pub async fn retry_value(
        &self,
        status: StatusCode,
        sent: &HeaderValue,
    ) -> Result<Option<HeaderValue>, TokenError> {
        if !self.is_rejection(status) {
            return Ok(None);
        }
        self.mark_rejected(sent).await;
        let fresh = self.value().await?;
        Ok((fresh != *sent).then_some(fresh))
    }

    fn header_value(&self, token: &str) -> Result<HeaderValue, TokenError> {
        let mut value = HeaderValue::from_str(&(self.format)(token)).map_err(|_| {
            TokenError::InvalidHeader {
                product: self.entry.store().branding().product().to_string(),
                entry: self.entry.name().to_string(),
            }
        })?;
        // Keeps the token out of `Debug` output and out of HTTP/2 HPACK
        // dynamic tables (where header values could otherwise be inferred).
        value.set_sensitive(true);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use http::header::AUTHORIZATION;

    use super::*;
    use crate::test_support::{LOCKED_SNIPPET, ok_snippet, store};

    const OLD: &str = "root@pam!mcp=old-secret";
    const NEW: &str = "root@pam!mcp=rotated-secret";

    fn token(dir: &Path) -> (PathBuf, LazyToken) {
        let entry = store(dir).entry("t").unwrap();
        let file = entry.path();
        let token = LazyToken::new(entry, AUTHORIZATION, |t| format!("PVEAPIToken={t}"));
        (file, token)
    }

    fn hv(token: &str) -> HeaderValue {
        HeaderValue::from_str(&format!("PVEAPIToken={token}")).unwrap()
    }

    /// A "ciphertext" that appends a line to `counter` on every decrypt.
    fn counting(counter: &Path, snippet: &str) -> String {
        format!("echo x >> '{}'\n{snippet}", counter.display())
    }

    fn runs(counter: &Path) -> usize {
        std::fs::read_to_string(counter).map_or(0, |s| s.lines().count())
    }

    #[tokio::test]
    async fn locked_key_fails_then_succeeds_after_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());

        std::fs::write(&file, LOCKED_SNIPPET).unwrap();
        let err = token.value().await.unwrap_err();
        assert!(
            matches!(err, TokenError::Pass(PassError::Locked { .. })),
            "{err}"
        );
        assert!(err.to_string().contains("test-mcp unlock"), "{err}");

        // "Unlock": the next request decrypts successfully, no restart.
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        let value = token.value().await.unwrap();
        assert_eq!(value, hv(OLD));
        assert!(value.is_sensitive());

        // Cached in memory: re-locking the key doesn't affect this process.
        std::fs::write(&file, LOCKED_SNIPPET).unwrap();
        assert_eq!(token.value().await.unwrap(), hv(OLD));
    }

    #[tokio::test]
    async fn rejection_rereads_and_returns_a_rotated_token() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        let sent = token.value().await.unwrap();

        // Rotated in the store (e.g. via `login`).
        std::fs::write(&file, ok_snippet(NEW)).unwrap();
        // A non-rejection leaves the cached token alone.
        assert_eq!(
            token.retry_value(StatusCode::OK, &sent).await.unwrap(),
            None
        );
        assert_eq!(token.value().await.unwrap(), hv(OLD));

        let fresh = token
            .retry_value(StatusCode::UNAUTHORIZED, &sent)
            .await
            .unwrap();
        assert_eq!(fresh, Some(hv(NEW)));
        assert_eq!(token.value().await.unwrap(), hv(NEW));
    }

    #[tokio::test]
    async fn rejection_of_an_unchanged_token_stands() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        let sent = token.value().await.unwrap();
        let fresh = token
            .retry_value(StatusCode::UNAUTHORIZED, &sent)
            .await
            .unwrap();
        assert_eq!(fresh, None);
    }

    #[tokio::test]
    async fn rejected_token_with_locked_key_keeps_the_real_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        let sent = token.value().await.unwrap();

        // gpg-agent's cache expires; the 401 must not turn into "locked".
        std::fs::write(&file, LOCKED_SNIPPET).unwrap();
        let fresh = token
            .retry_value(StatusCode::UNAUTHORIZED, &sent)
            .await
            .unwrap();
        assert_eq!(fresh, None, "no retry: the caller sees the real 401");
        assert_eq!(token.value().await.unwrap(), hv(OLD));
    }

    #[tokio::test]
    async fn failed_reread_backs_off_instead_of_decrypting_per_request() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        let sent = token.value().await.unwrap();

        // Locked from now on; count every decrypt attempt.
        let counter = dir.path().join("decrypts");
        std::fs::write(&file, counting(&counter, LOCKED_SNIPPET)).unwrap();
        for _ in 0..4 {
            // Each request is rejected again with the same token.
            let fresh = token
                .retry_value(StatusCode::UNAUTHORIZED, &sent)
                .await
                .unwrap();
            assert_eq!(fresh, None);
        }
        assert_eq!(
            runs(&counter),
            1,
            "gpg ran more than once within the backoff"
        );
    }

    #[tokio::test]
    async fn failed_reread_is_retried_after_the_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        let token = token.with_backoff(Duration::ZERO);
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        let sent = token.value().await.unwrap();

        let counter = dir.path().join("decrypts");
        std::fs::write(&file, counting(&counter, LOCKED_SNIPPET)).unwrap();
        for _ in 0..3 {
            assert_eq!(
                token
                    .retry_value(StatusCode::UNAUTHORIZED, &sent)
                    .await
                    .unwrap(),
                None
            );
        }
        assert_eq!(runs(&counter), 3);

        // Unlocked and rotated: picked up at the next re-read.
        std::fs::write(&file, ok_snippet(NEW)).unwrap();
        assert_eq!(token.value().await.unwrap(), hv(NEW));
    }

    #[tokio::test]
    async fn stale_rejection_cannot_discard_a_fresh_token() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        let old = token.value().await.unwrap();
        std::fs::write(&file, ok_snippet(NEW)).unwrap();
        let new = token
            .retry_value(StatusCode::UNAUTHORIZED, &old)
            .await
            .unwrap()
            .unwrap();

        // A late 401 for a request that was still in flight with the old
        // token must not mark the new one stale.
        let counter = dir.path().join("decrypts");
        std::fs::write(&file, counting(&counter, &ok_snippet(NEW))).unwrap();
        token.mark_rejected(&old).await;
        assert_eq!(token.value().await.unwrap(), new);
        assert_eq!(runs(&counter), 0, "re-read after a stale rejection");
    }

    #[tokio::test]
    async fn concurrent_first_requests_decrypt_once() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        let counter = dir.path().join("decrypts");
        std::fs::write(&file, counting(&counter, &ok_snippet(OLD))).unwrap();
        let token = Arc::new(token);
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let token = Arc::clone(&token);
                tokio::spawn(async move { token.value().await })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap().unwrap(), hv(OLD));
        }
        assert_eq!(runs(&counter), 1, "gpg ran more than once");
    }

    #[tokio::test]
    async fn rejection_statuses_are_configurable() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        assert!(token.is_rejection(StatusCode::UNAUTHORIZED));
        assert!(!token.is_rejection(StatusCode::FORBIDDEN));

        // NetBox answers 403 for an invalid token.
        let token = token.rejecting(&[StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN]);
        let sent = token.value().await.unwrap();
        std::fs::write(&file, ok_snippet(NEW)).unwrap();
        let fresh = token
            .retry_value(StatusCode::FORBIDDEN, &sent)
            .await
            .unwrap();
        assert_eq!(fresh, Some(hv(NEW)));
    }

    #[tokio::test]
    async fn token_that_is_not_a_header_value_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let entry = store(dir.path()).entry("t").unwrap();
        std::fs::write(entry.path(), ok_snippet("tok\u{7f}x")).unwrap();
        let token = LazyToken::new(entry, AUTHORIZATION, |t| format!("Token {t}"));
        let err = token.value().await.unwrap_err();
        assert!(matches!(err, TokenError::InvalidHeader { .. }), "{err}");
        assert!(err.to_string().starts_with("Test token"), "{err}");
        assert!(!err.to_string().contains("tok\u{7f}"), "{err}");
    }

    #[tokio::test]
    async fn debug_never_shows_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        token.value().await.unwrap();
        let debug = format!("{token:?}");
        assert!(!debug.contains("old-secret"), "{debug}");
    }

    #[tokio::test]
    async fn rejection_before_any_read_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        token.mark_rejected(&hv(OLD)).await;
        let counter = dir.path().join("decrypts");
        std::fs::write(&file, counting(&counter, &ok_snippet(OLD))).unwrap();
        assert_eq!(token.value().await.unwrap(), hv(OLD));
        assert_eq!(token.value().await.unwrap(), hv(OLD));
        assert_eq!(runs(&counter), 1);
    }

    #[tokio::test]
    async fn rotated_token_that_is_not_a_header_value_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        let sent = token.value().await.unwrap();
        std::fs::write(&file, ok_snippet("bad\u{1}token")).unwrap();
        let err = token
            .retry_value(StatusCode::UNAUTHORIZED, &sent)
            .await
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidHeader { .. }), "{err}");
    }

    #[tokio::test]
    async fn backoff_holds_then_expires() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        let token = token.with_backoff(Duration::from_millis(300));
        std::fs::write(&file, ok_snippet(OLD)).unwrap();
        let sent = token.value().await.unwrap();
        let counter = dir.path().join("decrypts");
        std::fs::write(&file, counting(&counter, LOCKED_SNIPPET)).unwrap();

        token.mark_rejected(&sent).await;
        assert_eq!(token.value().await.unwrap(), sent);
        assert_eq!(runs(&counter), 1);
        // Inside the window: the old token, no gpg run.
        assert_eq!(token.value().await.unwrap(), sent);
        assert_eq!(runs(&counter), 1);
        tokio::time::sleep(Duration::from_millis(400)).await;
        // Window over and still stale: re-read (fails again, old token kept).
        assert_eq!(token.value().await.unwrap(), sent);
        assert_eq!(runs(&counter), 2);
    }

    #[tokio::test]
    async fn default_backoff_and_accessors() {
        let dir = tempfile::tempdir().unwrap();
        let (_file, token) = token(dir.path());
        assert_eq!(REREAD_BACKOFF, Duration::from_secs(30));
        assert_eq!(token.header_name(), AUTHORIZATION);
        assert_eq!(token.entry().name(), "t");
        let debug = format!("{token:?}");
        assert!(debug.contains("backoff: 30s"), "{debug}");
    }

    #[tokio::test]
    async fn pass_errors_pass_through_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let (file, token) = token(dir.path());
        let missing = token.value().await.unwrap_err();
        assert!(matches!(
            missing,
            TokenError::Pass(PassError::NotFound { .. })
        ));
        let direct = token.entry().read_token().await.unwrap_err();
        assert_eq!(missing.to_string(), direct.to_string());
        drop(file);
    }
}
