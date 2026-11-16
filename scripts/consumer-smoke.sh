#!/bin/sh
# Builds and tests a throwaway crate that depends on pass-store the way the
# apps do: a git dependency with a `version`, the `http` feature, and
# `test-support` for its tests.
#
#   consumer-smoke.sh                  # this repo's HEAD commit, via file://
#   consumer-smoke.sh <git-url> <tag>  # e.g. the GitHub repo at a release tag
#
# Only committed files are reachable through git, so a file that works in
# the work tree but was never committed fails here.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
url=${1:-file://$here}
if [ $# -ge 2 ]; then
  ref="tag = \"$2\""
else
  ref="rev = \"$(git -C "$here" rev-parse HEAD)\""
  if [ -n "$(git -C "$here" status --porcelain)" ]; then
    echo "consumer-smoke: note: testing HEAD; uncommitted changes are not included" >&2
  fi
fi
version=$(sed -n 's/^version *= *"\([0-9]*\.[0-9]*\)\..*"/\1/p' "$here/Cargo.toml" | head -1)
toolchain=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$here/rust-toolchain.toml")

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/src" "$tmp/tests"
dep="version = \"$version\", git = \"$url\", $ref"

cat > "$tmp/Cargo.toml" <<TOML
[package]
name = "pass-store-consumer-smoke"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
pass-store = { $dep, features = ["http"] }
http = "1"

[dev-dependencies]
pass-store = { $dep, features = ["test-support"] }
tempfile = "3"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
TOML

# LazyToken must accept the app's own `http` types (the apps get them
# through reqwest).
cat > "$tmp/src/main.rs" <<'RUST'
fn main() {
    let store = pass_store::PassStore::new(
        "/nonexistent",
        "gpg",
        pass_store::Branding::new("Smoke", "smoke-mcp"),
    );
    let entry = store.entry("smoke/host").expect("valid entry name");
    let _token = pass_store::LazyToken::new(entry, http::header::AUTHORIZATION, |t| {
        format!("Token {t}")
    });
}
RUST

cat > "$tmp/tests/smoke.rs" <<'RUST'
use pass_store::test_support::{LOCKED_SNIPPET, fake_gpg, ok_snippet};
use pass_store::{Branding, PassError, PassStore};

#[tokio::test]
async fn reads_a_token_through_the_fake_gpg() {
    let dir = tempfile::tempdir().unwrap();
    let store = PassStore::new(dir.path(), fake_gpg(), Branding::new("Smoke", "smoke-mcp"));
    let entry = store.entry("t").unwrap();
    std::fs::write(entry.path(), ok_snippet("tok")).unwrap();
    assert_eq!(entry.read_token().await.unwrap(), "tok");
    std::fs::write(entry.path(), LOCKED_SNIPPET).unwrap();
    let err = entry.read_token().await.unwrap_err();
    assert!(matches!(err, PassError::Locked { .. }), "{err}");
    assert!(err.to_string().contains("`smoke-mcp unlock`"), "{err}");
}
RUST

echo "consumer-smoke: pass-store = { $dep }"
cd "$tmp"
RUSTUP_TOOLCHAIN=$toolchain CARGO_TARGET_DIR="$tmp/target" cargo test --quiet
echo "consumer-smoke: ok"
