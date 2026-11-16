#!/bin/sh
# Tests scripts/changelog-section.sh (which release.yml uses for the tag
# check and the release notes) and checks CHANGELOG.md's shape: an
# `## [Unreleased]` section first, then `## [X.Y.Z] - YYYY-MM-DD` headings.
set -eu
here=$(dirname "$0")
section="$here/changelog-section.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "$tmp/CHANGELOG.md" <<'MD'
# Changelog

## [Unreleased]

## [0.2.0] - 2026-12-01

### Fixed
- Second.

## [0.1.10] - 2026-11-20

## [0.1.1] - 2026-11-15

### Added
- First.
MD

got=$(CHANGELOG="$tmp/CHANGELOG.md" "$section" 0.2.0)
want=$(printf '### Fixed\n- Second.')
[ "$got" = "$want" ] || fail "0.2.0 section: got <$got>"

got=$(CHANGELOG="$tmp/CHANGELOG.md" "$section" 0.1.1)
want=$(printf '### Added\n- First.')
[ "$got" = "$want" ] || fail "0.1.1 section (last in file): got <$got>"

# 0.1.1 must not match the 0.1.10 heading, and an empty section fails.
if CHANGELOG="$tmp/CHANGELOG.md" "$section" 0.1.10 >/dev/null 2>&1; then
  fail "empty 0.1.10 section accepted"
fi
if CHANGELOG="$tmp/CHANGELOG.md" "$section" 9.9.9 >/dev/null 2>&1; then
  fail "missing section accepted"
fi
if "$section" >/dev/null 2>&1; then
  fail "no version argument accepted"
fi

# The real CHANGELOG.md.
log="$here/../CHANGELOG.md"
first=$(grep -m1 '^## ' "$log")
[ "$first" = "## [Unreleased]" ] || fail "first CHANGELOG section is <$first>, not ## [Unreleased]"
bad=$(grep '^## ' "$log" | grep -v '^## \[Unreleased\]$' |
  grep -vE '^## \[[0-9]+\.[0-9]+\.[0-9]+\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$' || true)
[ -z "$bad" ] || fail "malformed CHANGELOG headings: $bad"

echo "changelog tests: ok"
