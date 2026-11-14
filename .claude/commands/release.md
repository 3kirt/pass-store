Release pass-store to crates.io by bumping the version, verifying the build, and tagging.

This follows the same step list as gitlab-mcp, netbox-mcp and proxmox-mcp,
adapted for a library published to crates.io instead of release binaries.
Release from `main`: the release workflow refuses a tag that isn't on it.

## Steps

### 1. Determine the new version

Read `Cargo.toml` and extract the current `version` field. This is a library
the three apps depend on, so choose the bump by SemVer for 0.x crates: a
breaking API change bumps the minor version (`0.1.3` → `0.2.0`); anything else
bumps the patch (`0.1.3` → `0.1.4`). Check `git diff v<previous>..HEAD -- src`
for changes to public items, and say which bump you picked and why. If the user
supplied a version as an argument to this command, use that instead.

### 2. Update Cargo.toml

Change the `version` field in `Cargo.toml` to the new version string.

### 3. Update Cargo.lock

Run `cargo build` (without `--locked`) so Cargo rewrites `Cargo.lock` to match
the new version. This is the only step that runs without `--locked`.

```
cargo build
```

### 4. Audit dependencies

```
make deny
cargo outdated
```

**Security (`make deny`):** If cargo-deny reports a vulnerability advisory, a
banned crate (aws-lc-sys/aws-lc-rs), or a license that isn't allowed, stop
immediately and report it to the user. Do not proceed until it is resolved. Never
add a license to `deny.toml` without checking with the user that it is
GPL-3.0-compatible.

**Outdated dependencies (`cargo outdated`):** Report the results to the user.
Focus on direct dependencies listed in `Cargo.toml`. If any are behind, ask the
user whether to update them before continuing; transitive-only updates are
informational.

If `cargo deny` or `cargo outdated` are not installed, install them first:

```
cargo install --locked cargo-deny cargo-outdated
```

### 5. Check the pinned toolchain

The toolchain is pinned in `rust-toolchain.toml`. Compare it with the latest
stable (`rustup check`). If a newer stable exists, tell the user and offer to
bump the `channel` first. If they agree, update the pin, fix any new clippy
findings, and commit that separately before continuing.

### 6. Run the full quality gate

```
make check
make msrv
make test-real-gpg
```

`make check` runs fmt-check, lint (secrets scan, clippy over every feature set,
fmt), test (default and all features), deny, and `cargo package`. It needs a
clean work tree; before committing, use `make check PACKAGE_FLAGS=--allow-dirty`.
If anything fails, stop and report the error; do not proceed to tagging. If
only formatting fails, run `make fmt` and re-run.

### 7. Update CHANGELOG.md

Read `CHANGELOG.md`. This project keeps an `[Unreleased]` section near the top.

Derive the release content from two sources and merge them:
- The existing `[Unreleased]` section, if it has any entries.
- The git log since the previous release tag:

  ```
  git log v<previous version>..HEAD --oneline
  ```

Rename the `[Unreleased]` heading to `## [<new version>] - <today's date>`
(an ASCII hyphen, today's actual date, `YYYY-MM-DD`). Fold in anything from the
git log that isn't already listed, then add a fresh, empty `## [Unreleased]`
section above it.

Group entries into the standard changelog categories (Added, Changed, Fixed,
Removed, Security, Documentation, Internal), and omit any category with no
entries. Call out breaking API changes first, with what an app must change.
Exclude housekeeping commits such as version bumps and `cargo fmt` runs. The
release workflow publishes this section as the release notes, so confirm it
extracts:

```
scripts/changelog-section.sh <new version>
```

### 8. Commit the version bump and changelog

```
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "Bump version to <new version>"
```

### 9. Tag the release

```
git tag -a v<new version> -m v<new version>
```

### 10. Confirm before pushing

Show the user the new version, the commit SHA, and the tag, then ask whether to
push. Publishing to crates.io is permanent: a version can be yanked but never
replaced or deleted. Pushing the tag triggers `.github/workflows/release.yml`,
which verifies the tag, runs the full CI, runs `cargo publish` (with the
`CARGO_REGISTRY_TOKEN` secret), and creates the GitHub release with the
`.crate`, its checksum and a provenance attestation. If they confirm, run:

```
git push origin main v<new version>
```

### 11. Verify the release

1. Watch the Release run until it finishes, and report each job's result:

   ```
   gh run watch <run-id> --exit-status
   ```

2. Confirm crates.io serves the new version:

   ```
   cargo info pass-store@<new version>
   ```

3. Download the release's `.crate` and `checksums.txt` into the scratchpad,
   verify the sha256 (`shasum -a 256 -c`) and the provenance:

   ```
   gh attestation verify pass-store-<new version>.crate --repo 3kirt/pass-store
   ```

4. Offer to bump `pass-store` in gitlab-mcp, netbox-mcp and proxmox-mcp, one
   PR per repo, each running its own `make check`.
