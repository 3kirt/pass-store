Release pass-store to crates.io by bumping the version, verifying the build, and tagging.

This follows the same step list as gitlab-mcp, netbox-mcp and proxmox-mcp,
adapted for a library: what ships is the `.crate` on crates.io, not release
binaries, and publishing is permanent (a version can be yanked, never
replaced). Release from `main`: the release workflow refuses a tag that
isn't on it.

## Steps

### 1. Pre-flight

Stop and report if any of these fails; each would otherwise surface only
after the tag is pushed.

```
git switch main && git pull --ff-only
git status --porcelain            # must print nothing
gh secret list | grep CARGO_REGISTRY_TOKEN
```

- The work tree must be clean and `main` up to date with `origin/main`.
- `CARGO_REGISTRY_TOKEN` must be a repository secret: `release.yml`'s
  `cargo publish` needs it. If it's missing, ask the user to add a crates.io
  API token scoped to publishing `pass-store` (`gh secret set
  CARGO_REGISTRY_TOKEN`); never ask them to paste the token into the chat.
- The latest CI run on `main` passed:
  `gh run list --workflow ci.yml --branch main --limit 1`.

### 2. Determine the new version

Read `Cargo.toml` and extract the current `version` field. This is a library
the three apps depend on, so choose the bump by SemVer for 0.x crates: a
breaking API change bumps the minor version (`0.1.3` → `0.2.0`); anything else
bumps the patch (`0.1.3` → `0.1.4`). Check `git diff v<previous>..HEAD -- src`
for changes to public items, and say which bump you picked and why. If the user
supplied a version as an argument to this command, use that instead. On the
first release there is no previous tag: release the current `0.1.0`.

Confirm that version isn't on crates.io yet (`cargo info pass-store@<new
version>` must fail; on the first release, `cargo info pass-store` fails too).

### 3. Update Cargo.toml and Cargo.lock

Change the `version` field in `Cargo.toml` to the new version string, then
run `cargo build` (without `--locked`) so Cargo rewrites `Cargo.lock` to match.
This is the only step that runs without `--locked`.

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
informational. Raising a lower bound in `Cargo.toml` is a change the apps feel
(their lockfiles must follow), so mention it in the CHANGELOG.

If `cargo deny` or `cargo outdated` are not installed, install them first:

```
cargo install --locked cargo-deny cargo-outdated
```

### 5. Check the pinned toolchain

`rust-toolchain.toml` pins an exact Rust version (shared with the three apps).
Compare it with the latest stable (`rustup check`, or the weekly Scheduled
run's toolchain-drift job). If a newer stable exists, tell the user and offer
to bump the pin first (a separate commit, after `make check` passes on it);
otherwise continue on the pin.

### 6. Run the full quality gate — every check must pass

```
make check PACKAGE_FLAGS=--allow-dirty
make msrv
make test-real-gpg
make coverage
make minimal-versions
make check-windows
```

If any fails, stop and report the error; do not proceed to tagging. If only
formatting fails, run `make fmt` and re-run.

- `make check` is the pre-release gate CI also runs: fmt-check, lint
  (secrets scan, clippy over every feature set, fmt, rustdoc, actionlint,
  shellcheck), test (the changelog-script test, then the suite once per
  feature set), deny, and `cargo package`. `--allow-dirty` is needed only
  because the version bump isn't committed yet.
- `make test-real-gpg` drives the local real gpg with throwaway keyrings,
  and fails if the test skipped or didn't run. Confirm the output shows
  `real_gpg_status_codes_classify_as_expected ... ok`; a release whose
  real-gpg check didn't run verifies nothing about GnuPG drift.
- `make coverage`, `make minimal-versions` and `make check-windows` need
  cargo-llvm-cov with the `llvm-tools` component, a nightly toolchain, and
  `rustup target add x86_64-pc-windows-msvc`. If one of those isn't
  installed, say so and continue: the release workflow runs all of `ci.yml`
  before it publishes, so CI still enforces them.

### 7. Check the public API change (from the second release on)

Run cargo-semver-checks against the last published version, so the bump from
step 2 matches what changed:

```
cargo semver-checks --baseline-version <previous version> --all-features
```

If it reports a breaking change and step 2 picked a patch bump, stop and tell
the user. Skip this step on the first release (there is no baseline). Install
it with `cargo install --locked cargo-semver-checks` if needed.

### 8. Update CHANGELOG.md

Read `CHANGELOG.md` (Keep a Changelog format, shared with the three apps).
Rename the `## [Unreleased]` section to `## [<new version>] - YYYY-MM-DD`
(today, ASCII hyphen), keeping the entries already in it, then add a fresh,
empty `## [Unreleased]` section above it. No `---` separators.

Fold in anything from the git log since the previous release tag that isn't
already listed (on the first release, the whole history):

```
git log v<previous version>..HEAD --oneline
```

Group entries into the standard changelog categories (Added, Changed, Fixed,
Removed, Security, Documentation, Internal), and omit any category with no
entries. Call out breaking API changes first, with what an app must change.
Exclude housekeeping commits such as version bumps and `cargo fmt` runs. The
release workflow publishes this section as the release notes and fails if it
is missing or empty, so confirm it extracts and the changelog tests pass:

```
scripts/changelog-section.sh <new version>
make test-scripts
```

### 9. Commit the version bump and changelog

```
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "Bump version to <new version>"
make package
```

`make package` (now on a clean tree, without `--allow-dirty`) builds the exact
`.crate` that will be published.

### 10. Tag the release

```
git tag -a v<new version> -m v<new version>
```

### 11. Confirm before pushing

Show the user the new version, the commit SHA, and the tag, then ask whether
to push. Make clear that pushing the tag publishes to crates.io, which can't
be undone: a version can be yanked but never deleted or replaced. Pushing the
tag triggers `.github/workflows/release.yml`, which verifies the tag, runs the
full CI, runs `cargo publish`, and creates the GitHub release with the
`.crate`, its checksum and a provenance attestation. If they confirm, run:

```
git push origin main
git push origin v<new version>
```

### 12. Verify the release

1. Watch the Release run until it finishes, and report each job's result:

   ```
   gh run watch <run-id> --exit-status
   ```

2. Confirm crates.io serves the new version (the index can lag by a minute):

   ```
   cargo info pass-store@<new version>
   ```

3. Download the release's `.crate` and `checksums.txt` into a fresh scratch
   directory, verify the sha256 (`shasum -a 256 -c checksums.txt`) and the
   provenance:

   ```
   gh attestation verify pass-store-<new version>.crate --repo 3kirt/pass-store
   ```

4. Build against the published crate, the way the apps will get it. In a fresh
   scratch directory, create a throwaway binary crate (`cargo new
   --vcs none`). Depend on `pass-store = { version = "=<new version>",
   features = ["http"] }`, with `features = ["test-support"]` as a
   dev-dependency. Then run `cargo build` and `cargo test`, with one test
   that writes `ok_snippet("tok")` to an entry and reads it back through
   `PassStore::new(dir, fake_gpg(), Branding::new("Smoke", "smoke"))`. A
   failure here is a release regression: report it to the user.

5. Report what the apps would change, without editing them: each depends on
   pass-store through a git `rev`. Moving one to this release means replacing
   `git`/`rev` with `version = "<new version>"` and dropping the `allow-git`
   entry from its `deny.toml`. Offer that as a follow-up for the user to
   run in each app's own session.
