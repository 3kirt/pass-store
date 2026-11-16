# Single source of truth for local and CI checks: the workflows only call
# these targets. `make check` is the pre-release gate. Every cargo invocation
# is --locked, except `minimal-versions`, which re-resolves on purpose.

MSRV := $(shell sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)

# Each feature combination clippy and the tests cover ("none" = no features,
# "all" = --all-features).
FEATURE_SETS := none http test-support all

# A non-Unix target, so the `cfg(not(unix))` code paths compile somewhere.
WINDOWS_TARGET := x86_64-pc-windows-msvc

# Line coverage `make coverage` requires (unit, integration and real-gpg
# tests together).
COVERAGE_MIN := 97

# `cargo package` refuses uncommitted changes; pass PACKAGE_FLAGS=--allow-dirty
# to check a work tree before committing.
PACKAGE_FLAGS ?=

# Real tokens for the apps that use this crate: a Proxmox API token secret
# (USER@REALM!TOKENID=<uuid>), a GitLab PAT, a NetBox v2 token. Test fixtures
# use obviously fake values.
SECRET_PATTERN := ![A-Za-z0-9_.-]+=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|glpat-[A-Za-z0-9_-]{20,}|nbt_[A-Za-z0-9]{8,}\.[A-Za-z0-9]{20,}

# Runs `cargo $(1)` once per feature set.
define each_feature_set
	@set -e; for set in $(FEATURE_SETS); do \
		case $$set in none) flags= ;; all) flags=--all-features ;; *) flags="--features $$set" ;; esac; \
		echo "cargo $(1) $$flags $(2)"; \
		cargo $(1) $$flags $(2); \
	done
endef

.PHONY: build test test-scripts test-real-gpg lint secrets-scan clippy doc lint-workflows \
	fmt fmt-check deny msrv minimal-versions check-windows coverage package check clean

build:
	cargo build --locked --all-features

test: test-scripts
	$(call each_feature_set,test --locked)

# changelog-section.sh (used by release.yml) and CHANGELOG.md's shape.
test-scripts:
	scripts/test-changelog.sh

# Classification against the real gpg (generates throwaway keys). Fails
# unless the test actually ran: a filter matching nothing, or a skip, still
# reports `ok`.
REAL_GPG_TEST := real_gpg::real_gpg_status_codes_classify_as_expected
test-real-gpg:
	@out=$$(REAL_GPG=1 cargo test --locked --all-features --lib -- --ignored --exact $(REAL_GPG_TEST) 2>&1); \
	status=$$?; printf '%s\n' "$$out"; \
	[ $$status -eq 0 ] || exit $$status; \
	if printf '%s\n' "$$out" | grep -q skipping \
		|| ! printf '%s\n' "$$out" | grep -q 'test result: ok. 1 passed'; then \
		echo "test-real-gpg: the real-gpg test did not run" >&2; exit 1; \
	fi

lint: secrets-scan clippy fmt-check doc lint-workflows

clippy:
	$(call each_feature_set,clippy --all-targets --locked,-- -D warnings)

# Broken intra-doc links and other rustdoc warnings fail, as docs.rs would
# show them.
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features

# The workflows and shell scripts (needs actionlint and shellcheck).
lint-workflows:
	actionlint
	shellcheck scripts/*.sh

secrets-scan:
	@if git grep --untracked -nE '$(SECRET_PATTERN)' -- . ':!Cargo.lock'; then \
		echo "An API token secret appears to be committed"; exit 1; \
	fi

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

deny:
	cargo deny --locked check

msrv:
	cargo +$(MSRV) test --locked --all-features

# The lower bounds in Cargo.toml: resolve every direct dependency to the
# oldest version it allows (needs a nightly toolchain for that), then run
# the suite on the MSRV. An app whose own lockfile pins an older release
# builds with those. Cargo.lock is restored afterwards.
minimal-versions:
	@cp Cargo.lock Cargo.lock.orig; \
	status=0; \
	cargo +nightly update -Z direct-minimal-versions && \
		cargo +$(MSRV) test --locked --all-features || status=$$?; \
	mv Cargo.lock.orig Cargo.lock; \
	exit $$status

# Compiles everything, tests included, for a non-Unix target (needs
# `rustup target add $(WINDOWS_TARGET)`). The suite itself is Unix-only.
check-windows:
	$(call each_feature_set,clippy --all-targets --locked --target $(WINDOWS_TARGET),-- -D warnings)

# Needs cargo-llvm-cov, the llvm-tools component, and a real gpg.
coverage:
	REAL_GPG=1 cargo llvm-cov --locked --all-features --fail-under-lines $(COVERAGE_MIN) \
		-- --include-ignored

# Builds the .crate exactly as crates.io would receive it, and compiles it.
package:
	cargo package --locked $(PACKAGE_FLAGS)

check: fmt-check lint test deny package

clean:
	cargo clean
