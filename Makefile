# Single source of truth for local and CI checks: the workflows only call
# these targets. `make check` is the pre-release gate. Every cargo invocation
# is --locked.

MSRV := $(shell sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)

# Each feature combination clippy checks ("none" = no features, "all" = --all-features).
FEATURE_SETS := none http test-support all

# `cargo package` refuses uncommitted changes; pass PACKAGE_FLAGS=--allow-dirty
# to check a work tree before committing.
PACKAGE_FLAGS ?=

# Real tokens for the apps that use this crate: a Proxmox API token secret
# (USER@REALM!TOKENID=<uuid>), a GitLab PAT, a NetBox v2 token. Test fixtures
# use obviously fake values.
SECRET_PATTERN := ![A-Za-z0-9_.-]+=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|glpat-[A-Za-z0-9_-]{20,}|nbt_[A-Za-z0-9]{8,}\.[A-Za-z0-9]{20,}

.PHONY: build test test-real-gpg lint secrets-scan clippy fmt fmt-check deny msrv package check clean

build:
	cargo build --locked --all-features

test:
	cargo test --locked
	cargo test --locked --all-features

# Classification against the real gpg (generates throwaway keys).
test-real-gpg:
	REAL_GPG=1 cargo test --locked --all-features real_gpg -- --ignored

lint: secrets-scan clippy fmt-check

clippy:
	@set -e; for set in $(FEATURE_SETS); do \
		case $$set in none) flags= ;; all) flags=--all-features ;; *) flags="--features $$set" ;; esac; \
		echo "cargo clippy --all-targets --locked $$flags -- -D warnings"; \
		cargo clippy --all-targets --locked $$flags -- -D warnings; \
	done

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

# Builds the .crate exactly as crates.io would receive it, and compiles it.
package:
	cargo package --locked $(PACKAGE_FLAGS)

check: fmt-check lint test deny package

clean:
	cargo clean
