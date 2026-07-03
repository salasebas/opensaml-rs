# Release Process

This release process is for the independent, unofficial **saml-rs** Rust
package.

This repository publishes one crate after the migration: `saml-rs`.

Git tags use `v*`, for example `v0.1.5`.

## Normal release process

1. Merge changes to `main` using Conventional Commit titles: `fix: ...`,
   `feat: ...`, or `feat!: ...` / `BREAKING CHANGE: ...`.
2. The `Release-plz` workflow opens or updates a release PR.
3. Review the version bump, `Cargo.lock`, and `CHANGELOG.md`.
4. Merge the release PR after CI passes.
5. `release-plz release` publishes the crate, creates the `vX.Y.Z` tag, and
   creates the GitHub release.

`release-plz.toml` sets `release_always = false`, so publication happens only
from the merged release PR, not from every push to `main`.

Old alias crates are retired and frozen. Do not yank healthy published alias
versions as a deprecation mechanism; yank only for a bad release, security, or
legal reason.

## GitHub and crates.io setup

Recommended setup is crates.io trusted publishing:

1. In GitHub, allow Actions to create pull requests.
2. In GitHub, create the `release` environment and allow deployments from the
   `main` branch. The workflow runs from `main`; the `vX.Y.Z` tag is created
   later by release-plz.
3. In crates.io, configure trusted publishing for `saml-rs`: repository
   `salasebas/saml-rs`, workflow `.github/workflows/release-plz.yml`,
   environment `release`.
4. Do not configure `CARGO_REGISTRY_TOKEN` when using trusted publishing.

Before publishing, configure trusted publishing for the final GitHub repository
name if the repository rename has not happened yet.

## Manual fallback

1. Bump `[package] version` in the root `Cargo.toml`.
2. Refresh `Cargo.lock` with `cargo build`.
3. Run checks:

   ```bash
   cargo fmt --all --check
   cargo clippy -p saml-rs --all-targets --all-features -- -D warnings
   cargo nextest run -p saml-rs
   cargo test -p saml-rs --doc
   cargo check -p saml-rs --no-default-features
   ```

4. Update `CHANGELOG.md`.
5. Publish the crate:

   ```bash
   cargo publish -p saml-rs
   ```

6. Create the `vX.Y.Z` tag and GitHub release.

Use `cargo publish -p saml-rs --dry-run` to validate a publish without
uploading.
