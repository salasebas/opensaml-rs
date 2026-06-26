# Release Process

This release process is for the independent, unofficial **opensaml-rs** Rust
workspace. The `samlify` crate is a Rust crate-name alias and is not affiliated
with, maintained by, endorsed by, or sponsored by the npm `samlify` package or
its authors.

opensaml-rs uses **release-plz** to publish one coordinated workspace release.
All crates share the same version and are published together: `opensaml`,
`samlify`, `open-saml`, `rust-saml`, `rustsaml`, `saml-rs`, and `samlrs`.

Git tags use `v*`, for example `v0.1.5`.

## Normal release process

1. Merge changes to `main` using Conventional Commit titles: `fix: ...`,
   `feat: ...`, or `feat!: ...` / `BREAKING CHANGE: ...`.
2. The `Release-plz` workflow opens or updates a release PR.
3. Review the version bump, `Cargo.lock`, and `CHANGELOG.md`.
4. Merge the release PR after CI passes.
5. `release-plz release` publishes the crates, creates the `vX.Y.Z` tag, and
   creates the GitHub release.

`release-plz.toml` sets `release_always = false`, so publication happens only
from the merged release PR, not from every push to `main`.

## GitHub and crates.io setup

Recommended setup is crates.io trusted publishing:

1. In GitHub, allow Actions to create pull requests.
2. In GitHub, create the `release` environment and allow deployments from the
   `main` branch. The workflow runs from `main`; the `vX.Y.Z` tag is created
   later by release-plz.
3. In crates.io, configure trusted publishing for every crate above:
   repository `salasebas/opensaml-rs`, workflow
   `.github/workflows/release-plz.yml`, environment `release`.
4. Do not configure `CARGO_REGISTRY_TOKEN` when using trusted publishing.

## Manual fallback

1. Bump `[workspace.package] version` and the internal workspace dependency
   versions in the root `Cargo.toml`.
2. Refresh `Cargo.lock` with `cargo build --workspace`.
3. Run checks:

   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo nextest run --workspace --all-features
   ```

4. Update `CHANGELOG.md`.
5. Publish in dependency order: first `opensaml`, then the alias crates.

   ```bash
   cargo publish -p opensaml
   cargo publish -p samlify
   cargo publish -p open-saml
   cargo publish -p rust-saml
   cargo publish -p rustsaml
   cargo publish -p saml-rs
   cargo publish -p samlrs
   ```

6. Create the `vX.Y.Z` tag and GitHub release.

Use `cargo publish -p <crate> --dry-run` to validate a publish without
uploading. Published versions on crates.io are whatever you ship from this
repository; they are **not** the npm `samlify` package.
