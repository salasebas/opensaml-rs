# Release Process

This release process is for the independent, unofficial **opensaml-rs** Rust
workspace. The `samlify` crate is a Rust crate-name alias and is not affiliated
with, maintained by, endorsed by, or sponsored by the npm `samlify` package or
its authors.

opensaml-rs uses **Cargo** and is released via **GitHub releases** and
**crates.io**.

1. Bump the workspace version in the root `Cargo.toml` under
   `[workspace.package] version`. Member crates use `version.workspace = true`.
2. Align the path-dependency version pins in
   `[workspace.dependencies]` (`opensaml` / `samlify`) with the new version so
   the semver constraints match what you publish on crates.io.
3. Refresh the lockfile: `cargo build --workspace` so `Cargo.lock` reflects the
   bump (commit the lockfile change when it differs).
4. Run checks:

   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo nextest run --workspace --all-features
   ```

5. Update `CHANGELOG.md` with the release notes for the version being published.
6. Publish crates to crates.io in **dependency order**, waiting for each to be
   visible before publishing dependents:

   1. `opensaml` — no workspace dependencies.
   2. Alias crates — each depends only on `opensaml`: `samlify`, `open-saml`,
      `rust-saml`, `rustsaml`, `saml-rs`, `samlrs`.

   ```bash
   cargo publish -p opensaml
   cargo publish -p samlify
   cargo publish -p open-saml
   cargo publish -p rust-saml
   cargo publish -p rustsaml
   cargo publish -p saml-rs
   cargo publish -p samlrs
   ```

7. Create a **GitHub release** tagging the commit that matches the published
   version.

Use `cargo publish -p <crate> --dry-run` to validate a publish without
uploading. Published versions on crates.io are whatever you ship from this
repository; they are **not** the npm `samlify` package.
