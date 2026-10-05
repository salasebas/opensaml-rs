# How to upgrade saml-rs

Apply every guide from the minor version you run today up to the version you
are installing. Each guide is the work an existing integration must do. The
[changelog](../../CHANGELOG.md) lists the rest of the release, including
compatible additions.

## Guides

- [How to upgrade from 0.2 to 0.3](0.2-to-0.3.md)
- [How to upgrade from 0.3 to 0.4](0.3-to-0.4.md)
- [How to upgrade from 0.4 to 0.5](0.4-to-0.5.md)
- [How to upgrade from 0.5 to 0.6](0.5-to-0.6.md)

## How to add a guide

This section is for the person shipping the change, not for someone upgrading.

Add a guide in the same change that forces consumers to change code, runtime
behaviour, feature flags, or the minimum supported Rust version. Name the file
after that boundary, such as `0.2-to-0.3.md`, and cover the move from the
latest patch of the source minor release.

In the guide, state what breaks, who must change, and the steps to upgrade.
Leave compatible features out; the changelog records those.
