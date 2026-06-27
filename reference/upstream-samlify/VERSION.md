# Upstream samlify Reference

| Field | Value |
| --- | --- |
| Version | `2.13.1` |
| Tag | `v2.13.1` |
| Commit | `b1ff880ab40a4b4768b3afb53ef8b88c3437079b` |
| Repository | https://github.com/tngan/samlify |
| npm tarball | https://registry.npmjs.org/samlify/-/samlify-2.13.1.tgz |
| npm integrity | `sha512-vdYr/zohDGBbfWNU4miEzc1jmWOtkLySPViapC6nfGkv9KxzLq4UlGkKyryzwLw4jVlZk88Rw93HaCRVpe+t+g==` |

Sources live under `reference/upstream-samlify/2.13.1/repository/` and are
gitignored. Run `./scripts/fetch-upstream-samlify.sh` to populate them; the
script verifies the cloned tag against the pinned commit. Do not commit the
clone.

`samlify` (npm) is used as a behavioral/porting reference only. The Rust
`samlify` crate in this workspace is an unrelated re-export of `opensaml`.
