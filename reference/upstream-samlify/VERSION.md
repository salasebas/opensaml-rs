# Upstream samlify Reference

| Field | Value |
| --- | --- |
| Version | `2.10.2` |
| Tag | `v2.10.2` |
| Repository | https://github.com/tngan/samlify |

Sources live under `reference/upstream-samlify/2.10.2/repository/` and are
gitignored. Run `./scripts/fetch-upstream-samlify.sh` to populate them. Do not
commit the clone.

`samlify` (npm) is used as a behavioral/porting reference only. The Rust
`samlify` crate in this workspace is an unrelated re-export of `opensaml`.
