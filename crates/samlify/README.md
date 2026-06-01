# samlify

A thin re-export crate:

```rust
pub use opensaml::*;
```

It exists only to offer a `samlify`-shaped crate name. Use whichever you
prefer:

- `opensaml` — the real crate; depend on it directly.
- `samlify` — the same API under a familiar name.

## Disclaimer — no affiliation

This crate is an **independent, unofficial** Rust crate. It is **not**
affiliated with, derived from, maintained by, endorsed by, or sponsored by the
npm [`samlify`](https://www.npmjs.com/package/samlify) package or its authors.
"samlify" here is only a Rust crate name; it shares **no code** with the npm
package.

This crate contains no logic of its own — it is a Rust alias for
[`opensaml`](../opensaml) (`pub use opensaml::*;`). All logic, features, and docs
live in `opensaml`. Any trademarks belong to their respective owners.
