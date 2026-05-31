# samlify

A thin re-export crate:

```rust
pub use opensaml::*;
```

It exists only to offer a `samlify`-shaped crate name. Use whichever you
prefer:

- `opensaml` — the real crate; depend on it directly.
- `samlify` — the same API under a familiar name.

This is **not** the npm [`samlify`](https://www.npmjs.com/package/samlify)
package. It is a Rust alias for [`opensaml`](../opensaml). All logic, features,
and docs live in `opensaml`.
