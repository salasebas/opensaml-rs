# samlify parity

This workspace tracks selected behavior from the pinned npm `samlify`
reference in `reference/upstream-samlify/VERSION.md`.

## Metadata generation

- SP metadata `elementsOrder` profiles are exposed as
  `opensaml::constants::elements_order::{DEFAULT, ONELOGIN, SHIBBOLETH}`.
- IdP metadata `elementsOrder` is covered for the samlify 2.13.1 default,
  OneLogin, and Shibboleth profiles via
  `opensaml::constants::elements_order::idp`.
