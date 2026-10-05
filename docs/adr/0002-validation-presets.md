# Keep two validation presets and retire the strict bundle

saml-rs keeps two validation presets, Compatibility and Recommended.
Compatibility stays the current typed permissive behavior, including where a
mandatory requirement can be relaxed, and it does not claim standards
conformance. Raw settings keep their own historical defaults and are not
rewritten to match it. Recommended applies only to SAML features the crate
already implements: for the obligated actor, mandatory requirements stay in
force, and recommendations start enabled and can be relaxed only by an
explicit named option. A producer recommendation does not by itself become a
receiver rejection. Optional capabilities stay off until selected by name.
Library hardening that OASIS does not require, such as a direct Assertion
signature or the RSA-SHA2 XML-DSig profile, is also selected by name on top
of Recommended rather than collected into a third preset. A bundled strict
preset was rejected because callers need those hardenings independently, and
because a MAY is an optional capability rather than a stricter conformance
level.

`recommended()` is published only after the claimed features have been
classified, in this order: Web Browser SSO, Single Logout, then metadata and
replay. That release deprecates `strict()` and leaves its current behavior
unchanged. `Default`, `new`, `try_new`, and the config builders keep returning
Compatibility through that release, so existing callers do not change while
the preset is still being defined. The following release removes `strict()`
and points `Default`, `new`, `try_new`, and the builders at Recommended
together.
