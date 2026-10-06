# Keep two validation presets and retire the strict bundle

saml-rs keeps two validation presets, Compatibility and Recommended.
Compatibility is the legacy permissive preset: the samlify-port behavior kept
for callers leaving the raw API. It can still relax a mandatory requirement
where that port did, and it does not claim standards conformance. It does not
name a relaxation of an OASIS recommendation. Raw settings keep their own
historical defaults and are not rewritten to match it. Recommended is the
preset for claimed features. It is not an implementation of SAML V2.0 as a
whole. For the obligated actor, mandatory requirements stay in force, and
recommendations start enabled and can be relaxed only by an explicit named
option. A producer recommendation does not by itself become a receiver
rejection. Optional capabilities stay off until selected by name. Library
hardening that OASIS does not require, such as a direct Assertion signature
or the RSA-SHA2 XML-DSig profile, is also selected by name on top of
Recommended rather than collected into a third preset. A bundled strict
preset was rejected because callers need those hardenings independently, and
because a MAY is an optional capability rather than a stricter conformance
level.

Web Browser SSO, Single Logout, metadata, and replay are classified under
`docs/conformance/`. `recommended()` publishes that combination.
`strict()` is deprecated, keeps its current behavior, and does not gain the
RSA-SHA2 XML-DSig profile. The deprecation tells callers to start from
Recommended and add only the named hardenings they want. `Default`, `new`,
and `try_new` stay on Compatibility. Config builders stay on the deprecated
`strict()` method. The following release removes `strict()` and points
`Default`, `new`, `try_new`, and the builders at Recommended together.
