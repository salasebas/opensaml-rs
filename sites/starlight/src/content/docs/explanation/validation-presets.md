---
title: "Validation presets"
description: "saml-rs keeps two presets."
---

saml-rs keeps two presets.

**Recommended** is the preset for features the crate claims. Mandatory requirements stay in force. Recommendations start enabled and can be relaxed only by an explicit named option. A producer recommendation does not, by itself, become a receiver rejection. Optional capabilities stay off until you select them. Recommended is not an implementation of SAML V2.0 as a whole.

**Compatibility** is the legacy permissive preset: the samlify-port behaviour kept for callers leaving the raw API. It can still relax a mandatory requirement where that port did. It does not claim standards conformance. Raw settings keep their own historical defaults.

Library hardening that OASIS does not require stays off Recommended. Two examples are a signature directly on the Assertion, and the RSA-SHA2 XML-DSig profile. Each is selected by name, on top of Recommended. They are not collected into a third preset. A MAY in the standard is an optional capability, not a stricter conformance level. That is why a bundled `strict()` preset was rejected.

`recommended()` publishes the combination recorded under [Conformance](../reference/conformance.md).

`strict()` is deprecated. It keeps its current behaviour and does not gain the RSA-SHA2 profile. `Default`, `new`, and `try_new` stay on Compatibility. Config builders stay on the deprecated `strict()` method. The following release removes `strict()` and points `Default`, `new`, `try_new`, and the builders at Recommended together.

The calls are in [Validation](../guides/validation-preset.md). This page restates [ADR 0002](https://github.com/salasebas/saml-rs/blob/main/docs/adr/0002-validation-presets.md).
