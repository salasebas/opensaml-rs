---
title: "Typed API"
description: "Browser flows start from `Saml<Sp>` and `Saml<Idp>`. The local role is the configuration you build. The peer is a descriptor you import from metadata. A binding that SAML Web..."
---

Browser flows start from `Saml<Sp>` and `Saml<Idp>`. The local role is the configuration you build. The peer is a descriptor you import from metadata. A binding that SAML Web SSO does not allow cannot be represented on the typed builders.

Request correlation, `RelayState`, the clock, replay, and metadata trust show up in the function arguments. There is no hidden cache and no implied metadata signer. XML-DSig, canonicalisation, and XML-Enc stay in bergshamra. This crate does not implement them.

The raw `flow` API, `ServiceProvider`, and `IdentityProvider` stay available for migration. Their defaults are historical. Changing a typed preset does not rewrite them.

Artifact resolution, SOAP and other back-channel profiles, ECP/PAOS, SAML queries, NameID management, and metadata federation stay outside the typed API. That boundary is also the [coverage table](../reference/coverage.md).

The service-provider round trip is [Service provider](../guides/service-provider-sso.md). The design notes in the repository, including names that were rejected, are the [architecture record](https://github.com/salasebas/saml-rs/tree/main/docs/architecture). A heading there that says Proposed, Target, or Today describes that design record. The guides on this site are the current calls.
