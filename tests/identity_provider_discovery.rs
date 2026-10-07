//! Identity Provider Discovery cookie written by the typed identity provider.

use std::time::Duration;

use saml_rs::{
    CommonDomainCookie, CommonDomainCookieRequest, DiscoveryCookieLifetime, EntityId, IdpConfig,
    IdpValidationPolicy, Saml, SamlError, SsoEndpoint,
};

const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
/// Standard base64 of `IDP_ENTITY_ID`, then percent-encoded (`=` is `%3D`).
const IDP_ENTITY_COOKIE_VALUE: &str = "aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%3D";

fn identity_provider(entity_id: &str) -> Result<Saml<saml_rs::Idp>, SamlError> {
    let config = IdpConfig::builder(EntityId::try_new(entity_id)?)
        .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
        .validation(IdpValidationPolicy::compatibility())
        .build()?;
    Saml::idp(config)
}

fn remember(
    entity_id: &str,
    common_domain: &str,
    lifetime: DiscoveryCookieLifetime,
    existing_cookie: Option<&str>,
) -> Result<CommonDomainCookie, SamlError> {
    let mut request = CommonDomainCookieRequest::new(common_domain, lifetime);
    if let Some(value) = existing_cookie {
        request = request.with_existing_cookie(value);
    }
    identity_provider(entity_id)?.remember_identity_provider(request)
}

#[test]
fn identity_provider_writes_a_session_common_domain_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        DiscoveryCookieLifetime::Session,
        None,
    )?;

    assert_eq!(cookie.name(), "_saml_idp");
    assert_eq!(cookie.value(), IDP_ENTITY_COOKIE_VALUE);
    assert_eq!(cookie.path(), "/");
    assert_eq!(cookie.domain(), ".example.org");
    assert!(cookie.secure());
    assert_eq!(cookie.lifetime(), DiscoveryCookieLifetime::Session);
    assert_eq!(
        cookie.set_cookie_header(),
        "_saml_idp=aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%3D; Path=/; Domain=.example.org; Secure"
    );
    Ok(())
}

#[test]
fn persistent_cookie_records_max_age_in_whole_seconds() -> Result<(), Box<dyn std::error::Error>> {
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        DiscoveryCookieLifetime::Persistent {
            max_age: Duration::from_secs(86_400),
        },
        None,
    )?;

    assert_eq!(
        cookie.lifetime(),
        DiscoveryCookieLifetime::Persistent {
            max_age: Duration::from_secs(86_400),
        }
    );
    assert_eq!(
        cookie.set_cookie_header(),
        "_saml_idp=aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%3D; Path=/; Domain=.example.org; Secure; Max-Age=86400"
    );
    Ok(())
}

#[test]
fn empty_existing_cookie_starts_a_new_list() -> Result<(), Box<dyn std::error::Error>> {
    let cookie = remember(
        IDP_ENTITY_ID,
        "example.org",
        DiscoveryCookieLifetime::Session,
        Some(""),
    )?;
    assert_eq!(cookie.value(), IDP_ENTITY_COOKIE_VALUE);
    Ok(())
}

#[test]
fn writer_appends_this_identity_provider_and_moves_it_to_the_end(
) -> Result<(), Box<dyn std::error::Error>> {
    const OTHER: &str = "aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ%3D%3D";
    const MOVED: &str = "aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ%3D%3D%20aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%3D";

    let appended = remember(
        IDP_ENTITY_ID,
        "example.org",
        DiscoveryCookieLifetime::Session,
        Some(OTHER),
    )?;
    assert_eq!(appended.value(), MOVED);

    let moved = remember(
        IDP_ENTITY_ID,
        "example.org",
        DiscoveryCookieLifetime::Session,
        Some(&format!("{IDP_ENTITY_COOKIE_VALUE}%20{OTHER}")),
    )?;
    assert_eq!(moved.value(), MOVED);

    let collapsed = remember(
        IDP_ENTITY_ID,
        "example.org",
        DiscoveryCookieLifetime::Session,
        Some(&format!(
            "{IDP_ENTITY_COOKIE_VALUE}%20{OTHER}%20{IDP_ENTITY_COOKIE_VALUE}"
        )),
    )?;
    assert_eq!(collapsed.value(), MOVED);

    let form_encoded = remember(
        IDP_ENTITY_ID,
        "example.org",
        DiscoveryCookieLifetime::Session,
        Some(&format!("{IDP_ENTITY_COOKIE_VALUE}+{OTHER}")),
    )?;
    assert_eq!(form_encoded.value(), MOVED);

    let already_decoded = remember(
        IDP_ENTITY_ID,
        "example.org",
        DiscoveryCookieLifetime::Session,
        Some(
            "aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE= aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ==",
        ),
    )?;
    assert_eq!(already_decoded.value(), MOVED);
    Ok(())
}

#[test]
fn cookie_value_percent_encodes_base64_plus_and_slash() -> Result<(), Box<dyn std::error::Error>> {
    let plus = remember(
        "https://idp.example/~",
        "example.org",
        DiscoveryCookieLifetime::Session,
        None,
    )?;
    assert_eq!(plus.value(), "aHR0cHM6Ly9pZHAuZXhhbXBsZS9%2B");

    let slash = remember(
        "https://idp.example.com/metadata?x=1",
        "example.org",
        DiscoveryCookieLifetime::Session,
        None,
    )?;
    assert_eq!(
        slash.value(),
        "aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGE%2FeD0x"
    );

    let again = remember(
        "https://idp.example/~",
        "example.org",
        DiscoveryCookieLifetime::Session,
        Some(plus.value()),
    )?;
    assert_eq!(again.value(), plus.value());

    let decoded_plus = remember(
        "https://idp.example/~",
        "example.org",
        DiscoveryCookieLifetime::Session,
        Some("aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ== aHR0cHM6Ly9pZHAuZXhhbXBsZS9+"),
    )?;
    assert_eq!(
        decoded_plus.value(),
        "aHR0cHM6Ly9vdGhlci5leGFtcGxlLm5ldC9tZXRhZGF0YQ%3D%3D%20aHR0cHM6Ly9pZHAuZXhhbXBsZS9%2B"
    );
    Ok(())
}

#[test]
fn discovery_cookie_rejects_input_that_cannot_be_written() -> Result<(), Box<dyn std::error::Error>>
{
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            ".example.org",
            DiscoveryCookieLifetime::Session,
            None,
        ),
        "without a leading period",
    )?;
    assert_invalid(
        remember(IDP_ENTITY_ID, "", DiscoveryCookieLifetime::Session, None),
        "must not be empty",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org/idp",
            DiscoveryCookieLifetime::Session,
            None,
        ),
        "ASCII hostname",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "ex ample.org",
            DiscoveryCookieLifetime::Session,
            None,
        ),
        "ASCII hostname",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            DiscoveryCookieLifetime::Persistent {
                max_age: Duration::ZERO,
            },
            None,
        ),
        "at least one second",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            DiscoveryCookieLifetime::Persistent {
                max_age: Duration::from_millis(1_500),
            },
            None,
        ),
        "whole number of seconds",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            DiscoveryCookieLifetime::Session,
            Some("%"),
        ),
        "truncated percent escape",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            DiscoveryCookieLifetime::Session,
            Some("%ZZ"),
        ),
        "not hexadecimal",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            DiscoveryCookieLifetime::Session,
            Some("%20"),
        ),
        "empty entry",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            DiscoveryCookieLifetime::Session,
            Some("not-valid"),
        ),
        "not base64",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            DiscoveryCookieLifetime::Session,
            Some("%2Fw%3D%3D"),
        ),
        "not an entity identifier",
    )?;
    assert_invalid(
        remember(
            IDP_ENTITY_ID,
            "example.org",
            DiscoveryCookieLifetime::Session,
            Some(&"a".repeat(8_193)),
        ),
        "larger than 8192 bytes",
    )?;

    let prefix = "https://idp.example/";
    let within = format!("{prefix}{}", "a".repeat(1024 - prefix.len()));
    assert_eq!(within.chars().count(), 1024);
    let accepted = remember(
        &within,
        "example.org",
        DiscoveryCookieLifetime::Session,
        None,
    )?;
    assert_eq!(accepted.name(), "_saml_idp");
    let too_long = format!("{within}a");
    assert_invalid(
        remember(
            &too_long,
            "example.org",
            DiscoveryCookieLifetime::Session,
            None,
        ),
        "1024 characters",
    )?;
    assert_invalid(
        remember(
            "not-a-uri",
            "example.org",
            DiscoveryCookieLifetime::Session,
            None,
        ),
        "URI",
    )?;
    Ok(())
}

fn assert_invalid(
    result: Result<CommonDomainCookie, SamlError>,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(SamlError::Invalid(actual)) if actual.contains(message) => Ok(()),
        Err(SamlError::Invalid(actual)) => {
            Err(format!("error {actual:?} does not contain {message:?}").into())
        }
        Err(error) => Err(format!("expected Invalid, got {error}").into()),
        Ok(_) => Err(format!("expected Invalid containing {message:?}").into()),
    }
}
