//! Verifies the `samlify` crate re-exports the `opensaml` public API.

#[test]
fn reexports_constants_and_types() {
    // modules re-exported via `pub use opensaml::*;`
    assert_eq!(
        samlify::constants::Binding::Redirect.urn(),
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    );
    // re-exported root types
    let _setting = samlify::EntitySetting::default();
    let _err = samlify::OpenSamlError::UndefinedBinding;
}

#[test]
fn reexports_entities_and_metadata() -> Result<(), Box<dyn std::error::Error>> {
    use samlify::metadata::{Endpoint, SpMetadataConfig};
    use samlify::{EntitySetting, ServiceProvider};

    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            assertion_consumer_service: vec![Endpoint::new(
                samlify::constants::Binding::Post,
                "https://sp/acs",
            )],
            ..Default::default()
        },
        EntitySetting::default(),
    )?;
    assert_eq!(
        sp.metadata.get_entity_id(),
        Some("https://sp.example.com/metadata")
    );
    Ok(())
}
