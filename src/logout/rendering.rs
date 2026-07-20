use crate::constants::{namespace, status_code};
use crate::entity::{EntitySetting, User};
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::template::validate_tag_prefix;
use crate::xml::write::XmlWriter;

pub(super) fn issuer_of(setting: &EntitySetting, meta: &Metadata) -> String {
    setting
        .entity_id
        .clone()
        .or_else(|| meta.get_entity_id().map(str::to_string))
        .unwrap_or_default()
}

pub(super) struct LogoutRequestSubject<'a> {
    pub(super) name_id: &'a str,
    pub(super) session_indexes: Vec<&'a str>,
}

impl<'a> LogoutRequestSubject<'a> {
    pub(super) fn from_user(user: &'a User) -> Self {
        Self {
            name_id: &user.name_id,
            session_indexes: user.session_index.as_deref().into_iter().collect(),
        }
    }
}

pub(super) fn render_default_logout_response(
    setting: &EntitySetting,
    id: &str,
    issue_instant: &str,
    destination: &str,
    in_response_to: Option<&str>,
    issuer: &str,
) -> Result<String, SamlError> {
    validate_tag_prefix("protocol", &setting.tag_prefix_protocol)?;
    validate_tag_prefix("assertion", &setting.tag_prefix_assertion)?;

    let protocol_prefix = &setting.tag_prefix_protocol;
    let assertion_prefix = &setting.tag_prefix_assertion;
    let root_name = format!("{protocol_prefix}:LogoutResponse");
    let issuer_name = format!("{assertion_prefix}:Issuer");
    let status_name = format!("{protocol_prefix}:Status");
    let status_code_name = format!("{protocol_prefix}:StatusCode");
    let xmlns_protocol = format!("xmlns:{protocol_prefix}");
    let xmlns_assertion = format!("xmlns:{assertion_prefix}");
    let mut attrs = vec![
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", id),
        ("Version", "2.0"),
        ("IssueInstant", issue_instant),
        ("Destination", destination),
    ];
    if let Some(value) = in_response_to {
        attrs.push(("InResponseTo", value));
    }

    let mut writer = XmlWriter::new();
    writer.start(&root_name, &attrs);
    writer.text_element(&issuer_name, &[], issuer);
    writer.start(&status_name, &[]);
    writer.empty(&status_code_name, &[("Value", status_code::SUCCESS)]);
    writer.end(&status_name);
    writer.end(&root_name);
    Ok(writer.finish())
}

pub(super) fn render_default_logout_request(
    setting: &EntitySetting,
    meta: &Metadata,
    id: &str,
    issue_instant: &str,
    destination: &str,
    subject: &LogoutRequestSubject<'_>,
    name_id_format: &str,
) -> Result<String, SamlError> {
    validate_tag_prefix("protocol", &setting.tag_prefix_protocol)?;
    validate_tag_prefix("assertion", &setting.tag_prefix_assertion)?;

    let protocol_prefix = &setting.tag_prefix_protocol;
    let assertion_prefix = &setting.tag_prefix_assertion;
    let root_name = format!("{protocol_prefix}:LogoutRequest");
    let issuer_name = format!("{assertion_prefix}:Issuer");
    let name_id_name = format!("{assertion_prefix}:NameID");
    let session_index_name = format!("{protocol_prefix}:SessionIndex");
    let xmlns_protocol = format!("xmlns:{protocol_prefix}");
    let xmlns_assertion = format!("xmlns:{assertion_prefix}");
    let issuer = issuer_of(setting, meta);

    let attrs = [
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", id),
        ("Version", "2.0"),
        ("IssueInstant", issue_instant),
        ("Destination", destination),
    ];

    let mut writer = XmlWriter::new();
    writer.start(&root_name, &attrs);
    writer.text_element(&issuer_name, &[], &issuer);
    writer.text_element(
        &name_id_name,
        &[("Format", name_id_format)],
        subject.name_id,
    );
    for session_index in &subject.session_indexes {
        writer.text_element(&session_index_name, &[], session_index);
    }
    writer.end(&root_name);
    Ok(writer.finish())
}
