use crate::error::SamlError;

pub(crate) fn validate_crypto_xml_prefix(name: &str, prefix: &str) -> Result<(), SamlError> {
    if prefix.is_empty() {
        return Err(SamlError::Invalid(format!(
            "{name} XML prefix cannot be empty"
        )));
    }
    if matches!(prefix.to_ascii_lowercase().as_str(), "xml" | "xmlns") {
        return Err(SamlError::Invalid(format!("{name} XML prefix is reserved")));
    }

    let mut chars = prefix.chars();
    let first = chars
        .next()
        .ok_or_else(|| SamlError::Invalid(format!("{name} XML prefix cannot be empty")))?;
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(invalid_prefix(name));
    }
    if chars.any(|ch| !matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.')) {
        return Err(invalid_prefix(name));
    }
    Ok(())
}

fn invalid_prefix(name: &str) -> SamlError {
    SamlError::Invalid(format!("{name} XML prefix contains an invalid character"))
}
