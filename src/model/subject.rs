use crate::config::NameIdFormat;

/// NameID value and optional format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    value: String,
    format: Option<NameIdFormat>,
}

impl NameId {
    /// Create a NameID value.
    pub fn new(value: impl Into<String>, format: Option<NameIdFormat>) -> Self {
        Self {
            value: value.into(),
            format,
        }
    }

    /// Borrow the NameID text.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// NameID format, when extracted.
    pub fn format(&self) -> Option<&NameIdFormat> {
        self.format.as_ref()
    }
}

/// AuthnRequest NameIDPolicy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameIdPolicy {
    format: Option<NameIdFormat>,
    allow_create: Option<bool>,
}

impl NameIdPolicy {
    /// Create a NameIDPolicy model.
    pub fn new(format: Option<NameIdFormat>, allow_create: Option<bool>) -> Self {
        Self {
            format,
            allow_create,
        }
    }

    /// Requested NameID format.
    pub fn format(&self) -> Option<&NameIdFormat> {
        self.format.as_ref()
    }

    /// Whether the IdP may create a new identifier.
    pub fn allow_create(&self) -> Option<bool> {
        self.allow_create
    }
}

/// SubjectConfirmation captured from the validated flow result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectConfirmation {
    raw_xml: String,
}

impl SubjectConfirmation {
    /// Create a subject confirmation from extractor context XML.
    pub fn from_raw_xml(raw_xml: impl Into<String>) -> Self {
        Self {
            raw_xml: raw_xml.into(),
        }
    }

    /// Borrow the raw confirmation XML captured by the extractor.
    pub fn raw_xml(&self) -> &str {
        &self.raw_xml
    }
}

/// SAML subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    name_id: NameId,
    confirmations: Vec<SubjectConfirmation>,
}

impl Subject {
    /// Create a subject.
    pub fn new(name_id: NameId, confirmations: Vec<SubjectConfirmation>) -> Self {
        Self {
            name_id,
            confirmations,
        }
    }

    /// Subject NameID.
    pub fn name_id(&self) -> &NameId {
        &self.name_id
    }

    /// Subject confirmations.
    pub fn confirmations(&self) -> &[SubjectConfirmation] {
        &self.confirmations
    }
}
