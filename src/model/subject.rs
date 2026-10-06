use crate::config::NameIdFormat;

/// NameID value, format, and optional qualifier attributes.
///
/// [`Self::new`] leaves the qualifiers unset. Response generation copies the
/// value and format only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    value: String,
    format: Option<NameIdFormat>,
    name_qualifier: Option<String>,
    sp_name_qualifier: Option<String>,
    sp_provided_id: Option<String>,
}

impl NameId {
    /// Create a NameID value.
    pub fn new(value: impl Into<String>, format: Option<NameIdFormat>) -> Self {
        Self::with_qualifiers(value, format, None, None, None)
    }

    /// Create a NameID with qualifier attributes.
    ///
    /// `None` omits the attribute. `Some("")` is an empty value.
    pub fn with_qualifiers(
        value: impl Into<String>,
        format: Option<NameIdFormat>,
        name_qualifier: Option<String>,
        sp_name_qualifier: Option<String>,
        sp_provided_id: Option<String>,
    ) -> Self {
        Self {
            value: value.into(),
            format,
            name_qualifier,
            sp_name_qualifier,
            sp_provided_id,
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

    /// `NameQualifier`, when present.
    pub fn name_qualifier(&self) -> Option<&str> {
        self.name_qualifier.as_deref()
    }

    /// `SPNameQualifier`, when present.
    pub fn sp_name_qualifier(&self) -> Option<&str> {
        self.sp_name_qualifier.as_deref()
    }

    /// `SPProvidedID`, when present.
    pub fn sp_provided_id(&self) -> Option<&str> {
        self.sp_provided_id.as_deref()
    }
}

/// AuthnRequest NameIDPolicy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameIdPolicy {
    format: Option<NameIdFormat>,
    creation_request: NameIdCreationRequest,
}

/// AuthnRequest NameID creation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameIdCreationRequest {
    /// The request did not specify whether the IdP may create a new identifier.
    Unspecified,
    /// The IdP may create a new identifier.
    AllowCreate,
    /// The IdP must not create a new identifier.
    DoNotAllowCreate,
}

impl NameIdPolicy {
    /// Create a NameIDPolicy model.
    pub fn new(format: Option<NameIdFormat>, creation_request: NameIdCreationRequest) -> Self {
        Self {
            format,
            creation_request,
        }
    }

    /// Create a NameIDPolicy without an AllowCreate preference.
    pub fn unspecified(format: Option<NameIdFormat>) -> Self {
        Self::new(format, NameIdCreationRequest::Unspecified)
    }

    /// Create a NameIDPolicy allowing the IdP to create a new identifier.
    pub fn allow_creation(format: Option<NameIdFormat>) -> Self {
        Self::new(format, NameIdCreationRequest::AllowCreate)
    }

    /// Create a NameIDPolicy forbidding the IdP from creating a new identifier.
    pub fn disallow_creation(format: Option<NameIdFormat>) -> Self {
        Self::new(format, NameIdCreationRequest::DoNotAllowCreate)
    }

    pub(crate) fn from_parsed(
        format: Option<NameIdFormat>,
        allow_create: Option<bool>,
    ) -> Option<Self> {
        if format.is_none() && allow_create.is_none() {
            return None;
        }
        Some(match allow_create {
            Some(true) => Self::allow_creation(format),
            Some(false) => Self::disallow_creation(format),
            None => Self::unspecified(format),
        })
    }

    /// Requested NameID format.
    pub fn format(&self) -> Option<&NameIdFormat> {
        self.format.as_ref()
    }

    /// NameID creation request.
    pub fn creation_request(&self) -> NameIdCreationRequest {
        self.creation_request
    }

    /// Whether the IdP may create a new identifier.
    pub fn allow_create(&self) -> Option<bool> {
        match self.creation_request {
            NameIdCreationRequest::Unspecified => None,
            NameIdCreationRequest::AllowCreate => Some(true),
            NameIdCreationRequest::DoNotAllowCreate => Some(false),
        }
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

/// Subject requested by an `<AuthnRequest>` (Core §3.4.1).
///
/// The identity provider decides whether an assertion subject strongly matches
/// (Core §3.4.1.4, §3.3.4, Errata 05 E75). This library does not compare them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedSubject {
    identifier: RequestedSubjectIdentifier,
    confirmations: Vec<SubjectConfirmation>,
}

/// Identifier inside a requested [`RequestedSubject`] (Core §3.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedSubjectIdentifier {
    /// No `<BaseID>`, `<NameID>`, or `<EncryptedID>`. The presenter is the subject.
    NoIdentifier,
    /// `<NameID>` content and attributes.
    NameId(NameId),
    /// `<BaseID>`, not decoded.
    BaseId,
    /// `<EncryptedID>`, not decrypted.
    EncryptedId,
}

impl RequestedSubject {
    pub(crate) fn new(
        identifier: RequestedSubjectIdentifier,
        confirmations: Vec<SubjectConfirmation>,
    ) -> Self {
        Self {
            identifier,
            confirmations,
        }
    }

    /// Requested identifier.
    pub fn identifier(&self) -> &RequestedSubjectIdentifier {
        &self.identifier
    }

    /// `<NameID>` when the identifier is [`RequestedSubjectIdentifier::NameId`].
    pub fn name_id(&self) -> Option<&NameId> {
        match &self.identifier {
            RequestedSubjectIdentifier::NameId(name_id) => Some(name_id),
            RequestedSubjectIdentifier::NoIdentifier
            | RequestedSubjectIdentifier::BaseId
            | RequestedSubjectIdentifier::EncryptedId => None,
        }
    }

    /// `<SubjectConfirmation>` elements, in document order.
    ///
    /// An empty slice means the presenter is the only attesting entity
    /// (Core §3.4.1).
    pub fn confirmations(&self) -> &[SubjectConfirmation] {
        &self.confirmations
    }
}
