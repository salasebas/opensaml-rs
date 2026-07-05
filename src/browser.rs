//! Typed browser binding, endpoint, outbound, inbound, and pending-state APIs.

use core::marker::PhantomData;

use crate::binding::base64_decode;
use crate::config::EntityId;
use crate::constants::{url_params, Binding};
use crate::entity::BindingContext;
use crate::error::SamlError;
use crate::metadata::Endpoint;
use crate::model::{AuthnRequest, RelayState, RelayStateState, RequestId, SamlInstant};
use crate::raw::HttpRequest;

/// Browser SSO request bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsoRequestBinding {
    /// HTTP-Redirect binding.
    Redirect,
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
}

impl SsoRequestBinding {
    /// Convert to the raw compatibility binding.
    pub fn as_binding(self) -> Binding {
        match self {
            Self::Redirect => Binding::Redirect,
            Self::Post => Binding::Post,
            Self::SimpleSign => Binding::SimpleSign,
        }
    }
}

impl From<SsoRequestBinding> for Binding {
    fn from(value: SsoRequestBinding) -> Self {
        value.as_binding()
    }
}

impl TryFrom<Binding> for SsoRequestBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Redirect => Ok(Self::Redirect),
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Artifact => Err(SamlError::UndefinedBinding),
        }
    }
}

/// Browser SSO response bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsoResponseBinding {
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
}

impl SsoResponseBinding {
    /// Convert to the raw compatibility binding.
    pub fn as_binding(self) -> Binding {
        match self {
            Self::Post => Binding::Post,
            Self::SimpleSign => Binding::SimpleSign,
        }
    }
}

impl From<SsoResponseBinding> for Binding {
    fn from(value: SsoResponseBinding) -> Self {
        value.as_binding()
    }
}

impl TryFrom<Binding> for SsoResponseBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Redirect | Binding::Artifact => Err(SamlError::UndefinedBinding),
        }
    }
}

/// Single Logout bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogoutBinding {
    /// HTTP-Redirect binding.
    Redirect,
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
}

impl LogoutBinding {
    /// Convert to the raw compatibility binding.
    pub fn as_binding(self) -> Binding {
        match self {
            Self::Redirect => Binding::Redirect,
            Self::Post => Binding::Post,
            Self::SimpleSign => Binding::SimpleSign,
        }
    }
}

impl From<LogoutBinding> for Binding {
    fn from(value: LogoutBinding) -> Self {
        value.as_binding()
    }
}

impl TryFrom<Binding> for LogoutBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Redirect => Ok(Self::Redirect),
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Artifact => Err(SamlError::UndefinedBinding),
        }
    }
}

/// Absolute HTTP(S) endpoint URL used by typed SAML endpoint wrappers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointUrl(String);

impl EndpointUrl {
    /// Validate and wrap an absolute HTTP(S) URL.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the URL is not absolute HTTP(S).
    pub fn new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        let parsed = url::Url::parse(&value).map_err(|err| SamlError::Invalid(err.to_string()))?;
        if matches!(parsed.scheme(), "http" | "https") && parsed.has_host() {
            return Ok(Self(value));
        }
        Err(SamlError::Invalid(
            "endpoint URL must be absolute HTTP(S)".into(),
        ))
    }

    /// Borrow the URL string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Single Sign-On service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoEndpoint {
    binding: SsoRequestBinding,
    url: EndpointUrl,
}

impl SsoEndpoint {
    /// Create an SSO endpoint from an already validated URL.
    pub fn new(binding: SsoRequestBinding, url: EndpointUrl) -> Self {
        Self { binding, url }
    }

    /// Create an HTTP-Redirect SSO endpoint.
    pub fn redirect(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::Redirect,
            EndpointUrl::new(url)?,
        ))
    }

    /// Create an HTTP-POST SSO endpoint.
    pub fn post(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(SsoRequestBinding::Post, EndpointUrl::new(url)?))
    }

    /// Create an HTTP-POST-SimpleSign SSO endpoint.
    pub fn simple_sign(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::SimpleSign,
            EndpointUrl::new(url)?,
        ))
    }

    /// Narrow a raw metadata endpoint into an SSO endpoint.
    pub fn try_from_raw(endpoint: Endpoint) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::try_from(endpoint.binding)?,
            EndpointUrl::new(endpoint.location)?,
        ))
    }

    /// Convert to the raw metadata endpoint shape.
    pub fn to_raw(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.as_binding(),
            location: self.url.as_str().to_string(),
            is_default: false,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> SsoRequestBinding {
        self.binding
    }

    /// Endpoint URL.
    pub fn url(&self) -> &EndpointUrl {
        &self.url
    }
}

/// Assertion Consumer Service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcsEndpoint {
    binding: SsoResponseBinding,
    url: EndpointUrl,
    index: Option<u16>,
    is_default: bool,
}

impl AcsEndpoint {
    /// Create an ACS endpoint from an already validated URL.
    pub fn new(binding: SsoResponseBinding, url: EndpointUrl) -> Self {
        Self {
            binding,
            url,
            index: None,
            is_default: false,
        }
    }

    /// Create an HTTP-POST ACS endpoint.
    pub fn post(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(SsoResponseBinding::Post, EndpointUrl::new(url)?))
    }

    /// Create an HTTP-POST-SimpleSign ACS endpoint.
    pub fn simple_sign(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoResponseBinding::SimpleSign,
            EndpointUrl::new(url)?,
        ))
    }

    /// Set the ACS index advertised in metadata.
    pub fn with_index(mut self, index: u16) -> Self {
        self.index = Some(index);
        self
    }

    /// Mark this ACS endpoint as the default endpoint in metadata.
    pub fn with_default(mut self, is_default: bool) -> Self {
        self.is_default = is_default;
        self
    }

    /// Narrow a raw metadata endpoint into an ACS endpoint.
    pub fn try_from_raw(endpoint: Endpoint) -> Result<Self, SamlError> {
        Ok(Self {
            binding: SsoResponseBinding::try_from(endpoint.binding)?,
            url: EndpointUrl::new(endpoint.location)?,
            index: None,
            is_default: endpoint.is_default,
        })
    }

    /// Convert to the raw metadata endpoint shape.
    pub fn to_raw(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.as_binding(),
            location: self.url.as_str().to_string(),
            is_default: self.is_default,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> SsoResponseBinding {
        self.binding
    }

    /// Endpoint URL.
    pub fn url(&self) -> &EndpointUrl {
        &self.url
    }

    /// ACS index advertised in metadata.
    pub fn index(&self) -> Option<u16> {
        self.index
    }

    /// Whether this ACS endpoint is the default metadata endpoint.
    pub fn is_default(&self) -> bool {
        self.is_default
    }
}

/// Single Logout service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SloEndpoint {
    binding: LogoutBinding,
    url: EndpointUrl,
}

impl SloEndpoint {
    /// Create an SLO endpoint from an already validated URL.
    pub fn new(binding: LogoutBinding, url: EndpointUrl) -> Self {
        Self { binding, url }
    }

    /// Create an HTTP-Redirect SLO endpoint.
    pub fn redirect(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(LogoutBinding::Redirect, EndpointUrl::new(url)?))
    }

    /// Create an HTTP-POST SLO endpoint.
    pub fn post(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(LogoutBinding::Post, EndpointUrl::new(url)?))
    }

    /// Create an HTTP-POST-SimpleSign SLO endpoint.
    pub fn simple_sign(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(LogoutBinding::SimpleSign, EndpointUrl::new(url)?))
    }

    /// Narrow a raw metadata endpoint into an SLO endpoint.
    pub fn try_from_raw(endpoint: Endpoint) -> Result<Self, SamlError> {
        Ok(Self::new(
            LogoutBinding::try_from(endpoint.binding)?,
            EndpointUrl::new(endpoint.location)?,
        ))
    }

    /// Convert to the raw metadata endpoint shape.
    pub fn to_raw(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.as_binding(),
            location: self.url.as_str().to_string(),
            is_default: false,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> LogoutBinding {
        self.binding
    }

    /// Endpoint URL.
    pub fn url(&self) -> &EndpointUrl {
        &self.url
    }
}

/// HTML form field emitted or consumed by browser POST bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormField {
    name: String,
    value: String,
}

impl FormField {
    /// Create a form field.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Field value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Typed auto-submit POST form data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostForm {
    action: EndpointUrl,
    fields: Vec<FormField>,
}

impl PostForm {
    /// Create a POST form.
    pub fn new(action: EndpointUrl, fields: Vec<FormField>) -> Self {
        Self { action, fields }
    }

    /// Form action URL.
    pub fn action(&self) -> &EndpointUrl {
        &self.action
    }

    /// Hidden fields.
    pub fn fields(&self) -> &[FormField] {
        &self.fields
    }

    /// Return the first field value for a name.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name() == name)
            .map(FormField::value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundKind {
    Redirect,
    Post,
    SimpleSignPost,
}

/// Typed outbound browser action.
#[derive(Debug, Clone)]
pub struct Outbound<Message> {
    id: RequestId,
    relay_state: Option<RelayState>,
    kind: OutboundKind,
    redirect_url: Option<String>,
    post_form: Option<PostForm>,
    raw_context: BindingContext,
    _message: PhantomData<Message>,
}

impl<Message> Outbound<Message> {
    /// Message ID.
    pub fn id(&self) -> &RequestId {
        &self.id
    }

    /// RelayState parameter, when present.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }

    /// Redirect URL for Redirect actions.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::UndefinedBinding`] when this action is not Redirect.
    pub fn redirect_url(&self) -> Result<&str, SamlError> {
        if self.kind == OutboundKind::Redirect {
            return self
                .redirect_url
                .as_deref()
                .ok_or_else(|| SamlError::Invalid("missing redirect URL".into()));
        }
        Err(SamlError::UndefinedBinding)
    }

    /// POST form for POST and SimpleSign actions.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::UndefinedBinding`] when this action is Redirect.
    pub fn post_form(&self) -> Result<&PostForm, SamlError> {
        if matches!(self.kind, OutboundKind::Post | OutboundKind::SimpleSignPost) {
            return self
                .post_form
                .as_ref()
                .ok_or_else(|| SamlError::Invalid("missing POST form".into()));
        }
        Err(SamlError::UndefinedBinding)
    }

    /// Raw compatibility context used to build this typed action.
    pub fn raw_context(&self) -> &BindingContext {
        &self.raw_context
    }

    /// Consume the typed action and return the raw compatibility context.
    pub fn into_raw_context(self) -> BindingContext {
        self.raw_context
    }
}

impl<Message> TryFrom<BindingContext> for Outbound<Message> {
    type Error = SamlError;

    fn try_from(raw_context: BindingContext) -> Result<Self, Self::Error> {
        let id = RequestId::new(raw_context.id.clone())?;
        let relay_state = raw_context.relay_state.clone().map(RelayState::new);
        match raw_context.binding {
            Binding::Redirect => {
                EndpointUrl::new(raw_context.context.clone())?;
                Ok(Self {
                    id,
                    relay_state,
                    kind: OutboundKind::Redirect,
                    redirect_url: Some(raw_context.context.clone()),
                    post_form: None,
                    raw_context,
                    _message: PhantomData,
                })
            }
            Binding::Post => {
                reject_detached_signature_for_post(&raw_context)?;
                let form = post_form_from_context(&raw_context, false)?;
                Ok(Self {
                    id,
                    relay_state,
                    kind: OutboundKind::Post,
                    redirect_url: None,
                    post_form: Some(form),
                    raw_context,
                    _message: PhantomData,
                })
            }
            Binding::SimpleSign => {
                require_complete_detached_signature(&raw_context)?;
                let form = post_form_from_context(&raw_context, true)?;
                Ok(Self {
                    id,
                    relay_state,
                    kind: OutboundKind::SimpleSignPost,
                    redirect_url: None,
                    post_form: Some(form),
                    raw_context,
                    _message: PhantomData,
                })
            }
            Binding::Artifact => Err(SamlError::UndefinedBinding),
        }
    }
}

fn reject_partial_detached_signature(context: &BindingContext) -> Result<(), SamlError> {
    if context.sig_alg.is_some() != context.signature.is_some() {
        return Err(SamlError::Invalid(
            "partial detached signature state is invalid".into(),
        ));
    }
    Ok(())
}

fn reject_detached_signature_for_post(context: &BindingContext) -> Result<(), SamlError> {
    if context.sig_alg.is_some() || context.signature.is_some() {
        return Err(SamlError::Invalid(
            "POST outbound must not carry detached signature fields".into(),
        ));
    }
    Ok(())
}

fn require_complete_detached_signature(context: &BindingContext) -> Result<(), SamlError> {
    reject_partial_detached_signature(context)?;
    match (&context.sig_alg, &context.signature) {
        (Some(_), Some(_)) => Ok(()),
        _ => Err(SamlError::Invalid(
            "SimpleSign requires SigAlg and Signature".into(),
        )),
    }
}

fn post_form_from_context(
    context: &BindingContext,
    include_signature: bool,
) -> Result<PostForm, SamlError> {
    let action = EndpointUrl::new(context.entity_endpoint.clone())?;
    context.try_post_form()?;
    let mut fields = vec![FormField::new(
        context.request_type,
        context.context.clone(),
    )];
    if let Some(relay_state) = &context.relay_state {
        fields.push(FormField::new("RelayState", relay_state.clone()));
    }
    if include_signature {
        fields.push(FormField::new(
            "SigAlg",
            context.sig_alg.clone().unwrap_or_default(),
        ));
        fields.push(FormField::new(
            "Signature",
            context.signature.clone().unwrap_or_default(),
        ));
    }
    Ok(PostForm::new(action, fields))
}

/// Typed browser input for inbound SAML messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserInput<Message> {
    /// HTTP-Redirect input as a raw query string.
    Redirect {
        /// Raw URL query, with or without a leading `?`.
        raw_query: String,
        /// Message marker.
        _message: PhantomData<Message>,
    },
    /// HTTP-POST input as parsed form fields.
    Post {
        /// Parsed form fields.
        fields: Vec<FormField>,
        /// Message marker.
        _message: PhantomData<Message>,
    },
    /// HTTP-POST-SimpleSign input.
    SimpleSignPost {
        /// Raw form body.
        raw_body: String,
        /// Parsed form fields.
        fields: Vec<FormField>,
        /// Message marker.
        _message: PhantomData<Message>,
    },
}

impl<Message> BrowserInput<Message> {
    /// Create Redirect input from a raw query string.
    pub fn redirect(raw_query: impl Into<String>) -> Self {
        Self::Redirect {
            raw_query: raw_query.into(),
            _message: PhantomData,
        }
    }

    /// Create POST input from parsed fields.
    pub fn post(fields: Vec<FormField>) -> Self {
        Self::Post {
            fields,
            _message: PhantomData,
        }
    }

    /// Create SimpleSign POST input from a raw body and parsed fields.
    pub fn simple_sign_post(raw_body: impl Into<String>, fields: Vec<FormField>) -> Self {
        Self::SimpleSignPost {
            raw_body: raw_body.into(),
            fields,
            _message: PhantomData,
        }
    }

    /// Parse a raw `application/x-www-form-urlencoded` SimpleSign body.
    pub fn simple_sign_raw_body(raw_body: impl Into<String>) -> Self {
        let raw_body = raw_body.into();
        let fields = parse_form_fields(&raw_body);
        Self::simple_sign_post(raw_body, fields)
    }
}

impl<Message> TryFrom<BrowserInput<Message>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: BrowserInput<Message>) -> Result<Self, Self::Error> {
        match value {
            BrowserInput::Redirect { raw_query, .. } => {
                let raw_query = raw_query.trim_start_matches('?').to_string();
                let octet_string = redirect_octet_from_raw_query(&raw_query)?;
                let query = parse_form_pairs(&raw_query);
                Ok(HttpRequest {
                    query,
                    octet_string,
                    ..Default::default()
                })
            }
            BrowserInput::Post { fields, .. } => Ok(HttpRequest::post(fields_to_pairs(fields))),
            BrowserInput::SimpleSignPost {
                raw_body,
                mut fields,
                ..
            } => {
                if fields.is_empty() {
                    fields = parse_form_fields(&raw_body);
                }
                let octet_string = simplesign_octet_from_fields(&fields)?;
                let mut request = HttpRequest::post(fields_to_pairs(fields));
                request.octet_string = Some(octet_string);
                Ok(request)
            }
        }
    }
}

struct RawQueryParam<'a> {
    name: &'a str,
    encoded_value: &'a str,
}

fn raw_query_params(raw_query: &str) -> impl Iterator<Item = RawQueryParam<'_>> {
    raw_query
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.split_once('=') {
            Some((name, encoded_value)) => RawQueryParam {
                name,
                encoded_value,
            },
            None => RawQueryParam {
                name: segment,
                encoded_value: "",
            },
        })
}

fn unique_encoded_query_value<'a>(
    params: &'a [RawQueryParam<'a>],
    name: &str,
) -> Result<Option<&'a str>, SamlError> {
    let mut values = params
        .iter()
        .filter(|param| param.name == name)
        .map(|param| param.encoded_value);
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::Invalid(format!(
            "ambiguous Redirect field {name}"
        )));
    }
    Ok(first)
}

fn redirect_octet_from_raw_query(raw_query: &str) -> Result<Option<String>, SamlError> {
    let params: Vec<_> = raw_query_params(raw_query).collect();
    let request = unique_encoded_query_value(&params, url_params::SAML_REQUEST)?;
    let response = unique_encoded_query_value(&params, url_params::SAML_RESPONSE)?;
    let (message_name, message_value) = match (request, response) {
        (Some(request), None) => (url_params::SAML_REQUEST, request),
        (None, Some(response)) => (url_params::SAML_RESPONSE, response),
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => {
            return Err(SamlError::Invalid(
                "expected exactly one Redirect SAML message field".into(),
            ))
        }
    };
    let relay_state = unique_encoded_query_value(&params, url_params::RELAY_STATE)?;
    let sig_alg = unique_encoded_query_value(&params, url_params::SIG_ALG)?;
    let signature = unique_encoded_query_value(&params, url_params::SIGNATURE)?;

    let sig_alg = match (sig_alg, signature) {
        (Some(sig_alg), Some(_)) => sig_alg,
        (None, None) => return Ok(None),
        _ => {
            return Err(SamlError::Invalid(
                "incomplete Redirect signature parameters".into(),
            ))
        }
    };

    Ok(Some(match relay_state {
        Some(relay_state) => {
            format!("{message_name}={message_value}&RelayState={relay_state}&SigAlg={sig_alg}")
        }
        None => format!("{message_name}={message_value}&SigAlg={sig_alg}"),
    }))
}

fn parse_form_pairs(raw: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(raw.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn parse_form_fields(raw: &str) -> Vec<FormField> {
    parse_form_pairs(raw)
        .into_iter()
        .map(|(name, value)| FormField::new(name, value))
        .collect()
}

fn fields_to_pairs(fields: Vec<FormField>) -> Vec<(String, String)> {
    fields
        .into_iter()
        .map(|field| (field.name, field.value))
        .collect()
}

fn field_value<'a>(fields: &'a [FormField], name: &str) -> Result<Option<&'a str>, SamlError> {
    let mut values = fields
        .iter()
        .filter(|field| field.name() == name)
        .map(FormField::value);
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::Invalid("ambiguous form field".into()));
    }
    Ok(first)
}

fn simplesign_octet_from_fields(fields: &[FormField]) -> Result<String, SamlError> {
    let (message_name, encoded) = match (
        field_value(fields, url_params::SAML_REQUEST)?,
        field_value(fields, url_params::SAML_RESPONSE)?,
    ) {
        (Some(request), None) => (url_params::SAML_REQUEST, request),
        (None, Some(response)) => (url_params::SAML_RESPONSE, response),
        _ => {
            return Err(SamlError::Invalid(
                "expected exactly one SAML message field".into(),
            ))
        }
    };
    let raw_xml = String::from_utf8(base64_decode(encoded)?)
        .map_err(|err| SamlError::Xml(err.to_string()))?;
    let sig_alg = field_value(fields, url_params::SIG_ALG)?.ok_or(SamlError::MissingSigAlg)?;
    let relay_state = field_value(fields, url_params::RELAY_STATE)?;
    Ok(match relay_state {
        Some(relay_state) => {
            format!("{message_name}={raw_xml}&RelayState={relay_state}&SigAlg={sig_alg}")
        }
        None => format!("{message_name}={raw_xml}&SigAlg={sig_alg}"),
    })
}

/// Persistable correlation snapshot for a pending SAML message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSnapshot<Message> {
    /// Correlation ID.
    pub id: String,
    /// Exact RelayState state.
    pub relay_state: RelayStateState,
    /// Peer entity ID.
    pub peer_entity_id: String,
    /// Expected response binding keyword.
    pub expected_binding: String,
    /// Selected request binding keyword, if tracked.
    pub request_binding: Option<String>,
    /// Selected ACS URL.
    pub acs_url: String,
    /// Selected ACS binding keyword.
    pub acs_binding: String,
    /// Selected ACS index, if any.
    pub acs_index: Option<u16>,
    /// Whether the selected ACS was default.
    pub acs_is_default: bool,
    /// Issue instant, if recorded.
    pub issued_at: Option<SamlInstant>,
    /// Expiration instant, if recorded.
    pub expires_at: Option<SamlInstant>,
    _message: PhantomData<Message>,
}

impl PendingSnapshot<AuthnRequest> {
    /// Build an AuthnRequest snapshot from persistence fields.
    pub fn authn_request(
        id: impl Into<String>,
        relay_state: RelayStateState,
        peer_entity_id: impl Into<String>,
        expected_binding: impl Into<String>,
        acs_url: impl Into<String>,
        acs_binding: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            relay_state,
            peer_entity_id: peer_entity_id.into(),
            expected_binding: expected_binding.into(),
            request_binding: None,
            acs_url: acs_url.into(),
            acs_binding: acs_binding.into(),
            acs_index: None,
            acs_is_default: false,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        }
    }
}

/// Pending SAML message correlation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending<Message> {
    id: RequestId,
    relay_state: RelayStateState,
    request_binding: Option<SsoRequestBinding>,
    response_binding: Option<SsoResponseBinding>,
    peer_entity_id: EntityId,
    issued_at: Option<SamlInstant>,
    expires_at: Option<SamlInstant>,
    _message: PhantomData<Message>,
}

impl<Message> Pending<Message> {
    /// Create pending message state.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when RelayState or peer entity ID are malformed.
    pub fn new(
        id: RequestId,
        relay_state: RelayStateState,
        request_binding: Option<SsoRequestBinding>,
        response_binding: Option<SsoResponseBinding>,
        peer_entity_id: EntityId,
    ) -> Result<Self, SamlError> {
        relay_state.validate()?;
        EntityId::try_new(peer_entity_id.as_str().to_string())?;
        Ok(Self {
            id,
            relay_state,
            request_binding,
            response_binding,
            peer_entity_id,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        })
    }

    /// Record an issue instant.
    pub fn with_issue_instant(mut self, issued_at: SamlInstant) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    /// Record an expiration instant.
    pub fn with_expiration(mut self, expires_at: SamlInstant) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Request ID.
    pub fn id(&self) -> &RequestId {
        &self.id
    }

    /// RelayState state.
    pub fn relay_state(&self) -> &RelayStateState {
        &self.relay_state
    }

    /// Request binding, when tracked.
    pub fn request_binding(&self) -> Option<SsoRequestBinding> {
        self.request_binding
    }

    /// Expected response binding, when tracked.
    pub fn response_binding(&self) -> Option<SsoResponseBinding> {
        self.response_binding
    }

    /// Peer entity ID.
    pub fn peer_entity_id(&self) -> &EntityId {
        &self.peer_entity_id
    }

    /// Issue instant, if recorded.
    pub fn issued_at(&self) -> Option<&SamlInstant> {
        self.issued_at.as_ref()
    }

    /// Expiration instant, if recorded.
    pub fn expires_at(&self) -> Option<&SamlInstant> {
        self.expires_at.as_ref()
    }

    /// Build a persistable snapshot.
    pub fn snapshot(&self) -> PendingSnapshot<Message> {
        PendingSnapshot {
            id: self.id.as_str().to_string(),
            relay_state: self.relay_state.clone(),
            peer_entity_id: self.peer_entity_id.as_str().to_string(),
            expected_binding: self
                .response_binding
                .map(|binding| binding.as_binding().short_name().to_string())
                .unwrap_or_default(),
            request_binding: self
                .request_binding
                .map(|binding| binding.as_binding().short_name().to_string()),
            acs_url: String::new(),
            acs_binding: String::new(),
            acs_index: None,
            acs_is_default: false,
            issued_at: self.issued_at.clone(),
            expires_at: self.expires_at.clone(),
            _message: PhantomData,
        }
    }

    /// Reconstruct pending state from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when any snapshot field is malformed or inconsistent.
    pub fn from_snapshot(snapshot: PendingSnapshot<Message>) -> Result<Self, SamlError> {
        snapshot.relay_state.validate()?;
        if snapshot.expires_at.is_some() && snapshot.issued_at.is_none() {
            return Err(SamlError::Invalid(
                "pending snapshot expiration requires an issue instant".into(),
            ));
        }
        let request_binding = snapshot
            .request_binding
            .as_deref()
            .map(sso_request_binding_from_snapshot_value)
            .transpose()?;
        let response_binding = if snapshot.expected_binding.is_empty() {
            None
        } else {
            Some(sso_response_binding_from_snapshot_value(
                &snapshot.expected_binding,
            )?)
        };
        Ok(Self {
            id: RequestId::new(snapshot.id)?,
            relay_state: snapshot.relay_state,
            request_binding,
            response_binding,
            peer_entity_id: EntityId::try_new(snapshot.peer_entity_id)?,
            issued_at: snapshot.issued_at,
            expires_at: snapshot.expires_at,
            _message: PhantomData,
        })
    }
}

/// Pending AuthnRequest correlation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthnRequest {
    request_id: RequestId,
    relay_state: RelayStateState,
    acs: AcsEndpoint,
    response_binding: SsoResponseBinding,
    idp_entity_id: EntityId,
    issued_at: Option<SamlInstant>,
    expires_at: Option<SamlInstant>,
}

impl PendingAuthnRequest {
    /// Create pending AuthnRequest state without storing keys or metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the RelayState state is malformed,
    /// the IdP entity ID is empty, or the selected ACS binding does not match
    /// the expected response binding.
    pub fn new(
        request_id: RequestId,
        relay_state: RelayStateState,
        acs: AcsEndpoint,
        response_binding: SsoResponseBinding,
        idp_entity_id: EntityId,
    ) -> Result<Self, SamlError> {
        relay_state.validate()?;
        EntityId::try_new(idp_entity_id.as_str().to_string())?;
        if acs.binding() != response_binding {
            return Err(SamlError::Invalid(
                "ACS binding must match expected response binding".into(),
            ));
        }
        Ok(Self {
            request_id,
            relay_state,
            acs,
            response_binding,
            idp_entity_id,
            issued_at: None,
            expires_at: None,
        })
    }

    /// Record an issue instant.
    pub fn with_issue_instant(mut self, issued_at: SamlInstant) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    /// Record an expiration instant.
    pub fn with_expiration(mut self, expires_at: SamlInstant) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Reconstruct pending AuthnRequest state from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when any snapshot field is malformed or
    /// inconsistent.
    pub fn from_snapshot(snapshot: PendingSnapshot<AuthnRequest>) -> Result<Self, SamlError> {
        snapshot.relay_state.validate()?;
        if snapshot.expires_at.is_some() && snapshot.issued_at.is_none() {
            return Err(SamlError::Invalid(
                "pending snapshot expiration requires an issue instant".into(),
            ));
        }
        let request_id = RequestId::new(snapshot.id)?;
        let idp_entity_id = EntityId::try_new(snapshot.peer_entity_id)?;
        let response_binding =
            sso_response_binding_from_snapshot_value(&snapshot.expected_binding)?;
        let acs_binding = sso_response_binding_from_snapshot_value(&snapshot.acs_binding)?;
        let mut acs = AcsEndpoint::new(acs_binding, EndpointUrl::new(snapshot.acs_url)?)
            .with_default(snapshot.acs_is_default);
        if let Some(index) = snapshot.acs_index {
            acs = acs.with_index(index);
        }
        let mut pending = Self::new(
            request_id,
            snapshot.relay_state,
            acs,
            response_binding,
            idp_entity_id,
        )?;
        pending.issued_at = snapshot.issued_at;
        pending.expires_at = snapshot.expires_at;
        Ok(pending)
    }

    /// Build a persistable snapshot.
    pub fn snapshot(&self) -> PendingSnapshot<AuthnRequest> {
        let mut snapshot = PendingSnapshot::authn_request(
            self.request_id.as_str(),
            self.relay_state.clone(),
            self.idp_entity_id.as_str(),
            self.response_binding.as_binding().short_name(),
            self.acs.url().as_str(),
            self.acs.binding().as_binding().short_name(),
        );
        snapshot.acs_index = self.acs.index();
        snapshot.acs_is_default = self.acs.is_default();
        snapshot.issued_at = self.issued_at.clone();
        snapshot.expires_at = self.expires_at.clone();
        snapshot
    }

    /// Request ID.
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// RelayState state.
    pub fn relay_state(&self) -> &RelayStateState {
        &self.relay_state
    }

    /// Selected ACS endpoint.
    pub fn acs(&self) -> &AcsEndpoint {
        &self.acs
    }

    /// Expected response binding.
    pub fn response_binding(&self) -> SsoResponseBinding {
        self.response_binding
    }

    /// Selected IdP entity ID.
    pub fn idp_entity_id(&self) -> &EntityId {
        &self.idp_entity_id
    }

    /// Issue instant, if recorded.
    pub fn issued_at(&self) -> Option<&SamlInstant> {
        self.issued_at.as_ref()
    }

    /// Expiration instant, if recorded.
    pub fn expires_at(&self) -> Option<&SamlInstant> {
        self.expires_at.as_ref()
    }
}

fn sso_response_binding_from_snapshot_value(value: &str) -> Result<SsoResponseBinding, SamlError> {
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or(SamlError::UndefinedBinding)?;
    SsoResponseBinding::try_from(binding)
}

fn sso_request_binding_from_snapshot_value(value: &str) -> Result<SsoRequestBinding, SamlError> {
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or(SamlError::UndefinedBinding)?;
    SsoRequestBinding::try_from(binding)
}

/// Started browser flow with pending state and outbound browser action.
#[derive(Debug, Clone)]
pub struct Started<Message> {
    /// Pending correlation state.
    pub pending: Pending<Message>,
    /// Outbound browser action.
    pub outbound: Outbound<Message>,
}
