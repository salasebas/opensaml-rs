use core::marker::PhantomData;

use super::forms::{FormField, PostForm};
use crate::constants::Binding;
use crate::entity::BindingContext;
use crate::error::SamlError;
use crate::model::{
    AuthnRequest, EndpointUrl, LogoutRequest, LogoutResponse, MessageId, RelayState, SsoResponse,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundKind {
    Redirect,
    Post,
    SimpleSignPost,
}

/// Typed outbound browser action.
#[derive(Debug, Clone)]
pub struct Outbound<Message> {
    id: MessageId,
    relay_state: Option<RelayState>,
    kind: OutboundKind,
    redirect_url: Option<String>,
    post_form: Option<PostForm>,
    raw_context: BindingContext,
    _message: PhantomData<Message>,
}

impl<Message> Outbound<Message> {
    /// Message ID.
    pub fn id(&self) -> &MessageId {
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

impl TryFrom<BindingContext> for Outbound<AuthnRequest> {
    type Error = SamlError;

    fn try_from(raw_context: BindingContext) -> Result<Self, Self::Error> {
        outbound_from_context(raw_context, true)
    }
}

impl TryFrom<BindingContext> for Outbound<SsoResponse> {
    type Error = SamlError;

    fn try_from(raw_context: BindingContext) -> Result<Self, Self::Error> {
        outbound_from_context(raw_context, false)
    }
}

impl TryFrom<BindingContext> for Outbound<LogoutRequest> {
    type Error = SamlError;

    fn try_from(raw_context: BindingContext) -> Result<Self, Self::Error> {
        outbound_from_context(raw_context, true)
    }
}

impl TryFrom<BindingContext> for Outbound<LogoutResponse> {
    type Error = SamlError;

    fn try_from(raw_context: BindingContext) -> Result<Self, Self::Error> {
        outbound_from_context(raw_context, true)
    }
}

fn outbound_from_context<Message>(
    raw_context: BindingContext,
    allow_redirect: bool,
) -> Result<Outbound<Message>, SamlError> {
    let id = MessageId::try_new(raw_context.id.clone())?;
    let relay_state = raw_context
        .relay_state
        .clone()
        .map(RelayState::try_new)
        .transpose()?;
    match raw_context.binding {
        Binding::Redirect => {
            if !allow_redirect {
                return Err(SamlError::UndefinedBinding);
            }
            EndpointUrl::try_new(raw_context.context.clone())?;
            Ok(Outbound {
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
            Ok(Outbound {
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
            Ok(Outbound {
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
    let action = EndpointUrl::try_new(context.entity_endpoint.clone())?;
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
