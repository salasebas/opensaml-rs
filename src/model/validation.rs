use super::{AssertionId, MessageId};
use crate::error::SamlError;
use time::{Duration, OffsetDateTime};

/// Clock skew applied to SAML time-window checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockSkew {
    not_before_ms: i64,
    not_on_or_after_ms: i64,
}

impl ClockSkew {
    /// No clock skew tolerance.
    pub fn strict() -> Self {
        Self {
            not_before_ms: 0,
            not_on_or_after_ms: 0,
        }
    }

    /// Build clock skew from the raw SAML drift values, in milliseconds.
    ///
    /// The first argument applies to `NotBefore`; the second applies to
    /// `NotOnOrAfter`.
    pub fn from_millis(not_before_ms: i64, not_on_or_after_ms: i64) -> Self {
        Self {
            not_before_ms,
            not_on_or_after_ms,
        }
    }

    /// Return a copy with the `NotBefore` skew, in milliseconds.
    pub fn with_not_before_millis(mut self, not_before_ms: i64) -> Self {
        self.not_before_ms = not_before_ms;
        self
    }

    /// Return a copy with the `NotOnOrAfter` skew, in milliseconds.
    pub fn with_not_on_or_after_millis(mut self, not_on_or_after_ms: i64) -> Self {
        self.not_on_or_after_ms = not_on_or_after_ms;
        self
    }

    /// `NotBefore` skew, in milliseconds.
    pub fn not_before_millis(self) -> i64 {
        self.not_before_ms
    }

    /// `NotOnOrAfter` skew, in milliseconds.
    pub fn not_on_or_after_millis(self) -> i64 {
        self.not_on_or_after_ms
    }

    /// Return the raw `(NotBefore, NotOnOrAfter)` drift tuple.
    pub fn as_millis(self) -> (i64, i64) {
        (self.not_before_ms, self.not_on_or_after_ms)
    }
}

impl Default for ClockSkew {
    fn default() -> Self {
        Self::strict()
    }
}

/// Replay cache key derived from a validated SAML message.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[expect(
    clippy::enum_variant_names,
    reason = "variants name the exact SAML identifier family used in stable cache keys"
)]
pub enum ReplayKey {
    /// SAML AuthnRequest ID.
    AuthnRequestId(MessageId),
    /// SAML LogoutRequest ID.
    LogoutRequestId(MessageId),
    /// SAML LogoutResponse ID.
    LogoutResponseId(MessageId),
    /// SAML protocol response ID.
    ResponseId(MessageId),
    /// SAML assertion ID.
    AssertionId(AssertionId),
}

impl ReplayKey {
    /// Stable key family.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AuthnRequestId(_) => "authn_request_id",
            Self::LogoutRequestId(_) => "logout_request_id",
            Self::LogoutResponseId(_) => "logout_response_id",
            Self::ResponseId(_) => "response_id",
            Self::AssertionId(_) => "assertion_id",
        }
    }

    /// Raw SAML identifier value.
    pub fn value(&self) -> &str {
        match self {
            Self::AuthnRequestId(id) | Self::LogoutRequestId(id) | Self::LogoutResponseId(id) => {
                id.as_str()
            }
            Self::ResponseId(id) => id.as_str(),
            Self::AssertionId(id) => id.as_str(),
        }
    }

    /// Namespaced key suitable for cache storage and replay error payloads.
    pub fn cache_key(&self) -> String {
        format!("{}:{}", self.kind(), self.value())
    }
}

/// Caller-owned replay cache.
///
/// Implementations should atomically reject duplicate keys and return
/// [`SamlError::ReplayDetected`] for duplicate SAML messages.
pub trait ReplayCache {
    /// Check whether `key` has already been seen, then store it until
    /// `expires_at` if it is new.
    ///
    /// # Errors
    ///
    /// Implementations should return [`SamlError::ReplayDetected`] for
    /// duplicate keys. They may also return storage-specific failures mapped
    /// to [`SamlError`] if cache access fails.
    fn check_and_store(
        &mut self,
        key: ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<(), SamlError>;
}

/// Replay behavior for typed inbound browser flows.
#[non_exhaustive]
pub enum ReplayPolicy<'a> {
    /// Skip replay checks for raw compatibility migrations.
    DisabledForCompatibility,
    /// Require the caller to provide replay storage.
    RequireCache(&'a mut dyn ReplayCache),
}

/// Caller-owned validation context for typed inbound SAML messages.
pub struct SamlValidationContext<'a> {
    now: OffsetDateTime,
    clock_skew: ClockSkew,
    replay: ReplayPolicy<'a>,
    replay_retention: Option<Duration>,
}

impl<'a> SamlValidationContext<'a> {
    /// Build a validation context with strict clock skew.
    pub fn new(now: OffsetDateTime, replay: ReplayPolicy<'a>) -> Self {
        Self {
            now,
            clock_skew: ClockSkew::strict(),
            replay,
            replay_retention: None,
        }
    }

    /// Set clock skew tolerance for SAML time windows.
    pub fn with_clock_skew(mut self, clock_skew: ClockSkew) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    /// Set explicit replay retention for protocol messages that do not carry a
    /// SAML `NotOnOrAfter` value suitable for cache expiry.
    pub fn with_replay_retention(mut self, retention: Duration) -> Self {
        self.replay_retention = Some(retention);
        self
    }

    /// Validation instant supplied by the caller.
    pub fn now(&self) -> OffsetDateTime {
        self.now
    }

    /// Clock skew applied to time-window checks.
    pub fn clock_skew(&self) -> ClockSkew {
        self.clock_skew
    }

    /// Replay retention for protocol message IDs without SAML expiry.
    pub fn replay_retention(&self) -> Option<Duration> {
        self.replay_retention
    }

    pub(crate) fn replay_policy(&mut self) -> &mut ReplayPolicy<'a> {
        &mut self.replay
    }

    pub(crate) fn check_and_store_message_replay(
        &mut self,
        key: ReplayKey,
    ) -> Result<(), SamlError> {
        if matches!(&self.replay, ReplayPolicy::DisabledForCompatibility) {
            return Ok(());
        }
        let expires_at = self.message_replay_expires_at()?;
        match &mut self.replay {
            ReplayPolicy::DisabledForCompatibility => Ok(()),
            ReplayPolicy::RequireCache(cache) => cache.check_and_store(key, expires_at),
        }
    }

    fn message_replay_expires_at(&self) -> Result<OffsetDateTime, SamlError> {
        let Some(retention) = self.replay_retention else {
            return Err(SamlError::TimeWindowInvalid {
                field: crate::error::TimeWindowField::ReplayExpiration,
            });
        };
        if retention <= Duration::ZERO {
            return Err(SamlError::TimeWindowInvalid {
                field: crate::error::TimeWindowField::ReplayExpiration,
            });
        }
        self.now
            .checked_add(retention)
            .ok_or(SamlError::TimeWindowInvalid {
                field: crate::error::TimeWindowField::ReplayExpiration,
            })
    }
}
