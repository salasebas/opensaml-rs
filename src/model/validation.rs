use super::{AssertionId, MessageId, SessionIndex};
use crate::error::SamlError;
use time::OffsetDateTime;

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

    /// Build clock skew from the raw SAML drift tuple, in milliseconds.
    pub fn from_millis(not_before_ms: i64, not_on_or_after_ms: i64) -> Self {
        Self {
            not_before_ms,
            not_on_or_after_ms,
        }
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReplayKey {
    /// SAML protocol response ID.
    ResponseId(MessageId),
    /// SAML assertion ID.
    AssertionId(AssertionId),
    /// AuthnStatement SessionIndex.
    SessionIndex(SessionIndex),
}

impl ReplayKey {
    /// Stable key family.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ResponseId(_) => "response",
            Self::AssertionId(_) => "assertion",
            Self::SessionIndex(_) => "session",
        }
    }

    /// Raw SAML identifier value.
    pub fn value(&self) -> &str {
        match self {
            Self::ResponseId(id) => id.as_str(),
            Self::AssertionId(id) => id.as_str(),
            Self::SessionIndex(id) => id.as_str(),
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
    fn check_and_store(
        &mut self,
        key: ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<(), SamlError>;
}

/// Replay behavior for typed inbound browser flows.
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
}

impl<'a> SamlValidationContext<'a> {
    /// Build a validation context with strict clock skew.
    pub fn new(now: OffsetDateTime, replay: ReplayPolicy<'a>) -> Self {
        Self {
            now,
            clock_skew: ClockSkew::strict(),
            replay,
        }
    }

    /// Set clock skew tolerance for SAML time windows.
    pub fn with_clock_skew(mut self, clock_skew: ClockSkew) -> Self {
        self.clock_skew = clock_skew;
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

    pub(crate) fn replay_policy(&mut self) -> &mut ReplayPolicy<'a> {
        &mut self.replay
    }
}
