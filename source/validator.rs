//! Time and status validation (samlify `validator.ts` + `flow.ts` `checkStatus`).

use crate::constants::{status_code, ParserType};
use crate::error::SamlError;
use crate::xml::{extract_with_limits, fields, XmlLimits};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

fn parse(ts: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(ts, &Rfc3339).ok()
}

/// Validate a `NotBefore` / `NotOnOrAfter` window (samlify `verifyTime`).
///
/// `drift` is `(not_before_ms, not_on_or_after_ms)` added to the respective
/// bounds. When neither bound is present the document is treated as valid.
/// A present-but-unparseable timestamp fails closed (mirrors JS `Invalid Date`).
pub fn verify_time(
    not_before: Option<&str>,
    not_on_or_after: Option<&str>,
    drift: (i64, i64),
) -> bool {
    let now = OffsetDateTime::now_utc();
    let (nb_drift, na_drift) = (
        Duration::milliseconds(drift.0),
        Duration::milliseconds(drift.1),
    );

    match (not_before, not_on_or_after) {
        (None, None) => true,
        (Some(nb), None) => match parse(nb) {
            Some(t) => t + nb_drift <= now,
            None => false,
        },
        (None, Some(na)) => match parse(na) {
            Some(t) => now < t + na_drift,
            None => false,
        },
        (Some(nb), Some(na)) => match (parse(nb), parse(na)) {
            (Some(b), Some(a)) => b + nb_drift <= now && now < a + na_drift,
            _ => false,
        },
    }
}

/// Check the two-tier `<StatusCode>` of a response (samlify `checkStatus`).
///
/// Only `SAMLResponse` / `LogoutResponse` are checked; other parser types are
/// skipped. Success resolves to `Ok(())`; anything else is an error.
pub fn check_status(content: &str, parser_type: ParserType) -> Result<(), SamlError> {
    check_status_with_limits(content, parser_type, XmlLimits::default())
}

/// Check response status with explicit XML parser resource limits.
pub fn check_status_with_limits(
    content: &str,
    parser_type: ParserType,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let fields = match parser_type {
        ParserType::SamlResponse => fields::login_response_status_fields(),
        ParserType::LogoutResponse => fields::logout_response_status_fields(),
        _ => return Ok(()),
    };
    let result = extract_with_limits(content, &fields, limits)?;
    match result.get_str("top") {
        Some(code) if code == status_code::SUCCESS => Ok(()),
        Some(code) if !code.is_empty() => Err(SamlError::FailedStatus {
            top: code.to_string(),
            second: result.get_str("second").unwrap_or_default().to_string(),
        }),
        _ => Err(SamlError::UndefinedStatus),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE: &str = include_str!("../tests/fixtures/response.xml");
    const FAILED: &str = include_str!("../tests/fixtures/failed_response.xml");

    #[test]
    fn time_window_basic() {
        assert!(verify_time(None, None, (0, 0)));
        assert!(verify_time(
            Some("2000-01-01T00:00:00Z"),
            Some("2999-01-01T00:00:00Z"),
            (0, 0)
        ));
        // expired
        assert!(!verify_time(None, Some("2000-01-01T00:00:00Z"), (0, 0)));
        // not yet valid
        assert!(!verify_time(Some("2999-01-01T00:00:00Z"), None, (0, 0)));
        // unparseable fails closed
        assert!(!verify_time(Some("not-a-date"), None, (0, 0)));
    }

    #[test]
    fn drift_widens_window() {
        // expired, but a huge positive notOnOrAfter drift makes it valid again
        assert!(verify_time(
            None,
            Some("2000-01-01T00:00:00Z"),
            (0, 9_000_000_000_000)
        ));
        // not-yet-valid, but a huge negative notBefore drift makes it valid
        assert!(verify_time(
            Some("2999-01-01T00:00:00Z"),
            None,
            (-50_000_000_000_000, 0)
        ));
    }

    #[test]
    fn status_success_and_two_tier_failure() -> Result<(), Box<dyn std::error::Error>> {
        check_status(RESPONSE, ParserType::SamlResponse)?;
        // request types are skipped
        check_status(RESPONSE, ParserType::SamlRequest)?;

        match check_status(FAILED, ParserType::SamlResponse) {
            Err(SamlError::FailedStatus { top, second }) => {
                assert_eq!(top, status_code::REQUESTER);
                assert_eq!(second, status_code::INVALID_NAME_ID_POLICY);
            }
            other => return Err(format!("expected FailedStatus, got {other:?}").into()),
        }
        Ok(())
    }
}
