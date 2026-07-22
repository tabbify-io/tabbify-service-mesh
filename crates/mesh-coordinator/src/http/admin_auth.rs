//! One implementation of the `MESH_ADMIN_TOKEN` bearer gate.
//!
//! Every admin-scoped endpoint (policy, command queue, per-pair direct
//! flag, proactive gate, and the roster-read endpoints) shares this check
//! so the rule can't drift between copies. The posture is **fail-closed**:
//! when no admin token is configured the endpoint rejects every call
//! rather than degrading to an open one.

use crate::http::api::ApiError;
use axum::{
    Json,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

/// Build a JSON error response.
pub fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            error: message.into(),
        }),
    )
        .into_response()
}

/// Verify `Authorization: Bearer <token>` against the configured admin
/// token. Returns `None` on match, or `Some(401 response)` to reject.
///
/// (Returns `Option` rather than `Result` so the rejection — a large
/// `Response` — isn't carried in an `Err` variant, which would bloat every
/// caller's `Result`.)
///
/// `api_label` names the endpoint family in the "disabled" message so an
/// operator can tell which surface refused them.
pub fn check_admin_bearer(
    expected: Option<&str>,
    headers: &HeaderMap,
    api_label: &str,
) -> Option<Response> {
    let Some(expected) = expected else {
        return Some(err(
            StatusCode::UNAUTHORIZED,
            format!("{api_label} admin API disabled (MESH_ADMIN_TOKEN unset)"),
        ));
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(tok) if tok == expected => None,
        _ => Some(err(
            StatusCode::UNAUTHORIZED,
            "invalid or missing admin token",
        )),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, value.parse().expect("header value"));
        h
    }

    /// The matching bearer is the ONLY accepted input.
    #[test]
    fn matching_bearer_is_accepted() {
        let h = headers_with("Bearer good");
        assert!(check_admin_bearer(Some("good"), &h, "test").is_none());
    }

    /// A wrong token, a missing header, and a non-Bearer scheme are all 401.
    #[test]
    fn wrong_missing_and_non_bearer_are_rejected() {
        let expected = Some("good");
        for h in [
            headers_with("Bearer bad"),
            HeaderMap::new(),
            headers_with("Basic good"),
        ] {
            let resp = check_admin_bearer(expected, &h, "test").expect("must reject");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
    }

    /// Fail-closed: with no configured token even a correct-looking bearer
    /// is refused — an unconfigured admin surface is a closed one.
    #[test]
    fn unset_token_fails_closed() {
        let h = headers_with("Bearer anything");
        let resp = check_admin_bearer(None, &h, "test").expect("must reject");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
