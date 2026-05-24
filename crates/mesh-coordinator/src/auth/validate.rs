//! HTTP client for `POST <AUTH_URL>/v1/validate`.
//!
//! # Wire contract (mirrored from the auth service spec §5)
//!
//! Request body:  `{ "token": "<join-jwt>" }`
//! Response body: `{ "valid": bool, "subject": str, "network": str,
//!                   "tags": [str], "kind": str, "exp": i64 }`
//!
//! Only the `network` + `tags` are authoritative for the mesh; `subject`,
//! `kind`, and `exp` are carried for diagnostics / future use.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The validated claims the auth service returns for a join token.
///
/// `network` + `tags` are **authoritative**: the coordinator stamps a
/// node's identity from these, never from the joiner-supplied request.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ValidatedClaims {
    /// Whether the token is valid (signature + `exp` + not revoked).
    pub valid: bool,
    /// Token subject — user login or node label.
    #[serde(default)]
    pub subject: String,
    /// Authoritative network claim — selects the node's ULA block (§6).
    #[serde(default)]
    pub network: String,
    /// Authoritative tags claim — drive ACL roster filtering (§5).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Token kind — `"join"` for node-join tokens, `"auth"` for user
    /// tokens. The coordinator only admits `"join"` tokens.
    #[serde(default)]
    pub kind: String,
    /// Expiry, unix seconds. Carried for diagnostics; the auth service
    /// already enforces it in its `valid` decision.
    #[serde(default)]
    pub exp: i64,
}

/// Failure modes of a validate round-trip.
///
/// All of these map to a register rejection (HTTP 401). Distinguishing the
/// transport / status / decode cases keeps the coordinator log actionable
/// without leaking validator internals to the joiner.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Network / TLS failure reaching the auth service.
    #[error("auth service transport: {0}")]
    Transport(String),
    /// Auth service answered with a non-success status.
    #[error("auth service status {status}: {body}")]
    Status {
        /// HTTP status the auth service returned.
        status: u16,
        /// First chunk of the response body for diagnostics.
        body: String,
    },
    /// The response body did not match the expected JSON shape.
    #[error("auth service response decode: {0}")]
    Decode(String),
    /// The token validated as a non-`join` kind (e.g. a user-auth token
    /// presented as a join token). Fail closed.
    #[error("token kind {0:?} is not a join token")]
    WrongKind(String),
}

/// Body of `POST /v1/validate`.
#[derive(Debug, Serialize)]
struct ValidateRequest<'a> {
    token: &'a str,
}

/// Thin HTTP client for the auth service's validate endpoint.
///
/// Cheap to clone — shares one `reqwest::Client` internally. Built once at
/// coordinator startup from `AUTH_URL` and threaded into the
/// [`crate::Coordinator`].
#[derive(Debug, Clone)]
pub struct AuthValidator {
    http: reqwest::Client,
    validate_url: String,
}

impl AuthValidator {
    /// Build a validator targeting `auth_url` (e.g. `http://127.0.0.1:8080`).
    /// Trailing slashes are tolerated; the `/v1/validate` path is appended.
    ///
    /// # Errors
    /// Surfaces a [`ValidationError::Transport`] if the underlying reqwest
    /// client fails to build.
    pub fn new(auth_url: impl Into<String>) -> Result<Self, ValidationError> {
        let base = auth_url.into().trim_end_matches('/').to_owned();
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| ValidationError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            validate_url: format!("{base}/v1/validate"),
        })
    }

    /// Validate `token` against the auth service.
    ///
    /// Returns the parsed [`ValidatedClaims`] on a successful round-trip —
    /// the caller still has to check [`ValidatedClaims::valid`] and reject
    /// when it is `false` (the auth service returns `200 { valid: false }`
    /// for an expired / revoked / tampered token rather than a 4xx).
    ///
    /// This method *does* enforce the `kind == "join"` invariant: a token
    /// that validates as some other kind is rejected with
    /// [`ValidationError::WrongKind`] so a user-auth token can never be
    /// used to join the mesh.
    ///
    /// # Errors
    /// See [`ValidationError`] — transport, non-2xx status, body decode, or
    /// wrong token kind.
    pub async fn validate(&self, token: &str) -> Result<ValidatedClaims, ValidationError> {
        let resp = self
            .http
            .post(&self.validate_url)
            .json(&ValidateRequest { token })
            .send()
            .await
            .map_err(|e| ValidationError::Transport(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ValidationError::Status {
                status: status.as_u16(),
                body: body_excerpt(resp).await,
            });
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ValidationError::Transport(e.to_string()))?;
        let claims: ValidatedClaims = serde_json::from_slice(&bytes).map_err(|e| {
            ValidationError::Decode(format!(
                "{e} (body excerpt: {})",
                excerpt_str(&String::from_utf8_lossy(&bytes))
            ))
        })?;

        // A valid token of the wrong kind must not be accepted as a join
        // token. We only guard when the token is otherwise valid: an
        // invalid token's kind is meaningless and the caller rejects it on
        // `valid == false` anyway.
        if claims.valid && !claims.kind.is_empty() && claims.kind != "join" {
            return Err(ValidationError::WrongKind(claims.kind));
        }

        Ok(claims)
    }
}

/// Pull a bounded excerpt of a response body for an error path. Best-effort.
async fn body_excerpt(resp: reqwest::Response) -> String {
    match resp.text().await {
        Ok(s) => excerpt_str(&s),
        Err(e) => format!("<body read failed: {e}>"),
    }
}

fn excerpt_str(s: &str) -> String {
    const MAX: usize = 512;
    if s.len() > MAX {
        format!("{}...<truncated>", &s[..MAX])
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Happy path: a valid join token round-trips and the authoritative
    /// `network` + `tags` come back exactly as the auth service returned
    /// them.
    #[tokio::test]
    async fn validate_returns_authoritative_claims_for_valid_join_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/validate"))
            .and(header("content-type", "application/json"))
            .and(body_json(serde_json::json!({ "token": "good-join-jwt" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": true,
                "subject": "node-alice",
                "network": "alice",
                "tags": ["tag:user-alice", "tag:wasm-host"],
                "kind": "join",
                "exp": 1_900_000_000_i64,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let validator = AuthValidator::new(server.uri()).unwrap();
        let claims = validator.validate("good-join-jwt").await.unwrap();
        assert!(claims.valid);
        assert_eq!(claims.network, "alice");
        assert_eq!(
            claims.tags,
            vec!["tag:user-alice".to_owned(), "tag:wasm-host".to_owned()]
        );
        assert_eq!(claims.kind, "join");
        assert_eq!(claims.subject, "node-alice");
    }

    /// The auth service returns `200 { valid: false }` for an expired /
    /// revoked / tampered token. The validator surfaces that verbatim; the
    /// caller is responsible for the 401.
    #[tokio::test]
    async fn validate_surfaces_valid_false_without_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": false,
                "subject": "",
                "network": "",
                "tags": [],
                "kind": "join",
                "exp": 0,
            })))
            .mount(&server)
            .await;

        let validator = AuthValidator::new(server.uri()).unwrap();
        let claims = validator.validate("revoked").await.unwrap();
        assert!(!claims.valid);
    }

    /// A non-2xx from the auth service is a `Status` error, not a silent
    /// "valid" — fail closed.
    #[tokio::test]
    async fn validate_maps_non_success_status_to_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/validate"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let validator = AuthValidator::new(server.uri()).unwrap();
        let err = validator.validate("x").await.unwrap_err();
        match err {
            ValidationError::Status { status, body } => {
                assert_eq!(status, 500);
                assert!(body.contains("boom"));
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// A 200 with a garbled body must surface as `Decode`, never as a
    /// half-parsed "valid" claim set.
    #[tokio::test]
    async fn validate_maps_garbage_body_to_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let validator = AuthValidator::new(server.uri()).unwrap();
        let err = validator.validate("x").await.unwrap_err();
        assert!(matches!(err, ValidationError::Decode(_)), "{err:?}");
    }

    /// A valid token of the wrong kind (e.g. a user-auth token) must be
    /// rejected — it cannot be used to join the mesh.
    #[tokio::test]
    async fn validate_rejects_valid_non_join_kind() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": true,
                "subject": "alice",
                "network": "alice",
                "tags": ["tag:user-alice"],
                "kind": "auth",
                "exp": 1_900_000_000_i64,
            })))
            .mount(&server)
            .await;

        let validator = AuthValidator::new(server.uri()).unwrap();
        let err = validator.validate("user-token").await.unwrap_err();
        assert!(matches!(err, ValidationError::WrongKind(ref k) if k == "auth"), "{err:?}");
    }

    /// Transport failure (nothing listening) is a `Transport` error.
    #[tokio::test]
    async fn validate_maps_transport_failure() {
        // Reserve a port then drop the listener so the connect refuses.
        let validator = AuthValidator::new("http://127.0.0.1:1").unwrap();
        let err = validator.validate("x").await.unwrap_err();
        assert!(matches!(err, ValidationError::Transport(_)), "{err:?}");
    }

    #[test]
    fn new_trims_trailing_slash_and_appends_path() {
        let v = AuthValidator::new("http://auth.example/").unwrap();
        assert_eq!(v.validate_url, "http://auth.example/v1/validate");
    }
}
