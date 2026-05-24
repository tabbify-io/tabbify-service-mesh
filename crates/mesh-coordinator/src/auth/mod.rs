//! Join-token validation against the standalone auth service (spec §8).
//!
//! The coordinator does not hold signing keys or verify JWTs locally. It
//! calls the auth service's centralized `POST /v1/validate` endpoint
//! (revocation-aware) over **plain HTTP** — never over the mesh, because a
//! node registers precisely because it is not yet in the overlay
//! (chicken-and-egg, §8).
//!
//! The validator returns the authoritative `network` + `tags` from the
//! token claims. The coordinator stamps a node's identity from these
//! (via [`crate::roster::identity::stamp_identity`]) and never trusts the
//! `tags`/`network` a joiner self-asserts in its `RegisterRequest` — this
//! is what closes the ACL spoofing gap (§5.1).

mod validate;

pub use validate::{AuthValidator, ValidatedClaims, ValidationError};
