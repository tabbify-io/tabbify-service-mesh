//! Container naming and typing rules for the named-typed apps registry
//! (auth migration 0026).
//!
//! The node pre-validates the `deploy` tool's `app_name` with the SAME rule
//! auth later enforces at mint time. When the two copies drifted (node briefly
//! allowed a space auth rejected), the mismatch surfaced 15 days later as an
//! opaque 400 from the token mint.

use std::fmt;

/// Valid container kinds for the named-typed apps registry.
pub const CONTAINER_KINDS: [&str; 4] = ["workspace", "app", "devbox", "builder"];

/// Max container-name length in characters. 63 keeps the label DNS-label-sized
/// and matches the limit the node's `deploy` tool has always advertised.
pub const CONTAINER_NAME_MAX_LEN: usize = 63;

/// Why a container name failed validation. Variants rather than one message so
/// each service keeps its own audience-appropriate wording; [`fmt::Display`]
/// provides the canonical (auth-style) phrasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerNameError {
    /// The name is empty.
    Empty,
    /// The name exceeds `max` characters.
    TooLong {
        /// The enforced limit ([`CONTAINER_NAME_MAX_LEN`]).
        max: usize,
    },
    /// The name contains a character outside `[A-Za-z0-9._-]`.
    InvalidChar,
}

impl fmt::Display for ContainerNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty | Self::TooLong { .. } => write!(
                f,
                "container name must be 1..={CONTAINER_NAME_MAX_LEN} characters"
            ),
            Self::InvalidChar => write!(
                f,
                "container name allows only letters, digits, '.', '_' and '-'"
            ),
        }
    }
}

/// True for characters allowed in a container name (`[A-Za-z0-9._-]`, a
/// filesystem/DNS-safe subset). Exposed so label DERIVATION (auth's
/// `sanitize_label`) folds text with the SAME charset the validator enforces.
#[must_use]
pub const fn is_container_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// Validate a container name: non-empty, at most [`CONTAINER_NAME_MAX_LEN`]
/// characters, and only [`is_container_name_char`] characters. The name is a
/// display + slug label, not free text. No trimming here — callers decide
/// their own whitespace policy before validating.
pub fn validate_container_name(name: &str) -> Result<(), ContainerNameError> {
    if name.is_empty() {
        return Err(ContainerNameError::Empty);
    }
    if name.chars().count() > CONTAINER_NAME_MAX_LEN {
        return Err(ContainerNameError::TooLong {
            max: CONTAINER_NAME_MAX_LEN,
        });
    }
    if !name.chars().all(is_container_name_char) {
        return Err(ContainerNameError::InvalidChar);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_friendly_names() {
        for name in ["hello-world_1.0", "Api.v2_beta", "a", "my-api", "0.9"] {
            assert_eq!(validate_container_name(name), Ok(()), "rejected {name}");
        }
    }

    #[test]
    fn accepts_up_to_the_length_limit_and_rejects_past_it() {
        assert_eq!(validate_container_name(&"a".repeat(63)), Ok(()));
        assert_eq!(
            validate_container_name(&"a".repeat(64)),
            Err(ContainerNameError::TooLong { max: 63 })
        );
    }

    /// The space case: node accepting `"vcad demo"` while auth rejected it was
    /// a 15-day-latent production incident. Spaces stay rejected — everywhere.
    #[test]
    fn rejects_inner_spaces() {
        for name in ["My App", "vcad demo", "a b", " leading", "trailing "] {
            assert_eq!(
                validate_container_name(name),
                Err(ContainerNameError::InvalidChar),
                "accepted {name:?}"
            );
        }
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(validate_container_name(""), Err(ContainerNameError::Empty));
    }

    #[test]
    fn rejects_bad_charset() {
        for name in [
            "bad/slash",
            "emoji😀",
            "semi;colon",
            "tab\tname",
            "new\nline",
            "no!",
        ] {
            assert_eq!(
                validate_container_name(name),
                Err(ContainerNameError::InvalidChar),
                "accepted {name:?}"
            );
        }
    }

    #[test]
    fn length_is_counted_in_characters_before_charset() {
        // 64 multibyte chars fail as TooLong (length gate first, like the node
        // has always ordered its checks), not InvalidChar.
        assert_eq!(
            validate_container_name(&"é".repeat(64)),
            Err(ContainerNameError::TooLong { max: 63 })
        );
    }

    #[test]
    fn canonical_messages_are_stable() {
        assert_eq!(
            ContainerNameError::Empty.to_string(),
            "container name must be 1..=63 characters"
        );
        assert_eq!(
            ContainerNameError::TooLong { max: 63 }.to_string(),
            "container name must be 1..=63 characters"
        );
        assert_eq!(
            ContainerNameError::InvalidChar.to_string(),
            "container name allows only letters, digits, '.', '_' and '-'"
        );
    }

    #[test]
    fn container_kinds_are_the_known_four() {
        assert_eq!(CONTAINER_KINDS, ["workspace", "app", "devbox", "builder"]);
    }
}
