//! Persistent X25519 keypair storage for the joiner.
//!
//! The joiner's identity in the mesh is its X25519 public key — the
//! coordinator hashes it into a stable `peer_id`, and other peers use
//! it directly as the `WireGuard` remote public key. If we regenerate the
//! keypair every restart, the coordinator's roster accumulates stale
//! entries (one per restart) until its timeout sweep collects them, and
//! every restart looks like a fresh peer to the rest of the mesh.
//!
//! This module fixes that by persisting the 32-byte private key to disk
//! on first use and loading it on every subsequent start. The on-disk
//! layout is intentionally trivial — a single 32-byte file — because
//! that's the minimum the X25519 crate needs to reconstruct a
//! [`StaticSecret`], and we don't want to negotiate a richer format
//! across substrate releases.
//!
//! # Atomicity
//!
//! The "write" path is: write 32 bytes to `<path>.tmp` with mode 0600,
//! then `rename()` over the final path. Rename on the same filesystem
//! is atomic, so a crash mid-write leaves either the old (or no) file
//! at `path` plus an orphan `path.tmp` — never a half-written final
//! file. The parent directory is created lazily on first write.
//!
//! # Permissions
//!
//! On Unix the temp file is `chmod 0600` before the rename. On Windows
//! we rely on the default ACL (the file lives under the user's home
//! directory anyway). Future hardening: also `chmod` the parent dir,
//! and refuse to load if the file's mode is group/world-readable.

use crate::wg::keypair::{self, WgKeypair};
use std::fs;
use std::io;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

/// Load an X25519 keypair from `path`, or generate + persist a fresh
/// one if the file does not exist.
///
/// # Behavior
///
/// * **File present** — read 32 bytes, parse as [`StaticSecret`],
///   derive [`PublicKey`]. Files of any other length cause an
///   [`io::ErrorKind::InvalidData`] error.
/// * **File absent** — create the parent directory if needed, generate
///   a fresh keypair via [`keypair::generate`], write the 32-byte
///   private key to `<path>.tmp` with mode 0600 (Unix), then rename
///   atomically to `path`. Returns the in-memory keypair so the caller
///   doesn't pay for a second read.
///
/// # Errors
///
/// Any filesystem error is propagated verbatim; bad file size becomes
/// an [`io::ErrorKind::InvalidData`] error so callers can distinguish
/// "operator pointed us at the wrong file" from "disk is full".
pub fn load_or_generate(path: &Path) -> io::Result<WgKeypair> {
    if path.exists() {
        let bytes = fs::read(path)?;
        if bytes.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "keypair file {} has {} bytes, expected 32",
                    path.display(),
                    bytes.len()
                ),
            ));
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&bytes);
        let private = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&private);
        return Ok(WgKeypair { private, public });
    }

    // File missing — generate + persist atomically.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let kp = keypair::generate();
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, kp.private.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&tmp, perms)?;
    }
    fs::rename(&tmp, path)?;
    Ok(kp)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// First call creates the file with a fresh keypair; second call
    /// against the same path must return the *same* private key bytes,
    /// proving we persisted instead of generating anew.
    #[test]
    fn load_or_generate_creates_new_file_if_absent() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("nested").join("keypair");
        assert!(!path.exists());

        let kp1 = load_or_generate(&path).expect("first call");
        assert!(path.exists(), "file should exist after first call");

        let kp2 = load_or_generate(&path).expect("second call");
        assert_eq!(
            kp1.private.to_bytes(),
            kp2.private.to_bytes(),
            "second call must load the same persisted key"
        );
        assert_eq!(
            kp1.public.as_bytes(),
            kp2.public.as_bytes(),
            "public key must round-trip too"
        );
    }

    /// A file of the wrong length is not a valid keypair — surfacing
    /// `InvalidData` lets the caller distinguish corruption from
    /// transient I/O failures.
    #[test]
    fn load_or_generate_errors_on_bad_size() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("keypair");
        fs::write(&path, b"too short!").expect("seed bad file");

        let err = load_or_generate(&path).expect_err("must reject bad size");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "err: {err}");
    }
}
