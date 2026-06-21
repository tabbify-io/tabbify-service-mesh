//! Persistent peer identity: `WireGuard` keypair + assigned ULA in a single
//! JSON file.
//!
//! This module extends the keypair-persistence story from
//! [`crate::wg::persistent_keypair`] (32-byte raw file) with a richer
//! identity file that also records the coordinator-assigned ULA. When a
//! joiner loads an existing identity it re-requests the same ULA on
//! re-registration, giving long-lived supervisory peers a *sticky* mesh
//! address across restarts.
//!
//! # File format
//!
//! ```json
//! {
//!   "private_key": "<base64-standard-padded-32-bytes>",
//!   "ula": "fd5a:1f00:1::7"
//! }
//! ```
//!
//! The format is intentionally minimal so the file is human-readable and
//! trivially auditable. Future fields can be added without a breaking change
//! (serde `deny_unknown_fields` is intentionally **not** set).
//!
//! # Atomicity + permissions
//!
//! Identical to [`crate::wg::persistent_keypair`]: write to `<path>.tmp`
//! with mode 0600, then `rename()` over the final path. Crash-safe on any
//! POSIX filesystem.

use crate::wg::keypair::{WgKeypair, generate};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, ErrorKind};
use std::net::Ipv6Addr;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

/// On-disk representation of a persistent peer identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityFile {
    /// Base64-encoded 32-byte X25519 private key.
    private_key: String,
    /// IPv6 ULA assigned by the coordinator on the first join.
    ula: String,
}

/// A loaded peer identity: the `WireGuard` keypair and the sticky ULA.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// The X25519 keypair loaded from the identity file.
    pub keypair: WgKeypair,
    /// The coordinator-assigned ULA stored in the identity file.
    pub ula: Ipv6Addr,
}

/// Load an existing identity from `path`, or return `None` if the file is
/// absent.
///
/// # Errors
///
/// * [`ErrorKind::InvalidData`] — file exists but is malformed (bad JSON,
///   bad base64, wrong key length, bad ULA text).
/// * Any other [`io::Error`] — filesystem error on read.
pub fn load(path: &Path) -> io::Result<Option<PeerIdentity>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(path)?;
    let record: IdentityFile = serde_json::from_slice(&data).map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("identity file {} JSON: {e}", path.display()),
        )
    })?;

    let raw = B64.decode(&record.private_key).map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("identity file {} private_key base64: {e}", path.display()),
        )
    })?;
    if raw.len() != 32 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "identity file {} private_key is {} bytes, expected 32",
                path.display(),
                raw.len()
            ),
        ));
    }
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&raw);
    let private = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&private);
    let ula: Ipv6Addr = record.ula.parse().map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("identity file {} ula {:?}: {e}", path.display(), record.ula),
        )
    })?;

    Ok(Some(PeerIdentity {
        keypair: WgKeypair { private, public },
        ula,
    }))
}

/// Persist `(keypair, ula)` to `path` atomically with mode 0600 (Unix).
///
/// The parent directory is created if it does not exist. The write is
/// atomic: data lands in `<path>.tmp` first, then is renamed over `path`.
///
/// # Errors
///
/// Any filesystem error is propagated verbatim.
pub fn store(path: &Path, keypair: &WgKeypair, ula: Ipv6Addr) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let record = IdentityFile {
        private_key: B64.encode(keypair.private.as_bytes()),
        ula: ula.to_string(),
    };
    let json = serde_json::to_vec_pretty(&record)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("serialize identity: {e}")))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&tmp, perms)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// The quarantine path for a torn identity file: `<path>.corrupt`.
fn corrupt_path(path: &Path) -> std::path::PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".corrupt");
    std::path::PathBuf::from(os)
}

/// Load an existing identity if present, otherwise generate a fresh keypair
/// (without persisting — the ULA is not known yet at this stage).
///
/// Returns `(keypair, Option<sticky_ula>)`: when a prior identity was
/// loaded, `sticky_ula` holds the ULA to re-request; when no file exists,
/// `sticky_ula` is `None` and the caller should call [`store`] after the
/// coordinator returns the assigned ULA.
///
/// # Corrupt-identity quarantine
///
/// A TORN identity file (truncated write, disk corruption, a half-flushed
/// crash) surfaces [`ErrorKind::InvalidData`] from [`load`]. Such a file must
/// NEVER brick the box: instead of propagating the error (which would hard-exit
/// the joiner pre-network and strand a remote-only worker like MSI), we
/// best-effort RENAME the torn file to `<path>.corrupt` (preserving it for
/// post-mortem) and fall through to a FRESH keypair — the node simply re-joins
/// with a new identity + a coordinator-allocated ULA. A failed rename is logged
/// and ignored; we still proceed with a fresh keypair rather than fail.
///
/// # Errors
///
/// Propagates only NON-`InvalidData` filesystem errors from [`load`] (a real
/// transient I/O fault the caller should surface, not a corrupt-data brick).
pub fn load_or_fresh(path: &Path) -> io::Result<(WgKeypair, Option<Ipv6Addr>)> {
    match load(path) {
        Ok(Some(id)) => Ok((id.keypair, Some(id.ula))),
        Ok(None) => Ok((generate(), None)),
        Err(e) if e.kind() == ErrorKind::InvalidData => {
            let quarantine = corrupt_path(path);
            match fs::rename(path, &quarantine) {
                Ok(()) => tracing::warn!(
                    identity_path = %path.display(),
                    quarantine = %quarantine.display(),
                    error = %e,
                    "joiner: torn mesh-identity.json quarantined → fresh keypair (re-joins with a new ULA; the box must never brick on a corrupt identity)"
                ),
                Err(rename_err) => tracing::error!(
                    identity_path = %path.display(),
                    error = %e,
                    rename_error = %rename_err,
                    "joiner: torn mesh-identity.json could not be renamed; proceeding with a fresh keypair anyway"
                ),
            }
            Ok((generate(), None))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const ULA_A: &str = "fd5a:1f00:1::7";

    fn make_keypair() -> WgKeypair {
        generate()
    }

    /// Fresh path → `load` returns `None`.
    #[test]
    fn load_returns_none_when_absent() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("identity.json");
        assert!(load(&path).unwrap().is_none());
    }

    /// `store` then `load` round-trips the keypair bytes and ULA.
    #[test]
    fn store_and_load_round_trip() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("nested").join("identity.json");
        let kp = make_keypair();
        let ula: Ipv6Addr = ULA_A.parse().unwrap();

        store(&path, &kp, ula).expect("store");
        assert!(path.exists(), "file must exist after store");

        let id = load(&path).expect("load ok").expect("must be Some");
        assert_eq!(
            id.keypair.private.to_bytes(),
            kp.private.to_bytes(),
            "private key must round-trip"
        );
        assert_eq!(
            id.keypair.public.as_bytes(),
            kp.public.as_bytes(),
            "public key must round-trip"
        );
        assert_eq!(id.ula, ula, "ULA must round-trip");
    }

    /// `load_or_fresh` with no file returns a fresh keypair and `None` ULA.
    #[test]
    fn load_or_fresh_generates_when_absent() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("identity.json");
        let (_, sticky) = load_or_fresh(&path).unwrap();
        assert!(sticky.is_none(), "no file → no sticky ULA");
    }

    /// `load_or_fresh` with an existing file returns the persisted keypair
    /// and the sticky ULA — no new keypair is generated.
    #[test]
    fn load_or_fresh_returns_persisted_identity() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("identity.json");
        let kp = make_keypair();
        let ula: Ipv6Addr = ULA_A.parse().unwrap();
        store(&path, &kp, ula).unwrap();

        let (loaded_kp, sticky) = load_or_fresh(&path).unwrap();
        assert_eq!(
            loaded_kp.private.to_bytes(),
            kp.private.to_bytes(),
            "must reuse persisted private key"
        );
        assert_eq!(sticky, Some(ula), "must return the persisted ULA");
    }

    /// Simulates a peer restart: two calls to `load_or_fresh` with the same
    /// path and a `store` in between (as `Joiner::join` would do after the
    /// first registration) return the SAME keypair bytes and ULA.
    ///
    /// This is the core property: a long-lived supervisor keeps its mesh
    /// address across restarts.
    #[test]
    fn sticky_ula_stable_across_simulated_restart() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("identity.json");

        // ── First "process start" ──────────────────────────────────────────
        // No prior identity → fresh keypair, no sticky ULA.
        let (kp1, sticky1) = load_or_fresh(&path).unwrap();
        assert!(sticky1.is_none(), "first start: no prior file");

        // Coordinator assigns ULA X; joiner persists it.
        let assigned_ula: Ipv6Addr = ULA_A.parse().unwrap();
        store(&path, &kp1, assigned_ula).expect("persist after first join");

        // ── Second "process start" (restart) ──────────────────────────────
        // Existing identity → same keypair AND sticky_ula == assigned_ula.
        let (kp2, sticky2) = load_or_fresh(&path).unwrap();
        assert_eq!(
            kp2.private.to_bytes(),
            kp1.private.to_bytes(),
            "restart must reuse the persisted keypair"
        );
        assert_eq!(
            sticky2,
            Some(assigned_ula),
            "restart must re-request the same ULA"
        );
    }

    /// A malformed JSON file surfaces `InvalidData` — distinguishable from
    /// a transient I/O error so the operator can fix the file.
    #[test]
    fn load_errors_on_malformed_json() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("identity.json");
        fs::write(&path, b"not json").unwrap();
        let err = load(&path).expect_err("must fail on bad JSON");
        assert_eq!(err.kind(), ErrorKind::InvalidData, "err: {err}");
    }

    /// Wrong key size in a well-formed JSON file → `InvalidData`.
    #[test]
    fn load_errors_on_wrong_key_size() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("identity.json");
        // 16-byte key is too short.
        let bad = serde_json::json!({
            "private_key": B64.encode([0u8; 16]),
            "ula": ULA_A,
        });
        fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        let err = load(&path).expect_err("must fail on wrong key size");
        assert_eq!(err.kind(), ErrorKind::InvalidData, "err: {err}");
    }

    /// A bad ULA string in an otherwise valid file → `InvalidData`.
    #[test]
    fn load_errors_on_bad_ula() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("identity.json");
        let bad = serde_json::json!({
            "private_key": B64.encode([0u8; 32]),
            "ula": "not-an-ipv6",
        });
        fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        let err = load(&path).expect_err("must fail on bad ULA");
        assert_eq!(err.kind(), ErrorKind::InvalidData, "err: {err}");
    }

    /// A torn / corrupt identity file must NEVER brick the box: `load_or_fresh`
    /// quarantines it (renames to `<path>.corrupt`) and returns a FRESH keypair
    /// with no sticky ULA, so the node re-joins instead of hard-exiting on a
    /// `InvalidData` load error.
    #[test]
    fn load_or_fresh_quarantines_torn_file_and_returns_fresh() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("mesh-identity.json");
        // A torn write: valid-looking JSON object but garbage that fails to
        // parse into IdentityFile / decode — surfaces InvalidData from `load`.
        fs::write(&path, b"{ this is not valid json").unwrap();

        let (_, sticky) = load_or_fresh(&path).expect("must not hard-error on torn identity");
        assert!(sticky.is_none(), "fresh keypair → no sticky ULA");

        let corrupt = corrupt_path(&path);
        assert!(
            corrupt.exists(),
            "torn file must be quarantined to {}",
            corrupt.display()
        );
        assert!(
            !path.exists(),
            "the original torn path must be gone (renamed to .corrupt)"
        );
    }

    /// On Unix, the stored file must have mode 0600 (owner read/write only).
    #[cfg(unix)]
    #[test]
    fn store_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("identity.json");
        let kp = make_keypair();
        let ula: Ipv6Addr = ULA_A.parse().unwrap();
        store(&path, &kp, ula).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }
}
