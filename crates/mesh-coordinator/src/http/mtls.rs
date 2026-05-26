//! mTLS server config for the coordinator HTTP API.
//!
//! Loads coordinator cert + private key + CA bundle, then produces a
//! `rustls::ServerConfig` that requires every client to present a cert
//! signed by the CA. Used by `main.rs` to switch between plaintext
//! (`--insecure-no-mtls`) and TLS-protected serve modes.
//!
//! The CA model is intentionally simple (single root, no chain depth limit):
//! peers (joiners + coordinator itself) all sit under one organizationally-
//! owned `mesh-ca`. Authorization (who can register vs heartbeat) is NOT
//! enforced at the cert level — anything signed by the CA gets through;
//! the per-peer pubkey on the wire still drives roster identity.

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// Wrapper around an `Arc<ServerConfig>` to give the type a stable name
/// across call sites (the inner `Arc` is cheap to clone for axum-server).
#[derive(Debug, Clone)]
pub struct MtlsServerConfig {
    pub config: Arc<ServerConfig>,
}

/// Load PEM-encoded cert chain, private key, and trusted-CA bundle from
/// disk, then assemble a `rustls::ServerConfig` that enforces mTLS via
/// `WebPkiClientVerifier`.
///
/// Errors are `String` instead of a typed error enum because every caller
/// in this crate just wants to print the message — staying untyped keeps
/// the propagation through `anyhow::Context` in `main.rs` zero-friction.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<MtlsServerConfig, String> {
    // Installing the default crypto provider must happen exactly once per
    // process. We ignore the "already installed" error so this function
    // can be called multiple times (e.g. tests) without panicking. Using
    // `ring` here matches the rest of the workspace (which pulls the
    // `rustls-tls` feature on `reqwest` — same backend).
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let ca_certs = load_certs(ca_path)?;

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| format!("add ca cert: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| format!("build verifier: {e}"))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("server config: {e}"))?;

    Ok(MtlsServerConfig {
        config: Arc::new(config),
    })
}

/// Read a PEM file containing one or more certificates. Returns the
/// strongly-typed `CertificateDer` vector ready for rustls.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = File::open(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let mut reader = BufReader::new(f);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs in {}: {}", path.display(), e))
}

/// Read a PEM file containing a single PKCS#8 / SEC1 / RSA private key.
/// Returns the strongly-typed `PrivateKeyDer` ready for rustls.
fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let f = File::open(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let mut reader = BufReader::new(f);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse key in {}: {}", path.display(), e))?
        .ok_or_else(|| format!("no private key in {}", path.display()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn build_server_config_errors_on_missing_files() {
        let bogus = Path::new("/nonexistent/here");
        let err = build_server_config(bogus, bogus, bogus).unwrap_err();
        assert!(
            err.contains("read") || err.contains("No such"),
            "expected message to mention missing file, got: {err}"
        );
    }

    /// Generate a self-signed cert on the fly, reuse it as both the
    /// server cert and the trusted CA, and verify `build_server_config`
    /// accepts the bundle. This is the smallest valid input shape — real
    /// deployments would have a separate CA cert, but the loader code
    /// path is identical.
    #[test]
    fn build_server_config_accepts_valid_certs() {
        let dir = tempfile::TempDir::new().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["mesh-ca".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let cert_path = dir.path().join("server.pem");
        let key_path = dir.path().join("server.key");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        std::fs::write(&ca_path, &cert_pem).unwrap();

        let cfg = build_server_config(&cert_path, &key_path, &ca_path);
        assert!(cfg.is_ok(), "expected ok: {:?}", cfg.err());
    }
}
