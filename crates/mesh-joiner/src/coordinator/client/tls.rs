//! mTLS client builder used by [`super::CoordinatorClient`] when running
//! against a production coordinator (every endpoint goes through the
//! mesh CA — no public roots).

use crate::error::{JoinerError, Result};
use std::path::Path;

/// Read PEM cert + key + CA off disk and build a `reqwest::ClientBuilder`
/// pre-configured with a client identity and a single trusted root.
///
/// All I/O errors surface as [`JoinerError::HttpTransport`] because
/// they're effectively transport-setup failures from the caller's POV
/// (the coordinator request never even leaves the host).
pub(super) fn build_mtls_client_builder(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<reqwest::ClientBuilder> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| {
        JoinerError::HttpTransport(format!("read tls_cert {}: {e}", cert_path.display()))
    })?;
    let key_pem = std::fs::read(key_path).map_err(|e| {
        JoinerError::HttpTransport(format!("read tls_key {}: {e}", key_path.display()))
    })?;
    let ca_pem = std::fs::read(ca_path).map_err(|e| {
        JoinerError::HttpTransport(format!("read tls_ca {}: {e}", ca_path.display()))
    })?;

    // `Identity::from_pem` expects cert + key concatenated into one PEM
    // blob — the rustls backend internally parses the sections. Order
    // doesn't matter but we put cert first for diagnostic convenience.
    // Move `cert_pem` (not clone) — original isn't referenced again.
    let mut bundle = cert_pem;
    if !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(&key_pem);

    let identity = reqwest::Identity::from_pem(&bundle).map_err(|e| {
        JoinerError::HttpTransport(format!(
            "parse client identity (cert={}, key={}): {e}",
            cert_path.display(),
            key_path.display()
        ))
    })?;
    let root_ca = reqwest::Certificate::from_pem(&ca_pem).map_err(|e| {
        JoinerError::HttpTransport(format!("parse tls_ca {}: {e}", ca_path.display()))
    })?;

    // `tls_built_in_root_certs(false)` — drop the OS / webpki bundle
    // so ONLY our mesh CA is trusted. A misconfigured public CA must
    // not be able to MITM the mesh control plane.
    Ok(reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(root_ca)
        .identity(identity))
}
