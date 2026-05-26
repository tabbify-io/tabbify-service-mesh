use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "tabbify-mesh-ca", version)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialize a fresh CA (ca.crt + ca.key).
    Init {
        #[arg(long, default_value = "./mesh-ca")]
        out: PathBuf,
    },
    /// Issue a peer cert signed by the CA.
    IssuePeer {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "./mesh-ca")]
        ca_dir: PathBuf,
        #[arg(long, default_value = "./")]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Cmd::Init { out } => init_ca(&out),
        Cmd::IssuePeer { name, ca_dir, out } => issue_peer(&name, &ca_dir, &out),
    }
}

fn init_ca(out: &std::path::Path) -> Result<()> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyUsagePurpose};
    std::fs::create_dir_all(out)?;
    let mut params = CertificateParams::new(vec!["tabbify-mesh-ca".to_string()])?;
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "tabbify-mesh-ca");
        dn
    };
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    std::fs::write(out.join("ca.crt"), cert.pem())?;
    std::fs::write(out.join("ca.key"), key_pair.serialize_pem())?;
    println!("CA initialized at {}", out.display());
    Ok(())
}

fn issue_peer(name: &str, ca_dir: &std::path::Path, out: &std::path::Path) -> Result<()> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    let ca_cert_pem = std::fs::read_to_string(ca_dir.join("ca.crt"))?;
    let ca_key_pem = std::fs::read_to_string(ca_dir.join("ca.key"))?;
    let ca_key = KeyPair::from_pem(&ca_key_pem)?;
    let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let mut params = CertificateParams::new(vec![name.to_string()])?;
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        dn
    };
    let peer_key = KeyPair::generate()?;
    let peer_cert = params.signed_by(&peer_key, &ca_cert, &ca_key)?;

    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("peer.crt"), peer_cert.pem())?;
    std::fs::write(out.join("peer.key"), peer_key.serialize_pem())?;
    println!("Peer cert issued for '{}' at {}", name, out.display());
    Ok(())
}
