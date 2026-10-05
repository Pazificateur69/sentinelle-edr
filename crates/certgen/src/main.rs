//! Genere une mini-PKI pour le mTLS du parc : une autorite (CA), un certificat
//! serveur (SAN localhost) et un certificat client, tous signes par la CA.
//!
//! Usage : `cargo run -p sentinelle-certgen -- [dossier]` (defaut : ./certs)
//! Produit : ca.pem, server.pem, server.key, client.pem, client.key
//!
//! NON COMPILE depuis macOS. A valider sous Windows : API rcgen 0.13
//! (`self_signed`, `signed_by(&key, &issuer_cert, &issuer_key)`, `.pem()`,
//! `KeyPair::serialize_pem()`).

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "certs".to_string()));
    fs::create_dir_all(&dir).with_context(|| format!("creation de {}", dir.display()))?;

    // --- Autorite de certification ---
    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name.push(DnType::CommonName, "Sentinelle Root CA");
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();
    fs::write(dir.join("ca.pem"), &ca_pem)?;

    // --- Certificat serveur (SAN localhost) ---
    let srv_key = KeyPair::generate()?;
    let mut srv = CertificateParams::new(vec!["localhost".to_string()])?;
    srv.distinguished_name.push(DnType::CommonName, "sentinelle-server");
    srv.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    srv.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv_cert = srv.signed_by(&srv_key, &ca_cert, &ca_key)?;
    fs::write(dir.join("server.pem"), srv_cert.pem())?;
    fs::write(dir.join("server.key"), srv_key.serialize_pem())?;

    // --- Certificat client (agents) ---
    let cli_key = KeyPair::generate()?;
    let mut cli = CertificateParams::new(vec!["sentinelle-agent".to_string()])?;
    cli.distinguished_name.push(DnType::CommonName, "sentinelle-agent");
    cli.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key)?;
    fs::write(dir.join("client.pem"), cli_cert.pem())?;
    fs::write(dir.join("client.key"), cli_key.serialize_pem())?;

    println!("PKI generee dans {} :", dir.display());
    println!("  ca.pem  server.pem  server.key  client.pem  client.key");
    println!("Le meme certificat client peut servir a tous les agents (demo).");
    Ok(())
}
