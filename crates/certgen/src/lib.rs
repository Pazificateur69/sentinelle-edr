//! Génère une mini-PKI pour le mTLS du parc : CA + cert serveur (SAN localhost)
//! + cert client, tous signés par la CA. Réutilisable (bin + tests).

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::fs;
use std::path::Path;

/// Écrit ca.pem, server.pem, server.key, client.pem, client.key dans `dir`.
pub fn generate_pki(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("création de {}", dir.display()))?;

    // Autorité de certification.
    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "Sentinelle Root CA");
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key)?;
    fs::write(dir.join("ca.pem"), ca_cert.pem())?;

    // Certificat serveur (SAN localhost).
    let srv_key = KeyPair::generate()?;
    let mut srv = CertificateParams::new(vec!["localhost".to_string()])?;
    srv.distinguished_name
        .push(DnType::CommonName, "sentinelle-server");
    srv.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    srv.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv_cert = srv.signed_by(&srv_key, &ca_cert, &ca_key)?;
    fs::write(dir.join("server.pem"), srv_cert.pem())?;
    fs::write(dir.join("server.key"), srv_key.serialize_pem())?;

    // Certificat client (agents).
    let cli_key = KeyPair::generate()?;
    let mut cli = CertificateParams::new(vec!["sentinelle-agent".to_string()])?;
    cli.distinguished_name
        .push(DnType::CommonName, "sentinelle-agent");
    cli.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key)?;
    fs::write(dir.join("client.pem"), cli_cert.pem())?;
    fs::write(dir.join("client.key"), cli_key.serialize_pem())?;

    Ok(())
}
