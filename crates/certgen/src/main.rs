//! Génère la mini-PKI mTLS du parc.
//! Usage : `cargo run -p sentinelle-certgen -- [dossier]` (défaut : ./certs)

use anyhow::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "certs".to_string()));
    sentinelle_certgen::generate_pki(&dir)?;
    println!("PKI générée dans {} :", dir.display());
    println!("  ca.pem  server.pem  server.key  client.pem  client.key");
    Ok(())
}
