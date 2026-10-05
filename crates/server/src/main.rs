//! Serveur de parc Sentinelle.
//!
//! - Ingestion **gRPC + mTLS** : plusieurs agents poussent leur telemetrie.
//! - Console web **multi-hotes** : le panneau "Risque par hote" agrege tous
//!   les postes connectes.
//!
//! NON COMPILE depuis macOS (deps lourdes). A valider sous Windows : API TLS de
//! tonic 0.14 (`ServerTlsConfig`/`Identity`/`Certificate`), nom de la feature
//! TLS ("tls-ring"), signature de `Server::builder().tls_config(...)`.

mod ingest;

use anyhow::{Context, Result};
use ingest::IngestService;
use sentinelle_common::Engine;
use sentinelle_console::{base_routes, AppState};
use sentinelle_proto::v1::ingest_server::IngestServer;
use std::path::PathBuf;
use tokio::sync::broadcast;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let (sse_tx, _) = broadcast::channel(2048);
    let state = AppState::new(sse_tx, "serveur-central".to_string(), None);
    if let Ok(e) = Engine::with_builtin_rules() {
        state.set_runtime(e.rule_count(), 0);
    }
    state.broadcast_stats(chrono::Utc::now().timestamp());

    // --- Console HTTP (multi-hotes) ---
    let http_addr = std::env::var("SENTINELLE_HTTP").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let app = base_routes()
        .layer(CorsLayer::permissive())
        .with_state(state.clone());
    {
        let http_addr = http_addr.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&http_addr).await {
                Ok(listener) => {
                    tracing::info!("Console parc : http://{http_addr}");
                    if let Err(e) = axum::serve(listener, app).await {
                        tracing::error!("console : {e}");
                    }
                }
                Err(e) => tracing::error!("bind console {http_addr} : {e}"),
            }
        });
    }

    // --- Ingestion gRPC + mTLS ---
    let certs = PathBuf::from(std::env::var("SENTINELLE_CERTS_DIR").unwrap_or_else(|_| "certs".to_string()));
    let ca = std::fs::read(certs.join("ca.pem")).context("lecture certs/ca.pem")?;
    let srv_cert = std::fs::read(certs.join("server.pem")).context("lecture certs/server.pem")?;
    let srv_key = std::fs::read(certs.join("server.key")).context("lecture certs/server.key")?;

    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(srv_cert, srv_key))
        .client_ca_root(Certificate::from_pem(ca)); // mTLS : exige un cert client valide

    let grpc_addr = std::env::var("SENTINELLE_GRPC")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()
        .context("adresse gRPC invalide")?;
    tracing::info!("Ingestion gRPC (mTLS) : {grpc_addr}");

    Server::builder()
        .tls_config(tls)?
        .add_service(IngestServer::new(IngestService { state }))
        .serve(grpc_addr)
        .await?;
    Ok(())
}
