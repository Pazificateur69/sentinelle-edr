//! Serveur de parc Sentinelle.
//!
//! - Ingestion **gRPC + mTLS bidirectionnelle** : les agents poussent leur
//!   télémétrie et reçoivent en retour les ordres de réponse.
//! - Console web **multi-hôtes** avec **réponse à distance** : depuis la console,
//!   `POST /api/respond/kill/{host}/{pid}` pousse un ordre de kill à l'agent visé.
//!
//! NON COMPILÉ depuis macOS : validé par la CI (Ubuntu + Windows).

use anyhow::{Context, Result};
use axum::{
    extract::Path, http::StatusCode, middleware, response::Json, routing::post, Extension, Router,
};
use sentinelle_common::Engine;
use sentinelle_console::{base_routes, require_token, AppState};
use sentinelle_proto::v1::{ingest_server::IngestServer, Command};
use sentinelle_server::ingest::{IngestService, Registry};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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
    let store =
        std::env::var("SENTINELLE_DB")
            .ok()
            .and_then(|path| match sentinelle_console::Store::open(&path) {
                Ok(s) => {
                    tracing::info!("Persistance SQLite : {path}");
                    Some(Arc::new(s))
                }
                Err(e) => {
                    tracing::error!("ouverture base {path} : {e:#}");
                    None
                }
            });
    let state = AppState::new(sse_tx, "serveur-central".to_string(), None, store);
    state.load_history();
    if let Ok(e) = Engine::with_builtin_rules() {
        state.set_runtime(e.rule_count(), 0);
    }
    state.broadcast_stats(chrono::Utc::now().timestamp());

    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));

    // --- Console HTTP (multi-hôtes) + réponse à distance ---
    let http_addr =
        std::env::var("SENTINELLE_HTTP").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    // La réponse `kill` à distance est destructrice : garde par jeton
    // (`SENTINELLE_TOKEN`). Ouvert si non défini, mais FORTEMENT recommandé pour
    // un serveur de parc exposé au réseau.
    let kill_route = Router::new()
        .route("/api/respond/kill/{host}/{pid}", post(kill))
        .route_layer(middleware::from_fn(require_token));
    let app: Router = base_routes()
        .with_state(state.clone())
        .merge(kill_route)
        .layer(Extension(registry.clone()))
        .layer(CorsLayer::permissive());
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
    let certs = PathBuf::from(
        std::env::var("SENTINELLE_CERTS_DIR").unwrap_or_else(|_| "certs".to_string()),
    );
    let ca = std::fs::read(certs.join("ca.pem")).context("lecture certs/ca.pem")?;
    let srv_cert = std::fs::read(certs.join("server.pem")).context("lecture certs/server.pem")?;
    let srv_key = std::fs::read(certs.join("server.key")).context("lecture certs/server.key")?;

    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(srv_cert, srv_key))
        .client_ca_root(Certificate::from_pem(ca));

    let grpc_addr = std::env::var("SENTINELLE_GRPC")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()
        .context("adresse gRPC invalide")?;
    tracing::info!("Ingestion gRPC (mTLS) : {grpc_addr}");

    Server::builder()
        .tls_config(tls)?
        .add_service(IngestServer::new(IngestService { state, registry }))
        .serve(grpc_addr)
        .await?;
    Ok(())
}

/// Pousse un ordre de terminaison de processus à l'agent `host`.
async fn kill(
    Path((host, pid)): Path<(String, u32)>,
    Extension(reg): Extension<Registry>,
) -> (StatusCode, Json<serde_json::Value>) {
    let sender = reg.lock().unwrap().get(&host).cloned();
    match sender {
        Some(tx) => match tx.try_send(Ok(Command {
            kind: "kill".to_string(),
            pid,
        })) {
            Ok(()) => (
                StatusCode::OK,
                Json(json!({ "ok": true, "host": host, "pid": pid })),
            ),
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "ok": false, "error": format!("file de l'agent : {e}") })),
            ),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": format!("agent '{host}' non connecté") })),
        ),
    }
}
