//! Agent Sentinelle MONO-POSTE : collecte (ETW sous Windows, simulation ailleurs)
//! -> moteur de detection local -> console web temps reel sur ce poste.
//!
//! Pour un parc de machines, voir `sentinelle-agent` (collecteur) +
//! `sentinelle-server` (serveur central + console multi-hotes).

mod http;
mod ingest;
mod respond;
mod sim;

use anyhow::Result;
use sentinelle_console::AppState;
use std::net::SocketAddr;
use tokio::sync::{broadcast, mpsc};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let host = hostname();
    let (sse_tx, _) = broadcast::channel(1024);
    let (inject_tx, inject_rx) = mpsc::unbounded_channel();

    let store = open_store();
    let state = AppState::new(sse_tx, host.clone(), Some(inject_tx.clone()), store);
    state.load_history();

    tokio::spawn(ingest::ingest_loop(inject_rx, state.clone()));

    #[cfg(windows)]
    {
        let tx = inject_tx.clone();
        let h = host.clone();
        std::thread::spawn(move || {
            if let Err(e) = sentinelle_sensor_windows::run(h, move |ev| {
                let _ = tx.send(ev);
            }) {
                tracing::error!("capteur ETW arrete : {e:#}");
            }
        });
        tracing::info!("Capteur ETW actif (lancer en Administrateur).");
    }
    #[cfg(not(windows))]
    tracing::warn!("Hors Windows : pas de capteur ETW. Bouton 'Simuler une attaque' ou POST /api/simulate.");

    let app = http::router(state);
    let addr: SocketAddr = "127.0.0.1:8787".parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Console Sentinelle : http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".into())
}

/// Ouvre la persistance SQLite si `SENTINELLE_DB` est défini.
fn open_store() -> Option<std::sync::Arc<sentinelle_console::Store>> {
    let path = std::env::var("SENTINELLE_DB").ok()?;
    match sentinelle_console::Store::open(&path) {
        Ok(s) => {
            tracing::info!("Persistance SQLite : {path}");
            Some(std::sync::Arc::new(s))
        }
        Err(e) => {
            tracing::error!("ouverture base {path} : {e:#}");
            None
        }
    }
}
