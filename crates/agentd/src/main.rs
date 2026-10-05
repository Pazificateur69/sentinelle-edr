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
    // Canal d'ingestion borné : backpressure plutôt que croissance mémoire illimitée.
    let (inject_tx, inject_rx) = mpsc::channel::<sentinelle_common::Event>(8192);

    let store = open_store();
    let state = AppState::new(sse_tx, host.clone(), Some(inject_tx.clone()), store);
    state.load_history();

    tokio::spawn(ingest::ingest_loop(inject_rx, state.clone()));

    // Capteur de ce poste. Sous Windows : ETW (télémétrie noyau profonde, nécessite
    // l'admin) avec repli automatique sur la scrutation multi-OS si l'ETW ne démarre
    // pas. Ailleurs : scrutation multi-OS. La scrutation est moins profonde (pas de
    // réseau/fichier/handle, rate les process très brefs) mais c'est de la vraie
    // télémétrie, pas une simulation.
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        let tx = inject_tx.clone();
        let h = host.clone();
        let dropped = std::sync::Arc::new(AtomicU64::new(0));
        // try_send : si la file est pleine, on abandonne (et on compte).
        let emit = move |ev: sentinelle_common::Event| {
            if tx.try_send(ev).is_err() {
                let n = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n % 1000 == 0 {
                    tracing::warn!("file d'ingestion pleine : {n} événements abandonnés");
                }
            }
        };
        std::thread::spawn(move || run_sensor(h, emit));
    }

    // Rejeu d'une capture d'événements (JSONL, un Event par ligne) à travers tout
    // le pipeline — utile pour tester/affiner les détections sur de la télémétrie réelle.
    if let Ok(file) = std::env::var("SENTINELLE_REPLAY_FILE") {
        let tx = inject_tx.clone();
        tokio::spawn(async move {
            match std::fs::read_to_string(&file) {
                Ok(content) => {
                    let mut n = 0u64;
                    for line in content.lines().filter(|l| !l.trim().is_empty()) {
                        match serde_json::from_str::<sentinelle_common::Event>(line) {
                            Ok(ev) => {
                                if tx.send(ev).await.is_err() {
                                    break;
                                }
                                n += 1;
                                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                            }
                            Err(e) => tracing::warn!("replay : ligne ignorée ({e})"),
                        }
                    }
                    tracing::info!("Rejeu terminé : {n} événements depuis {file}");
                }
                Err(e) => tracing::error!("rejeu {file} : {e}"),
            }
        });
    }

    let app = http::router(state);
    // Adresse d'écoute de la console, configurable (défaut : 127.0.0.1:8787).
    let addr: SocketAddr = std::env::var("SENTINELLE_HTTP")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Console Sentinelle : http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// Lance le capteur de ce poste (bloquant). Sous Windows : ETW, avec repli sur la
/// scrutation multi-OS si l'ETW ne peut pas démarrer (sans admin, p. ex.). Ailleurs :
/// scrutation multi-OS. `emit` reçoit chaque événement observé.
fn run_sensor<F>(host: String, emit: F)
where
    F: Fn(sentinelle_common::Event) + Send + Sync + Clone + 'static,
{
    #[cfg(windows)]
    {
        tracing::info!("Capteur ETW (lancer en Administrateur pour la télémétrie noyau).");
        if let Err(e) = sentinelle_sensor_windows::run(host.clone(), emit.clone()) {
            tracing::warn!(
                "capteur ETW indisponible ({e:#}) — repli sur la scrutation multi-OS."
            );
            if let Err(e) = sentinelle_sensor_proc::run(host, emit) {
                tracing::error!("capteur multi-OS arrêté : {e:#}");
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Err(e) = sentinelle_sensor_proc::run(host, emit) {
            tracing::error!("capteur multi-OS arrêté : {e:#}");
        }
    }
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
