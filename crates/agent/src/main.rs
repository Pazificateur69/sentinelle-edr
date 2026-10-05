//! Agent de parc Sentinelle : collecte les evenements (ETW sous Windows,
//! chaine simulee ailleurs), applique le moteur de detection en local, et
//! pousse evenements + alertes au serveur central via gRPC + mTLS.
//!
//! NON COMPILE depuis macOS. A valider sous Windows : API client TLS tonic 0.14
//! (`ClientTlsConfig`, `Channel::from_shared(...).tls_config(...).connect()`),
//! et le streaming client (`client.stream(Request::new(ReceiverStream))`).
//!
//! Variables : SENTINELLE_HOST (nom du poste), SENTINELLE_SERVER (def.
//! https://localhost:50051), SENTINELLE_CERTS_DIR (def. certs),
//! SENTINELLE_RULES_DIR (regles Sigma), SENTINELLE_REPLAY_SECS (rejoue la
//! simulation en boucle toutes les N s).

mod respond;

use anyhow::{Context, Result};
use sentinelle_common::{Engine, Event};
use sentinelle_proto::v1::ingest_client::IngestClient;
use sentinelle_proto::v1::Telemetry;
use sentinelle_proto::{tel_alert, tel_event};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::Request;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let host = std::env::var("SENTINELLE_HOST")
        .ok()
        .or_else(|| std::env::args().nth(1))
        .unwrap_or_else(hostname);
    let endpoint =
        std::env::var("SENTINELLE_SERVER").unwrap_or_else(|_| "https://localhost:50051".to_string());
    let certs = PathBuf::from(std::env::var("SENTINELLE_CERTS_DIR").unwrap_or_else(|_| "certs".to_string()));

    // mTLS client.
    let ca = std::fs::read(certs.join("ca.pem")).context("lecture certs/ca.pem")?;
    let cli_cert = std::fs::read(certs.join("client.pem")).context("lecture certs/client.pem")?;
    let cli_key = std::fs::read(certs.join("client.key")).context("lecture certs/client.key")?;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cli_cert, cli_key))
        .domain_name("localhost");

    let channel = Channel::from_shared(endpoint.clone())?
        .tls_config(tls)?
        .connect()
        .await
        .with_context(|| format!("connexion a {endpoint}"))?;
    let mut client = IngestClient::new(channel);
    tracing::info!("Connecte a {endpoint} en tant que '{host}'");

    // Flux bidirectionnel : on envoie des Telemetry et on reçoit des ordres.
    let (tx_tel, rx_tel) = mpsc::channel::<Telemetry>(1024);
    let response = client
        .session(Request::new(ReceiverStream::new(rx_tel)))
        .await
        .context("ouverture du flux gRPC")?;
    let mut commands = response.into_inner();

    // Battement de cœur périodique : prouve que le capteur est vivant, même sans activité.
    {
        let hb_tx = tx_tel.clone();
        let hb_host = host.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(10));
            loop {
                iv.tick().await;
                if hb_tx
                    .send(sentinelle_proto::tel_heartbeat(&hb_host))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    // Tâche de réception des ordres de réponse (ex. kill) venant du serveur.
    let cmd_task = tokio::spawn(async move {
        while let Ok(Some(cmd)) = commands.message().await {
            if cmd.kind == "kill" {
                match crate::respond::kill_process(cmd.pid) {
                    Ok(()) => tracing::warn!("Réponse : processus {} terminé (ordre serveur)", cmd.pid),
                    Err(e) => tracing::error!("Réponse kill {} : {e:#}", cmd.pid),
                }
            }
        }
    });

    // Moteur de detection local.
    let mut engine = Engine::with_builtin_rules()?;
    if let Ok(dir) = std::env::var("SENTINELLE_RULES_DIR") {
        let (extra, _errs) = sentinelle_common::sigma::load_dir(std::path::Path::new(&dir));
        engine.add_rules(extra);
    }
    if let Ok(path) = std::env::var("SENTINELLE_CONFIG") {
        if let Ok(cfg) = sentinelle_common::Config::from_file(&path) {
            engine.set_config(cfg);
        }
    }
    // Scan YARA optionnel (SENTINELLE_YARA_DIR).
    let yara: Option<Arc<sentinelle_scan::YaraScanner>> = std::env::var("SENTINELLE_YARA_DIR")
        .ok()
        .and_then(|d| sentinelle_scan::YaraScanner::from_dir(std::path::Path::new(&d)).ok().flatten())
        .map(Arc::new);
    if yara.is_some() {
        tracing::info!("YARA actif sur l'agent.");
    }

    #[cfg(windows)]
    {
        let (ev_tx, mut ev_rx) = mpsc::channel::<Event>(8192);
        let h = host.clone();
        std::thread::spawn(move || {
            if let Err(e) = sentinelle_sensor_windows::run(h, move |ev| {
                // try_send : file bornée, abandon silencieux si saturée.
                let _ = ev_tx.try_send(ev);
            }) {
                tracing::error!("capteur ETW : {e:#}");
            }
        });
        while let Some(ev) = ev_rx.recv().await {
            process(&mut engine, ev, &tx_tel, &yara).await;
        }
    }

    #[cfg(not(windows))]
    {
        tracing::warn!("Hors Windows : rejoue la chaine d'attaque simulee.");
        let repeat = std::env::var("SENTINELLE_REPLAY_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok());
        loop {
            for ev in sentinelle_common::scenario::attack_chain(&host) {
                process(&mut engine, ev, &tx_tel, &yara).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            match repeat {
                Some(s) => tokio::time::sleep(Duration::from_secs(s)).await,
                None => break,
            }
        }
    }

    drop(tx_tel); // ferme le flux sortant
    let _ = cmd_task.await;
    Ok(())
}

/// Detecte localement puis pousse l'evenement et ses alertes au serveur.
async fn process(
    engine: &mut Engine,
    ev: Event,
    tx: &mpsc::Sender<Telemetry>,
    yara: &Option<Arc<sentinelle_scan::YaraScanner>>,
) {
    let mut alerts = engine.ingest(ev.clone());
    if let Some(sc) = yara {
        let sc = sc.clone();
        let ev2 = ev.clone();
        let hits = tokio::task::spawn_blocking(move || {
            sentinelle_scan::scan_image_alerts(&sc, &ev2, sentinelle_scan::DEFAULT_MAX_BYTES)
        })
        .await
        .unwrap_or_default();
        alerts.extend(hits);
    }
    let _ = tx.send(tel_event(&ev)).await;
    for a in alerts {
        let _ = tx.send(tel_alert(&a)).await;
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "poste-inconnu".to_string())
}
