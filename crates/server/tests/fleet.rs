//! Test d'intégration du parc : valide AU RUNTIME (en CI) le chemin complet
//! certs → serveur ↔ agent en **mTLS**, flux **bidirectionnel**, ingestion
//! côté serveur et **routage d'un ordre de réponse** (kill) vers le client.
//!
//! C'est la validation runtime du parc qui, sinon, nécessiterait une machine
//! dédiée : handshake TLS mutuel, streaming gRPC, registre d'agents, commande.

use sentinelle_common::{Alert, Event, Severity};
use sentinelle_console::AppState;
use sentinelle_proto::tel_alert;
use sentinelle_proto::v1::ingest_client::IngestClient;
use sentinelle_proto::v1::{ingest_server::IngestServer, Command};
use sentinelle_server::ingest::{IngestService, Registry};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_fleet_roundtrip() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    sentinelle_certgen::generate_pki(dir.path())?;
    let read = |f: &str| std::fs::read(dir.path().join(f)).unwrap();

    // --- Serveur ---
    let (sse_tx, _) = broadcast::channel(64);
    let state = AppState::new(sse_tx, "srv".into(), None, None);
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    let svc = IngestService {
        state: state.clone(),
        registry: registry.clone(),
    };

    let srv_tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(read("server.pem"), read("server.key")))
        .client_ca_root(Certificate::from_pem(read("ca.pem")));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);

    tokio::spawn(async move {
        Server::builder()
            .tls_config(srv_tls)
            .unwrap()
            .add_service(IngestServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    // --- Client (agent) ---
    let cli_tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read("ca.pem")))
        .identity(Identity::from_pem(read("client.pem"), read("client.key")))
        .domain_name("localhost");
    let endpoint = Channel::from_shared(format!("https://localhost:{}", addr.port()))?
        .tls_config(cli_tls)?;

    let channel = {
        let mut got = None;
        for _ in 0..50 {
            if let Ok(c) = endpoint.connect().await {
                got = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        got.expect("connexion mTLS au serveur")
    };
    let mut client = IngestClient::new(channel);

    let (tx_tel, rx_tel) = mpsc::channel(16);
    let response = client
        .session(tonic::Request::new(ReceiverStream::new(rx_tel)))
        .await?;
    let mut inbound = response.into_inner();

    // L'agent pousse une alerte pour l'hôte "poste-x".
    let alert = Alert {
        ts: chrono::Utc::now(),
        host: "poste-x".into(),
        rule_id: "R1".into(),
        title: "t".into(),
        description: "d".into(),
        severity: Severity::High,
        attack: vec!["T1059".into()],
        score: 70,
        event: Event::process_start("poste-x", 1, 2, r"C:\a.exe", ""),
        ancestors: vec![],
    };
    tx_tel.send(tel_alert(&alert)).await?;
    // Battement de cœur (santé du capteur).
    tx_tel
        .send(sentinelle_proto::tel_heartbeat("poste-x"))
        .await?;

    // Le serveur ingère l'alerte et enregistre l'agent.
    let mut registered = false;
    for _ in 0..60 {
        if registry.lock().unwrap().contains_key("poste-x") {
            registered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(registered, "l'agent 'poste-x' doit être enregistré côté serveur");
    assert!(
        state.inner.lock().unwrap().last_stats.total_alerts >= 1,
        "l'alerte doit être ingérée côté serveur"
    );
    assert!(
        state.seen.lock().unwrap().contains_key("poste-x"),
        "la santé du capteur (heartbeat) doit être enregistrée"
    );

    // Le serveur pousse un ordre de kill ; l'agent doit le recevoir.
    registry
        .lock()
        .unwrap()
        .get("poste-x")
        .cloned()
        .unwrap()
        .try_send(Ok(Command {
            kind: "kill".into(),
            pid: 4242,
        }))
        .unwrap();

    let cmd = tokio::time::timeout(Duration::from_secs(3), inbound.message())
        .await??
        .expect("l'agent doit recevoir l'ordre");
    assert_eq!(cmd.kind, "kill");
    assert_eq!(cmd.pid, 4242);

    Ok(())
}
