use sentinelle_console::AppState;
use sentinelle_proto::v1::{ingest_server::Ingest, telemetry, Command, Telemetry};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

/// Registre des agents connectes : hote -> canal d'ordres a lui pousser.
pub type Registry = Arc<Mutex<HashMap<String, mpsc::Sender<Result<Command, Status>>>>>;

pub struct IngestService {
    pub state: AppState,
    pub registry: Registry,
}

type CmdStream = Pin<Box<dyn Stream<Item = Result<Command, Status>> + Send>>;

#[tonic::async_trait]
impl Ingest for IngestService {
    type SessionStream = CmdStream;

    async fn session(
        &self,
        request: Request<Streaming<Telemetry>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let peer = request.remote_addr();
        let mut inbound = request.into_inner();
        // Canal d'ordres serveur -> agent (devient le flux de retour).
        let (cmd_tx, cmd_rx) = mpsc::channel::<Result<Command, Status>>(16);
        let state = self.state.clone();
        let registry = self.registry.clone();
        tracing::info!("Agent connecté : {peer:?}");

        tokio::spawn(async move {
            let mut host: Option<String> = None;
            while let Ok(Some(msg)) = inbound.message().await {
                let now = chrono::Utc::now().timestamp();
                // Apprendre l'hote au 1er message et enregistrer son canal d'ordres.
                if host.is_none() {
                    let h = match &msg.payload {
                        Some(telemetry::Payload::Event(e)) => Some(e.host.clone()),
                        Some(telemetry::Payload::Alert(a)) => Some(a.host.clone()),
                        None => None,
                    };
                    if let Some(hh) = h {
                        registry.lock().unwrap().insert(hh.clone(), cmd_tx.clone());
                        tracing::info!("Agent enregistré : {hh}");
                        host = Some(hh);
                    }
                }
                match msg.payload {
                    Some(telemetry::Payload::Event(e)) => {
                        state.ingest_event(sentinelle_proto::event_from_proto(e))
                    }
                    Some(telemetry::Payload::Alert(a)) => {
                        state.ingest_alert(sentinelle_proto::alert_from_proto(a))
                    }
                    None => {}
                }
                state.broadcast_stats(now);
            }
            if let Some(h) = host {
                registry.lock().unwrap().remove(&h);
                tracing::info!("Agent déconnecté : {h}");
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(cmd_rx)) as CmdStream))
    }
}
