use sentinelle_console::AppState;
use sentinelle_proto::v1::{ingest_server::Ingest, telemetry, Ack, Telemetry};
use tonic::{Request, Response, Status, Streaming};

/// Implementation du service gRPC d'ingestion. Chaque agent ouvre un flux ;
/// chaque message (evenement ou alerte) alimente l'etat partage de la console.
pub struct IngestService {
    pub state: AppState,
}

#[tonic::async_trait]
impl Ingest for IngestService {
    async fn stream(
        &self,
        request: Request<Streaming<Telemetry>>,
    ) -> Result<Response<Ack>, Status> {
        let peer = request.remote_addr();
        let mut stream = request.into_inner();
        let mut received = 0u64;
        tracing::info!("Agent connecte : {peer:?}");

        while let Some(msg) = stream.message().await? {
            received += 1;
            let now = chrono::Utc::now().timestamp();
            match msg.payload {
                Some(telemetry::Payload::Event(e)) => {
                    self.state.ingest_event(sentinelle_proto::event_from_proto(e));
                }
                Some(telemetry::Payload::Alert(a)) => {
                    self.state.ingest_alert(sentinelle_proto::alert_from_proto(a));
                }
                None => {}
            }
            self.state.broadcast_stats(now);
        }

        tracing::info!("Agent deconnecte : {peer:?} ({received} messages)");
        Ok(Response::new(Ack { received }))
    }
}
