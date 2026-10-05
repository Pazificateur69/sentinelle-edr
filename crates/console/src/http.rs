use crate::state::{AppState, Stats};
use axum::{
    extract::State,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        Html, Json,
    },
    routing::get,
    Router,
};
use futures::Stream;
use sentinelle_common::{Alert, Event};
use std::convert::Infallible;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

/// Console embarquee dans le binaire : aucun fichier externe a deployer.
const INDEX: &str = include_str!("../../../console/index.html");

/// Routes communes (console + API de lecture + flux SSE).
/// Le binaire applique `.with_state(state)` et peut `.merge()` des routes en plus.
pub fn base_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/api/stream", get(stream))
        .route("/api/alerts", get(alerts))
        .route("/api/events", get(events))
        .route("/api/stats", get(stats))
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn stream(
    State(st): State<AppState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = st.tx.subscribe();
    let s = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(m) => SseEvent::default().json_data(&m).ok().map(Ok),
        Err(_) => None,
    });
    Sse::new(s).keep_alive(KeepAlive::default())
}

async fn alerts(State(st): State<AppState>) -> Json<Vec<Alert>> {
    let s = st.inner.lock().unwrap();
    Json(s.alerts.iter().cloned().collect())
}

async fn events(State(st): State<AppState>) -> Json<Vec<Event>> {
    let s = st.inner.lock().unwrap();
    Json(s.events.iter().take(200).cloned().collect())
}

async fn stats(State(st): State<AppState>) -> Json<Stats> {
    let s = st.inner.lock().unwrap();
    Json(s.last_stats.clone())
}
