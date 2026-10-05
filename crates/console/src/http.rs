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
        .route("/api/history", get(history))
        .route("/api/coverage", get(coverage))
        .route("/api/report", get(report))
        .route("/healthz", get(healthz))
}

/// Rapport d'incident Markdown téléchargeable, construit à partir des alertes
/// persistées (ou du tampon mémoire). Se convertit en PDF par impression.
async fn report(State(st): State<AppState>) -> impl axum::response::IntoResponse {
    let alerts = collect_alerts(&st);
    let now = chrono::Utc::now();
    let md = sentinelle_common::report::incident_markdown(&st.host, now, &alerts);
    let filename = format!("rapport-incident-{}.md", now.format("%Y%m%d-%H%M%S"));
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/markdown; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        md,
    )
}

/// Source d'alertes pour le rapport : SQLite si activé, sinon tampon mémoire.
fn collect_alerts(st: &AppState) -> Vec<Alert> {
    if let Some(store) = &st.store {
        if let Ok(a) = store.recent(1000) {
            return a;
        }
    }
    st.inner.lock().unwrap().alerts.iter().cloned().collect()
}

/// Sonde de disponibilité (ops / orchestrateur).
async fn healthz() -> &'static str {
    "ok"
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
    if let Some(store) = &st.store {
        if let Ok(e) = store.recent_events(200) {
            return Json(e);
        }
    }
    let s = st.inner.lock().unwrap();
    Json(s.events.iter().take(200).cloned().collect())
}

async fn stats(State(st): State<AppState>) -> Json<Stats> {
    let s = st.inner.lock().unwrap();
    Json(s.last_stats.clone())
}

/// Couverture MITRE ATT&CK par tactique (nombre de règles), pour la console.
async fn coverage() -> Json<Vec<(String, usize)>> {
    match sentinelle_common::Engine::with_builtin_rules() {
        Ok(e) => Json(e.tactic_coverage()),
        Err(_) => Json(vec![]),
    }
}

/// Historique persistant (depuis SQLite si activé, sinon le tampon en mémoire).
async fn history(State(st): State<AppState>) -> Json<Vec<Alert>> {
    if let Some(store) = &st.store {
        if let Ok(a) = store.recent(300) {
            return Json(a);
        }
    }
    let s = st.inner.lock().unwrap();
    Json(s.alerts.iter().cloned().collect())
}
