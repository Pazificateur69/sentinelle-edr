use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use sentinelle_console::{base_routes, AppState};
use serde_json::json;
use tower_http::cors::CorsLayer;

/// Routes de base (console) + routes specifiques a l'agent mono-poste.
pub fn router(state: AppState) -> Router {
    base_routes()
        .route("/api/simulate", post(simulate))
        .route("/api/respond/kill/{host}/{pid}", post(kill))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn simulate(State(st): State<AppState>) -> StatusCode {
    tokio::spawn(crate::sim::run_simulation(st));
    StatusCode::ACCEPTED
}

async fn kill(
    State(_st): State<AppState>,
    Path((_host, pid)): Path<(String, u32)>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Mono-poste : l'hôte est le poste local, on tue directement par pid.
    match crate::respond::kill_process(pid) {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true, "pid": pid }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": e.to_string() })),
        ),
    }
}
