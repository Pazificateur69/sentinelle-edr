//! Etat partage + console web temps reel, reutilises par l'agent mono-poste
//! (`sentinelle-agentd`) et le serveur de parc (`sentinelle-server`).

pub mod http;
pub mod state;
pub mod store;

pub use http::base_routes;
pub use state::{AppState, HostRisk, SseMsg, Stats};
pub use store::Store;
