//! Rejoue une chaine d'attaque realiste pour faire reagir le moteur et animer
//! la console (demo, et plateformes sans ETW).

use sentinelle_console::AppState;
use std::time::Duration;

pub async fn run_simulation(state: AppState) {
    let Some(inject) = state.inject.clone() else {
        tracing::warn!("Simulation indisponible : pas de canal d'injection.");
        return;
    };
    let step = Duration::from_millis(500);
    for ev in sentinelle_common::scenario::attack_chain(&state.host) {
        if inject.send(ev).is_err() {
            break;
        }
        tokio::time::sleep(step).await;
    }
    tracing::info!("Simulation d'attaque terminee.");
}
