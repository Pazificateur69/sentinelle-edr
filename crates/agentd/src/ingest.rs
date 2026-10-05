use sentinelle_common::{Engine, Event};
use sentinelle_console::AppState;
use tokio::sync::mpsc;

/// Boucle de detection mono-poste : un evenement entre, les regles sortent.
pub async fn ingest_loop(mut rx: mpsc::UnboundedReceiver<Event>, state: AppState) {
    let mut engine = match Engine::with_builtin_rules() {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("regles invalides : {e:#}");
            return;
        }
    };

    // Import optionnel de regles Sigma (SENTINELLE_RULES_DIR).
    if let Ok(dir) = std::env::var("SENTINELLE_RULES_DIR") {
        let (extra, errs) = sentinelle_common::sigma::load_dir(std::path::Path::new(&dir));
        let n = extra.len();
        for (file, msg) in &errs {
            tracing::warn!("Sigma ignore {file} : {msg}");
        }
        engine.add_rules(extra);
        tracing::info!("Sigma : {n} regle(s) importee(s) ({} ignoree(s))", errs.len());
    }

    // Seuils réglables optionnels (SENTINELLE_CONFIG = fichier TOML).
    if let Ok(path) = std::env::var("SENTINELLE_CONFIG") {
        match sentinelle_common::Config::from_file(&path) {
            Ok(cfg) => {
                tracing::info!("Configuration chargée : {path}");
                engine.set_config(cfg);
            }
            Err(e) => tracing::warn!("Config {path} ignorée : {e:#}"),
        }
    }

    // Allowlist externe optionnelle (SENTINELLE_ALLOWLIST = fichier JSON).
    if let Ok(file) = std::env::var("SENTINELLE_ALLOWLIST") {
        match sentinelle_common::suppress::load_file(std::path::Path::new(&file)) {
            Ok(s) => {
                tracing::info!("Allowlist : {} entree(s) chargee(s)", s.len());
                engine.add_suppressions(s);
            }
            Err(e) => tracing::warn!("Allowlist {file} ignoree : {e:#}"),
        }
    }

    let rule_count = engine.rule_count();
    state.set_runtime(rule_count, 0);
    state.broadcast_stats(chrono::Utc::now().timestamp());

    while let Some(ev) = rx.recv().await {
        let now = ev.ts.timestamp();
        let alerts = engine.ingest(ev.clone());
        state.ingest_event(ev);
        for a in alerts {
            state.ingest_alert(a);
        }
        state.set_runtime(rule_count, engine.tracked_processes());
        state.broadcast_stats(now);
    }
}
