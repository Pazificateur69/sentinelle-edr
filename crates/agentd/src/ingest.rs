use sentinelle_common::{Alert, Engine, Event};
use sentinelle_console::AppState;
use sentinelle_scan::YaraScanner;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Boucle de detection mono-poste : un evenement entre, les regles sortent.
pub async fn ingest_loop(mut rx: mpsc::Receiver<Event>, state: AppState) {
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

    // Scan YARA optionnel des images de processus (SENTINELLE_YARA_DIR).
    let yara: Option<Arc<YaraScanner>> = std::env::var("SENTINELLE_YARA_DIR")
        .ok()
        .and_then(|d| match YaraScanner::from_dir(std::path::Path::new(&d)) {
            Ok(Some(s)) => {
                tracing::info!("YARA actif : règles chargées depuis {d}");
                Some(Arc::new(s))
            }
            Ok(None) => {
                tracing::warn!("YARA : aucune règle valide dans {d}");
                None
            }
            Err(e) => {
                tracing::warn!("YARA {d} ignoré : {e:#}");
                None
            }
        });

    let rule_count = engine.rule_count();
    state.set_runtime(rule_count, 0);
    state.broadcast_stats(chrono::Utc::now().timestamp());

    while let Some(ev) = rx.recv().await {
        let now = ev.ts.timestamp();
        let mut alerts = engine.ingest(ev.clone());
        if let Some(scanner) = &yara {
            alerts.extend(yara_scan_image(scanner.clone(), &ev).await);
        }
        state.ingest_event(ev);
        for a in alerts {
            state.ingest_alert(a);
        }
        state.set_runtime(rule_count, engine.tracked_processes());
        state.broadcast_stats(now);
    }
}

/// Scanne l'image d'un nouveau processus avec YARA, hors du thread async
/// (lecture disque + scan sont bloquants). Une alerte par règle correspondante.
async fn yara_scan_image(scanner: Arc<YaraScanner>, ev: &Event) -> Vec<Alert> {
    let ev2 = ev.clone();
    tokio::task::spawn_blocking(move || {
        sentinelle_scan::scan_image_alerts(&scanner, &ev2, sentinelle_scan::DEFAULT_MAX_BYTES)
    })
    .await
    .unwrap_or_default()
}
