use sentinelle_common::{risk::RiskTracker, Alert, Event};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

const MAX_ALERTS: usize = 500;
const MAX_EVENTS: usize = 2000;

/// Message pousse aux clients de la console (SSE).
#[derive(Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "lowercase")]
pub enum SseMsg {
    Event(Event),
    Alert(Alert),
    Stats(Stats),
}

#[derive(Clone, Serialize, Default)]
pub struct HostRisk {
    pub host: String,
    pub score: u32,
    pub level: &'static str,
    /// Secondes depuis la dernière télémétrie reçue de cet hôte.
    pub silent_secs: i64,
    /// Vivacité du capteur : "live" | "stale" | "silent".
    pub status: &'static str,
}

/// Vivacité d'un hôte d'après son silence (heartbeat attendu ~10 s).
pub fn liveness(silent_secs: i64) -> &'static str {
    if silent_secs > 60 {
        "silent"
    } else if silent_secs > 25 {
        "stale"
    } else {
        "live"
    }
}

#[derive(Clone, Serialize, Default)]
pub struct Stats {
    pub total_events: u64,
    pub total_alerts: u64,
    pub rule_count: usize,
    pub tracked_processes: usize,
    pub hosts: Vec<HostRisk>,
}

pub fn level_of(score: f64) -> &'static str {
    if score >= 100.0 {
        "critical"
    } else if score >= 40.0 {
        "warning"
    } else {
        "ok"
    }
}

pub struct Shared {
    pub alerts: VecDeque<Alert>,
    pub events: VecDeque<Event>,
    pub risk: RiskTracker,
    pub last_stats: Stats,
}

/// Etat partage d'un nœud (agent mono-poste ou serveur de parc).
#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<SseMsg>,
    pub host: String,
    /// Canal d'injection d'evenement BORNÉ (mode mono-poste, simulation/capteur).
    /// Borné pour éviter l'OOM sous un flot d'événements ; `None` côté serveur de
    /// parc (les événements arrivent par gRPC).
    pub inject: Option<mpsc::Sender<Event>>,
    /// Persistance SQLite optionnelle des alertes.
    pub store: Option<Arc<crate::store::Store>>,
    /// Dernière télémétrie reçue par hôte (epoch secondes) — santé des capteurs.
    pub seen: Arc<Mutex<HashMap<String, i64>>>,
    pub inner: Arc<Mutex<Shared>>,
}

fn push_cap<T>(q: &mut VecDeque<T>, item: T, cap: usize) {
    q.push_front(item);
    while q.len() > cap {
        q.pop_back();
    }
}

impl AppState {
    pub fn new(
        tx: broadcast::Sender<SseMsg>,
        host: String,
        inject: Option<mpsc::Sender<Event>>,
        store: Option<Arc<crate::store::Store>>,
    ) -> Self {
        AppState {
            tx,
            host,
            inject,
            store,
            seen: Arc::new(Mutex::new(HashMap::new())),
            inner: Arc::new(Mutex::new(Shared {
                alerts: VecDeque::new(),
                events: VecDeque::new(),
                risk: RiskTracker::new(),
                last_stats: Stats::default(),
            })),
        }
    }

    /// Note qu'on vient de recevoir de la télémétrie de cet hôte (santé capteur).
    pub fn mark_seen(&self, host: &str, now: i64) {
        self.seen.lock().unwrap().insert(host.to_string(), now);
    }

    /// Enregistre un evenement et le diffuse.
    pub fn ingest_event(&self, ev: Event) {
        self.mark_seen(&ev.host, ev.ts.timestamp());
        {
            let mut s = self.inner.lock().unwrap();
            s.last_stats.total_events += 1;
            push_cap(&mut s.events, ev.clone(), MAX_EVENTS);
        }
        // ponytail: persistance synchrone par événement ; batcher si débit élevé.
        if let Some(store) = &self.store {
            let _ = store.insert_event(&ev);
        }
        let _ = self.tx.send(SseMsg::Event(ev));
    }

    /// Enregistre une alerte (peut provenir de n'importe quel hote), met a jour
    /// le risque de cet hote, et diffuse.
    pub fn ingest_alert(&self, a: Alert) {
        let now = a.ts.timestamp();
        self.mark_seen(&a.host, now);
        {
            let mut s = self.inner.lock().unwrap();
            s.last_stats.total_alerts += 1;
            s.risk.add(&a.host, a.score, now);
            push_cap(&mut s.alerts, a.clone(), MAX_ALERTS);
        }
        // Persistance best-effort (ne bloque jamais le flux).
        if let Some(store) = &self.store {
            if let Err(e) = store.insert_alert(&a) {
                tracing::warn!("persistance alerte échouée : {e:#}");
            }
        }
        let _ = self.tx.send(SseMsg::Alert(a));
    }

    /// Recharge l'historique d'alertes depuis la base (au démarrage).
    pub fn load_history(&self) {
        let Some(store) = &self.store else {
            return;
        };
        if let Ok(total) = store.count() {
            self.inner.lock().unwrap().last_stats.total_alerts = total;
        }
        if let Ok(alerts) = store.recent(MAX_ALERTS) {
            let mut s = self.inner.lock().unwrap();
            for a in alerts.into_iter().rev() {
                s.alerts.push_front(a); // la plus récente finit en tête
            }
            tracing::info!("historique rechargé : {} alertes", s.alerts.len());
        }
        // Purge au démarrage (borne la taille de la base).
        let _ = store.prune();
    }

    /// Met a jour les compteurs runtime (nombre de regles, process suivis).
    pub fn set_runtime(&self, rule_count: usize, tracked: usize) {
        let mut s = self.inner.lock().unwrap();
        s.last_stats.rule_count = rule_count;
        s.last_stats.tracked_processes = tracked;
    }

    /// Recalcule la table par hôte (risque + vivacité du capteur) et diffuse.
    pub fn broadcast_stats(&self, now: i64) {
        let seen = self.seen.lock().unwrap().clone();
        let stats = {
            let mut s = self.inner.lock().unwrap();
            // Union des hôtes vus (heartbeat/télémétrie) et des hôtes à risque.
            let mut names: std::collections::BTreeSet<String> = seen.keys().cloned().collect();
            for (h, _) in s.risk.hosts(now) {
                names.insert(h);
            }
            let mut hosts: Vec<HostRisk> = names
                .into_iter()
                .map(|host| {
                    let score = s.risk.score(&host, now);
                    let last = seen.get(&host).copied().unwrap_or(now);
                    let silent = (now - last).max(0);
                    HostRisk {
                        host,
                        score: score.round() as u32,
                        level: level_of(score),
                        silent_secs: silent,
                        status: liveness(silent),
                    }
                })
                .collect();
            hosts.sort_by(|a, b| b.score.cmp(&a.score));
            s.last_stats.hosts = hosts;
            s.last_stats.clone()
        };
        let _ = self.tx.send(SseMsg::Stats(stats));
    }
}

#[cfg(test)]
mod tests {
    use super::liveness;

    #[test]
    fn liveness_thresholds() {
        assert_eq!(liveness(5), "live");
        assert_eq!(liveness(40), "stale");
        assert_eq!(liveness(120), "silent");
    }
}
