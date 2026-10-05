use sentinelle_common::{risk::RiskTracker, Alert, Event};
use serde::Serialize;
use std::collections::VecDeque;
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
    /// Canal d'injection d'evenement (mode mono-poste, pour la simulation).
    /// `None` cote serveur de parc (les evenements arrivent par gRPC).
    pub inject: Option<mpsc::UnboundedSender<Event>>,
    /// Persistance SQLite optionnelle des alertes.
    pub store: Option<Arc<crate::store::Store>>,
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
        inject: Option<mpsc::UnboundedSender<Event>>,
        store: Option<Arc<crate::store::Store>>,
    ) -> Self {
        AppState {
            tx,
            host,
            inject,
            store,
            inner: Arc::new(Mutex::new(Shared {
                alerts: VecDeque::new(),
                events: VecDeque::new(),
                risk: RiskTracker::new(),
                last_stats: Stats::default(),
            })),
        }
    }

    /// Enregistre un evenement et le diffuse.
    pub fn ingest_event(&self, ev: Event) {
        {
            let mut s = self.inner.lock().unwrap();
            s.last_stats.total_events += 1;
            push_cap(&mut s.events, ev.clone(), MAX_EVENTS);
        }
        let _ = self.tx.send(SseMsg::Event(ev));
    }

    /// Enregistre une alerte (peut provenir de n'importe quel hote), met a jour
    /// le risque de cet hote, et diffuse.
    pub fn ingest_alert(&self, a: Alert) {
        let now = a.ts.timestamp();
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
    }

    /// Met a jour les compteurs runtime (nombre de regles, process suivis).
    pub fn set_runtime(&self, rule_count: usize, tracked: usize) {
        let mut s = self.inner.lock().unwrap();
        s.last_stats.rule_count = rule_count;
        s.last_stats.tracked_processes = tracked;
    }

    /// Recalcule la table de risque par hote et diffuse les stats.
    pub fn broadcast_stats(&self, now: i64) {
        let stats = {
            let mut s = self.inner.lock().unwrap();
            let mut hosts: Vec<HostRisk> = s
                .risk
                .hosts(now)
                .into_iter()
                .map(|(host, score)| HostRisk {
                    host,
                    score: score.round() as u32,
                    level: level_of(score),
                })
                .collect();
            hosts.sort_by(|a, b| b.score.cmp(&a.score));
            s.last_stats.hosts = hosts;
            s.last_stats.clone()
        };
        let _ = self.tx.send(SseMsg::Stats(stats));
    }
}
