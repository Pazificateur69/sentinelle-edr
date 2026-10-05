//! Corrélation d'alertes en incidents.
//!
//! Un « incident » regroupe les alertes d'une même séquence : même hôte,
//! rapprochées dans le temps. Une rafale de N alertes isolées devient une seule
//! histoire lisible pour l'analyste (et un seul bloc dans le rapport / la console).
//!
//! ponytail: heuristique hôte + fenêtre temporelle (pas de lignée pid). Suffit à
//! grouper une chaîne d'attaque ; si deux attaques distinctes tombent dans la
//! même fenêtre sur le même hôte, elles fusionnent. Raffiner par ascendance
//! commune (pid racine) si le besoin apparaît.

use crate::{tactic_of, Alert, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Écart max entre deux alertes consécutives d'un même incident.
pub const DEFAULT_WINDOW_SECS: i64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub host: String,
    pub started: DateTime<Utc>,
    pub ended: DateTime<Utc>,
    pub severity: Severity,
    /// Score cumulé (le volume compte pour un incident, pas que le pic).
    pub score: u32,
    pub alert_count: usize,
    /// Techniques ATT&CK distinctes (triées).
    pub techniques: Vec<String>,
    /// Tactiques distinctes, dans l'ordre kill chain.
    pub tactics: Vec<String>,
    pub alerts: Vec<Alert>,
}

/// Regroupe les alertes en incidents (hôte + proximité temporelle).
pub fn correlate(alerts: &[Alert], window_secs: i64) -> Vec<Incident> {
    // Tri par hôte puis par temps : les alertes d'un même hôte se suivent.
    let mut sorted: Vec<&Alert> = alerts.iter().collect();
    sorted.sort_by(|a, b| a.host.cmp(&b.host).then(a.ts.cmp(&b.ts)));

    let mut incidents: Vec<Incident> = Vec::new();
    for a in sorted {
        // Incident ouvert le plus récent pour cet hôte, si la dernière alerte
        // est dans la fenêtre.
        let fit = incidents
            .iter_mut()
            .rev()
            .find(|inc| inc.host == a.host && (a.ts - inc.ended).num_seconds() <= window_secs);
        match fit {
            Some(inc) => {
                if a.ts > inc.ended {
                    inc.ended = a.ts;
                }
                inc.alerts.push(a.clone());
            }
            None => incidents.push(Incident {
                id: format!("INC-{}-{}", a.host, a.ts.format("%Y%m%d-%H%M%S")),
                host: a.host.clone(),
                started: a.ts,
                ended: a.ts,
                severity: Severity::Info,
                score: 0,
                alert_count: 0,
                techniques: Vec::new(),
                tactics: Vec::new(),
                alerts: vec![a.clone()],
            }),
        }
    }

    for inc in &mut incidents {
        finalize(inc);
    }
    // Le plus grave d'abord, puis le plus récent.
    incidents.sort_by(|x, y| y.score.cmp(&x.score).then(y.started.cmp(&x.started)));
    incidents
}

fn finalize(inc: &mut Incident) {
    inc.alert_count = inc.alerts.len();
    inc.severity = inc
        .alerts
        .iter()
        .map(|a| a.severity)
        .max()
        .unwrap_or(Severity::Info);
    inc.score = inc.alerts.iter().map(|a| a.score).sum();

    let techs: std::collections::BTreeSet<String> = inc
        .alerts
        .iter()
        .flat_map(|a| a.attack.iter().cloned())
        .collect();
    inc.techniques = techs.iter().cloned().collect();

    let mut tacs: Vec<&'static str> = techs
        .iter()
        .map(|t| tactic_of(t))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    tacs.sort_by_key(|t| crate::KILL_CHAIN.iter().position(|k| k == t).unwrap_or(usize::MAX));
    inc.tactics = tacs.into_iter().map(str::to_string).collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Engine, Event};

    fn alert_at(host: &str, secs_from_epoch: i64, attack: &str) -> Alert {
        let mut ev = Event::process_start(host, 1, 0, r"C:\x.exe", "");
        ev.ts = DateTime::from_timestamp(secs_from_epoch, 0).unwrap();
        Alert {
            ts: ev.ts,
            host: host.to_string(),
            rule_id: "SNT-T".into(),
            title: "t".into(),
            description: String::new(),
            severity: Severity::High,
            attack: vec![attack.to_string()],
            score: 70,
            event: ev,
            ancestors: vec![],
        }
    }

    #[test]
    fn attack_chain_is_one_incident() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let mut alerts = Vec::new();
        for ev in crate::scenario::attack_chain("h") {
            alerts.extend(eng.ingest(ev));
        }
        let inc = correlate(&alerts, DEFAULT_WINDOW_SECS);
        assert_eq!(inc.len(), 1, "une chaîne rapprochée = 1 incident, obtenu {}", inc.len());
        assert_eq!(inc[0].alert_count, alerts.len());
        assert!(inc[0].tactics.len() >= 3, "l'incident doit couvrir plusieurs tactiques");
    }

    #[test]
    fn time_gap_splits_incidents() {
        let a = alert_at("h", 1_000, "T1059");
        let b = alert_at("h", 1_000 + 10 * 60, "T1003"); // +10 min > fenêtre
        let inc = correlate(&[a, b], DEFAULT_WINDOW_SECS);
        assert_eq!(inc.len(), 2);
    }

    #[test]
    fn different_hosts_never_merge() {
        let a = alert_at("poste-a", 2_000, "T1059");
        let b = alert_at("poste-b", 2_001, "T1003"); // même instant, hôte différent
        let inc = correlate(&[a, b], DEFAULT_WINDOW_SECS);
        assert_eq!(inc.len(), 2);
    }

    #[test]
    fn same_window_same_host_merges() {
        let a = alert_at("h", 3_000, "T1059");
        let b = alert_at("h", 3_030, "T1003"); // +30 s < fenêtre
        let inc = correlate(&[a, b], DEFAULT_WINDOW_SECS);
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].alert_count, 2);
        assert_eq!(inc[0].techniques, vec!["T1003".to_string(), "T1059".to_string()]);
    }
}
