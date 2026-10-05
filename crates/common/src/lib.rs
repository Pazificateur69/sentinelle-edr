//! Cœur de Sentinelle : schema d'evenements, moteur de regles facon Sigma,
//! arbre de processus pour la correlation, et scoring de risque. Tout est pur
//! et multiplateforme : testable partout, y compris sur macOS.

pub mod event;
pub mod proctree;
pub mod risk;
pub mod rules;
pub mod scenario;
pub mod sigma;
pub mod suppress;

pub use event::{Event, EventKind};
pub use rules::{Rule, Severity};
pub use suppress::Suppression;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Regles embarquees dans le binaire (pas d'IO au demarrage).
const BUILTIN_RULES_JSON: &str = include_str!("../rules.json");
/// Allowlist embarquee (reduction des faux positifs).
const BUILTIN_ALLOWLIST_JSON: &str = include_str!("../allowlist.json");

/// Fenetre de deduplication : une meme (regle, hote, pid) n'alerte qu'une fois.
const DEDUP_WINDOW_SECS: i64 = 60;
/// Detection de rafale : seuil de processus crees par un meme parent...
const BURST_THRESHOLD: usize = 8;
/// ...dans cette fenetre glissante.
const BURST_WINDOW_SECS: i64 = 10;

/// Une detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub ts: chrono::DateTime<Utc>,
    pub host: String,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub attack: Vec<String>,
    pub score: u32,
    pub event: Event,
}

/// Moteur de detection : regles + arbre de processus + allowlist + etat
/// comportemental (dedup, detection de rafale).
pub struct Engine {
    rules: Vec<Rule>,
    tree: proctree::ProcTree,
    allowlist: Vec<Suppression>,
    /// (regle, hote, pid) -> dernier horodatage d'alerte (deduplication).
    recent: HashMap<(String, String, u32), i64>,
    /// ppid -> horodatages des creations recentes (detection de rafale).
    spawns: HashMap<u32, VecDeque<i64>>,
}

impl Engine {
    /// Charge les regles + l'allowlist compilees dans le binaire.
    pub fn with_builtin_rules() -> anyhow::Result<Self> {
        let rules: Vec<Rule> = serde_json::from_str(BUILTIN_RULES_JSON)?;
        let allowlist: Vec<Suppression> = serde_json::from_str(BUILTIN_ALLOWLIST_JSON)?;
        Ok(Self::new(rules, allowlist))
    }

    pub fn from_rules(rules: Vec<Rule>) -> Self {
        Self::new(rules, Vec::new())
    }

    fn new(rules: Vec<Rule>, allowlist: Vec<Suppression>) -> Self {
        Self {
            rules,
            tree: proctree::ProcTree::new(),
            allowlist,
            recent: HashMap::new(),
            spawns: HashMap::new(),
        }
    }

    /// Ajoute des regles (ex. importees de Sigma) au moteur.
    pub fn add_rules(&mut self, extra: Vec<Rule>) {
        self.rules.extend(extra);
    }

    /// Ajoute des entrees d'allowlist (ex. chargees d'un fichier).
    pub fn add_suppressions(&mut self, extra: Vec<Suppression>) {
        self.allowlist.extend(extra);
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn tracked_processes(&self) -> usize {
        self.tree.len()
    }

    /// Ingere un evenement : arbre -> regles -> comportemental -> allowlist -> dedup.
    pub fn ingest(&mut self, mut ev: Event) -> Vec<Alert> {
        self.tree.observe(&mut ev);
        let ancestors = self.tree.ancestors(ev.pid);
        let now = ev.ts.timestamp();

        let mut alerts: Vec<Alert> = self
            .rules
            .iter()
            .filter(|r| r.matches(&ev, &ancestors))
            .map(|r| Alert {
                ts: ev.ts,
                host: ev.host.clone(),
                rule_id: r.id.clone(),
                title: r.title.clone(),
                description: r.description.clone(),
                severity: r.severity,
                attack: r.attack.clone(),
                score: r.severity.weight(),
                event: ev.clone(),
            })
            .collect();

        // Detection comportementale : rafale de creations de processus.
        if ev.kind == EventKind::ProcessStart {
            if let Some(a) = self.detect_spawn_burst(&ev, now) {
                alerts.push(a);
            }
        }

        // Allowlist (faux positifs) puis deduplication.
        let ev_ref = &ev;
        alerts.retain(|a| !self.allowlist.iter().any(|s| s.matches_alert(&a.rule_id, ev_ref)));
        let mut kept = Vec::with_capacity(alerts.len());
        for a in alerts {
            if !self.is_duplicate(&a, now) {
                kept.push(a);
            }
        }
        kept
    }

    fn detect_spawn_burst(&mut self, ev: &Event, now: i64) -> Option<Alert> {
        if ev.ppid == 0 {
            return None;
        }
        let dq = self.spawns.entry(ev.ppid).or_default();
        dq.push_back(now);
        while let Some(&front) = dq.front() {
            if now - front > BURST_WINDOW_SECS {
                dq.pop_front();
            } else {
                break;
            }
        }
        (dq.len() >= BURST_THRESHOLD).then(|| Alert {
            ts: ev.ts,
            host: ev.host.clone(),
            rule_id: "SNT-B001".to_string(),
            title: "Rafale de créations de processus".to_string(),
            description: format!(
                "{} processus créés par le même parent (pid {}) en moins de {}s — comportement anormal",
                dq.len(),
                ev.ppid,
                BURST_WINDOW_SECS
            ),
            severity: Severity::High,
            attack: vec!["T1059".to_string()],
            score: Severity::High.weight(),
            event: ev.clone(),
        })
    }

    fn is_duplicate(&mut self, a: &Alert, now: i64) -> bool {
        let key = (a.rule_id.clone(), a.host.clone(), a.event.pid);
        if let Some(&last) = self.recent.get(&key) {
            if now - last < DEDUP_WINDOW_SECS {
                return true;
            }
        }
        self.recent.insert(key, now);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_parse() {
        let eng = Engine::with_builtin_rules().expect("rules.json doit parser");
        assert!(eng.rule_count() >= 10, "au moins 10 regles de depart");
    }

    #[test]
    fn office_macro_chain_fires_critical() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        // explorer -> winword -> powershell
        eng.ingest(Event::process_start("h", 1, 0, r"C:\Windows\explorer.exe", ""));
        eng.ingest(Event::process_start("h", 2, 1, r"C:\Office\winword.exe", ""));
        let alerts = eng.ingest(
            Event::process_start("h", 3, 2, r"C:\W\powershell.exe", "")
                .with_cmdline("powershell -nop -w hidden -enc ZQBj"),
        );
        assert!(
            alerts.iter().any(|a| a.rule_id == "SNT-0001"),
            "la chaine macro Office doit se declencher, alertes={:?}",
            alerts.iter().map(|a| &a.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn encoded_powershell_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts = eng.ingest(
            Event::process_start("h", 5, 1, r"C:\W\powershell.exe", r"C:\W\explorer.exe")
                .with_cmdline("powershell.exe -EncodedCommand MABtAGEA"),
        );
        assert!(alerts.iter().any(|a| a.rule_id == "SNT-0010"));
    }

    #[test]
    fn allowlist_suppresses_matching_alert() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts = eng.ingest(
            Event::process_start("h", 9, 1, r"C:\Windows\System32\schtasks.exe", r"C:\W\explorer.exe")
                .with_cmdline(r"schtasks /create /tn \sentinelle\maintenance\job"),
        );
        // SNT-0031 matcherait, mais ALLOW-0001 le supprime.
        assert!(!alerts.iter().any(|a| a.rule_id == "SNT-0031"));
    }

    #[test]
    fn duplicate_alert_is_deduplicated() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let ev = Event::process_start("h", 50, 1, r"C:\W\powershell.exe", r"C:\W\explorer.exe")
            .with_cmdline("powershell.exe -enc AAAA");
        let first = eng.ingest(ev.clone());
        let second = eng.ingest(ev);
        assert!(first.iter().any(|a| a.rule_id == "SNT-0010"));
        assert!(!second.iter().any(|a| a.rule_id == "SNT-0010")); // meme (regle,hote,pid)
    }

    #[test]
    fn process_spawn_burst_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let mut got_burst = false;
        for i in 0..8u32 {
            let alerts = eng.ingest(Event::process_start(
                "h",
                100 + i,
                7,
                r"C:\tmp\x.exe",
                r"C:\tmp\parent.exe",
            ));
            if alerts.iter().any(|a| a.rule_id == "SNT-B001") {
                got_burst = true;
            }
        }
        assert!(got_burst, "une rafale de 8 processus doit lever SNT-B001");
    }
}
