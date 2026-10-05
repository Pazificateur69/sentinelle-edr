//! Cœur de Sentinelle : schema d'evenements, moteur de regles facon Sigma,
//! arbre de processus pour la correlation, et scoring de risque. Tout est pur
//! et multiplateforme : testable partout, y compris sur macOS.

pub mod event;
pub mod proctree;
pub mod risk;
pub mod rules;
pub mod scenario;
pub mod sigma;

pub use event::{Event, EventKind};
pub use rules::{Rule, Severity};

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Regles embarquees dans le binaire (pas d'IO au demarrage).
const BUILTIN_RULES_JSON: &str = include_str!("../rules.json");

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

/// Moteur de detection : regles + arbre de processus.
pub struct Engine {
    rules: Vec<Rule>,
    tree: proctree::ProcTree,
}

impl Engine {
    /// Charge les regles compilees dans le binaire.
    pub fn with_builtin_rules() -> anyhow::Result<Self> {
        let rules: Vec<Rule> = serde_json::from_str(BUILTIN_RULES_JSON)?;
        Ok(Self {
            rules,
            tree: proctree::ProcTree::new(),
        })
    }

    pub fn from_rules(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            tree: proctree::ProcTree::new(),
        }
    }

    /// Ajoute des regles (ex. importees de Sigma) au moteur.
    pub fn add_rules(&mut self, extra: Vec<Rule>) {
        self.rules.extend(extra);
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn tracked_processes(&self) -> usize {
        self.tree.len()
    }

    /// Ingere un evenement : met a jour l'arbre puis evalue les regles.
    /// Renvoie une alerte par regle declenchee.
    pub fn ingest(&mut self, mut ev: Event) -> Vec<Alert> {
        self.tree.observe(&mut ev);
        let ancestors = self.tree.ancestors(ev.pid);
        self.rules
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
            .collect()
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
}
