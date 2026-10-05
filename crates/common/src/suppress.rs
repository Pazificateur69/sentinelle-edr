use crate::event::Event;
use crate::rules::Cond;
use serde::{Deserialize, Serialize};

/// Entree d'allowlist : supprime les alertes dont l'evenement correspond, pour
/// reduire les faux positifs. `rule_id` = None supprime toutes les regles ;
/// sinon seulement cette regle. Les conditions (ET) doivent toutes matcher.
/// Une suppression sans condition ne supprime rien (garde-fou : pas de
/// "supprime tout" accidentel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub all: Vec<Cond>,
}

/// Charge une allowlist depuis un fichier JSON (tableau de `Suppression`).
pub fn load_file(path: &std::path::Path) -> anyhow::Result<Vec<Suppression>> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

impl Suppression {
    pub fn matches_alert(&self, rule_id: &str, ev: &Event) -> bool {
        if let Some(rid) = &self.rule_id {
            if rid != rule_id {
                return false;
            }
        }
        !self.all.is_empty() && self.all.iter().all(|c| c.matches(ev))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Op;

    #[test]
    fn empty_suppression_never_matches() {
        let s = Suppression {
            id: "x".into(),
            rule_id: None,
            all: vec![],
        };
        let ev = Event::process_start("h", 1, 2, r"C:\a.exe", "");
        assert!(!s.matches_alert("SNT-0001", &ev));
    }

    #[test]
    fn scoped_suppression_matches_only_its_rule() {
        let s = Suppression {
            id: "x".into(),
            rule_id: Some("SNT-0031".into()),
            all: vec![Cond {
                field: "CommandLine".into(),
                op: Op::Contains,
                values: vec!["maintenance".into()],
            }],
        };
        let ev = Event::process_start("h", 1, 2, r"C:\schtasks.exe", "")
            .with_cmdline("schtasks /create /tn maintenance");
        assert!(s.matches_alert("SNT-0031", &ev));
        assert!(!s.matches_alert("SNT-0001", &ev)); // autre regle : pas supprimee
    }
}
