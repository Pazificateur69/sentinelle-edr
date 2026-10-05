//! Cœur de Sentinelle : schema d'evenements, moteur de regles facon Sigma,
//! arbre de processus pour la correlation, et scoring de risque. Tout est pur
//! et multiplateforme : testable partout, y compris sur macOS.

pub mod config;
pub mod event;
pub mod proctree;
pub mod risk;
pub mod rules;
pub mod scenario;
pub mod sigma;
pub mod suppress;

pub use config::Config;
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

/// Tactique MITRE ATT&CK d'une technique (sous-technique ignorée).
pub fn tactic_of(technique: &str) -> &'static str {
    let base = technique.split('.').next().unwrap_or(technique);
    match base {
        "T1189" | "T1566" => "Initial Access",
        "T1059" | "T1203" | "T1047" | "T1569" | "T1106" => "Execution",
        "T1547" | "T1053" | "T1543" | "T1136" | "T1546" | "T1197" => "Persistence",
        "T1548" | "T1068" | "T1134" => "Privilege Escalation",
        "T1218" | "T1027" | "T1562" | "T1070" | "T1140" | "T1211" | "T1112" | "T1055" | "T1036" => "Defense Evasion",
        "T1003" | "T1552" | "T1555" => "Credential Access",
        "T1087" | "T1082" | "T1016" | "T1049" | "T1018" | "T1482" | "T1033" | "T1007" => "Discovery",
        "T1021" => "Lateral Movement",
        "T1105" | "T1071" | "T1571" | "T1095" | "T1090" | "T1572" => "Command and Control",
        "T1048" | "T1567" => "Exfiltration",
        "T1486" | "T1490" => "Impact",
        _ => "Autre",
    }
}

/// Détecte un outil sensible renommé : le nom sur disque diffère du nom
/// d'origine (ressource de version du PE) et ce nom d'origine est celui d'un
/// binaire couramment abusé. Renvoie le nom d'origine en cas de masquerading.
///
/// On restreint volontairement aux binaires dont le renommage est quasi
/// toujours malveillant : renommer un `chrome.exe` est banal, renommer un
/// `powershell.exe` ou un `mimikatz.exe` ne l'est pas.
fn masqueraded_tool(ev: &Event) -> Option<String> {
    const SENSITIVE: &[&str] = &[
        "cmd", "powershell", "pwsh", "rundll32", "regsvr32", "mshta", "wscript",
        "cscript", "certutil", "bitsadmin", "wmic", "mimikatz", "psexec",
        "psexesvc", "net", "nltest", "ntdsutil", "vssadmin",
    ];
    if ev.original_file_name.is_empty() || ev.image.is_empty() {
        return None;
    }
    // base_name met déjà en minuscules ; on retire le `.exe` final pour comparer.
    let strip = |s: String| s.strip_suffix(".exe").map(str::to_string).unwrap_or(s);
    let on_disk = strip(event::base_name(&ev.image));
    let origin = strip(event::base_name(&ev.original_file_name));
    if on_disk != origin && SENSITIVE.contains(&origin.as_str()) {
        Some(ev.original_file_name.clone())
    } else {
        None
    }
}

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
    /// Chaîne d'ascendance (noms d'images, du parent vers la racine) pour le contexte.
    #[serde(default)]
    pub ancestors: Vec<String>,
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
    /// pid -> horodatages des ecritures recentes (chiffrement massif).
    file_writes: HashMap<u32, VecDeque<i64>>,
    config: Config,
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
            file_writes: HashMap::new(),
            config: Config::default(),
        }
    }

    /// Ajoute des regles (ex. importees de Sigma) au moteur.
    pub fn add_rules(&mut self, extra: Vec<Rule>) {
        self.rules.extend(extra);
    }

    /// Remplace les seuils du moteur (comportemental + deduplication).
    pub fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Ajoute des entrees d'allowlist (ex. chargees d'un fichier).
    pub fn add_suppressions(&mut self, extra: Vec<Suppression>) {
        self.allowlist.extend(extra);
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Techniques MITRE ATT&CK couvertes par le jeu de règles (triées, uniques).
    /// Donne la "surface de détection" du moteur.
    pub fn attack_coverage(&self) -> Vec<String> {
        self.rules
            .iter()
            .flat_map(|r| r.attack.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Nombre de règles par tactique ATT&CK (triée par tactique). Vue "kill chain"
    /// de la couverture, à la manière des évaluations MITRE ATT&CK.
    pub fn tactic_coverage(&self) -> Vec<(String, usize)> {
        let mut map: std::collections::BTreeMap<&'static str, usize> =
            std::collections::BTreeMap::new();
        for r in &self.rules {
            let mut seen: std::collections::BTreeSet<&'static str> = Default::default();
            for t in &r.attack {
                seen.insert(tactic_of(t));
            }
            for tac in seen {
                *map.entry(tac).or_insert(0) += 1;
            }
        }
        map.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
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
                score: r.score(),
                event: ev.clone(),
                ancestors: Vec::new(),
            })
            .collect();

        // Detections comportementales (a etats).
        match ev.kind {
            EventKind::ProcessStart => {
                if let Some(a) = self.detect_spawn_burst(&ev, now) {
                    alerts.push(a);
                }
                // Usurpation de parent : le créateur réel diffère du parent déclaré.
                if ev.real_ppid != 0 && ev.real_ppid != ev.ppid {
                    alerts.push(Alert {
                        ts: ev.ts,
                        host: ev.host.clone(),
                        rule_id: "SNT-B003".to_string(),
                        title: "Usurpation de parent (PPID spoofing)".to_string(),
                        description: format!(
                            "Parent déclaré pid {} mais créateur réel pid {} — parent falsifié",
                            ev.ppid, ev.real_ppid
                        ),
                        severity: Severity::High,
                        attack: vec!["T1134.004".to_string()],
                        score: Severity::High.weight(),
                        event: ev.clone(),
                        ancestors: Vec::new(),
                    });
                }
                // Masquerading : outil sensible renommé (le nom sur disque diffère
                // du nom d'origine inscrit dans la ressource de version du PE). T1036.003.
                if let Some(orig) = masqueraded_tool(&ev) {
                    alerts.push(Alert {
                        ts: ev.ts,
                        host: ev.host.clone(),
                        rule_id: "SNT-B004".to_string(),
                        title: "Outil système renommé (masquerading)".to_string(),
                        description: format!(
                            "'{}' tourne sous le nom '{}' mais embarque le nom d'origine '{}' — binaire renommé pour se dissimuler",
                            ev.image,
                            event::base_name(&ev.image),
                            orig
                        ),
                        severity: Severity::High,
                        attack: vec!["T1036.003".to_string()],
                        score: Severity::High.weight(),
                        event: ev.clone(),
                        ancestors: Vec::new(),
                    });
                }
            }
            EventKind::FileWrite => {
                if let Some(a) = self.detect_file_burst(&ev, now) {
                    alerts.push(a);
                }
            }
            _ => {}
        }

        // Contexte d'investigation : ascendance (noms) sur chaque alerte.
        if !ancestors.is_empty() {
            let names: Vec<String> = ancestors.iter().map(|a| event::base_name(a)).collect();
            for a in &mut alerts {
                a.ancestors = names.clone();
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
        let window = self.config.spawn_burst_window_secs;
        let threshold = self.config.spawn_burst_threshold;
        let dq = self.spawns.entry(ev.ppid).or_default();
        dq.push_back(now);
        while let Some(&front) = dq.front() {
            if now - front > window {
                dq.pop_front();
            } else {
                break;
            }
        }
        (dq.len() >= threshold).then(|| Alert {
            ts: ev.ts,
            host: ev.host.clone(),
            rule_id: "SNT-B001".to_string(),
            title: "Rafale de créations de processus".to_string(),
            description: format!(
                "{} processus créés par le même parent (pid {}) en moins de {}s — comportement anormal",
                dq.len(),
                ev.ppid,
                window
            ),
            severity: Severity::High,
            attack: vec!["T1059".to_string()],
            score: Severity::High.weight(),
            event: ev.clone(),
            ancestors: Vec::new(),
        })
    }

    fn detect_file_burst(&mut self, ev: &Event, now: i64) -> Option<Alert> {
        if ev.pid == 0 {
            return None;
        }
        let window = self.config.file_burst_window_secs;
        let threshold = self.config.file_burst_threshold;
        let dq = self.file_writes.entry(ev.pid).or_default();
        dq.push_back(now);
        while let Some(&front) = dq.front() {
            if now - front > window {
                dq.pop_front();
            } else {
                break;
            }
        }
        (dq.len() >= threshold).then(|| Alert {
            ts: ev.ts,
            host: ev.host.clone(),
            rule_id: "SNT-B002".to_string(),
            title: "Chiffrement massif de fichiers (rançongiciel)".to_string(),
            description: format!(
                "{} fichiers écrits par le processus pid {} en moins de {}s — comportement de rançongiciel",
                dq.len(),
                ev.pid,
                window
            ),
            severity: Severity::Critical,
            attack: vec!["T1486".to_string()],
            score: Severity::Critical.weight(),
            event: ev.clone(),
            ancestors: Vec::new(),
        })
    }

    fn is_duplicate(&mut self, a: &Alert, now: i64) -> bool {
        let key = (a.rule_id.clone(), a.host.clone(), a.event.pid);
        if let Some(&last) = self.recent.get(&key) {
            if now - last < self.config.dedup_window_secs {
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
    fn attack_coverage_is_broad() {
        let eng = Engine::with_builtin_rules().unwrap();
        let cov = eng.attack_coverage();
        // couverture large et triée/unique
        assert!(cov.len() >= 20, "couverture ATT&CK trop faible: {}", cov.len());
        assert!(cov.contains(&"T1003".to_string())); // credential dumping
        assert!(cov.contains(&"T1486".to_string())); // ransomware
        assert!(cov.windows(2).all(|w| w[0] < w[1])); // trié, sans doublon
    }

    #[test]
    fn tactic_coverage_spans_kill_chain() {
        let eng = Engine::with_builtin_rules().unwrap();
        let cov: std::collections::HashMap<String, usize> =
            eng.tactic_coverage().into_iter().collect();
        for tac in [
            "Execution",
            "Persistence",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Command and Control",
            "Exfiltration",
            "Impact",
            "Privilege Escalation",
        ] {
            assert!(cov.contains_key(tac), "tactique non couverte : {tac}");
        }
    }

    #[test]
    fn full_attack_chain_triggers_key_detections() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let mut fired = std::collections::HashSet::new();
        for ev in crate::scenario::attack_chain("h") {
            for a in eng.ingest(ev) {
                fired.insert(a.rule_id);
            }
        }
        // Bout en bout : la chaîne simulée doit couvrir toute la kill chain.
        for rid in [
            "SNT-0001", // macro Office -> interpréteur
            "SNT-0010", // PowerShell encodé
            "SNT-0011", // download cradle
            "SNT-0021", // dump LSASS
            "SNT-0020", // mimikatz
            "SNT-0100", // C2
            "SNT-0200", // BYOVD
            "SNT-0300", // accès LSASS par handle
            "SNT-0310", // injection par thread distant
            "SNT-0320", // tube nommé C2
            "SNT-B003", // usurpation de parent
            "SNT-0101", // note de rançon
            "SNT-B002", // chiffrement massif
            "SNT-0050", // suppression shadow copies
            "SNT-0051", // sabotage bcdedit
        ] {
            assert!(fired.contains(rid), "détection manquante dans la chaîne : {rid}");
        }
    }

    #[test]
    fn masquerade_renamed_tool_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        // powershell.exe renommé en svchost.exe pour se fondre dans la masse,
        // mais la ressource de version du PE trahit l'origine.
        let alerts = eng.ingest(
            Event::process_start("h", 10, 1, r"C:\Users\pub\svchost.exe", "")
                .with_original_file_name("PowerShell.EXE"),
        );
        assert!(
            alerts.iter().any(|a| a.rule_id == "SNT-B004"),
            "un binaire sensible renommé doit lever SNT-B004, alertes={:?}",
            alerts.iter().map(|a| &a.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn masquerade_no_false_positive() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        // Vrai powershell.exe : nom disque == nom d'origine (casse ignorée) -> rien.
        let a1 = eng.ingest(
            Event::process_start("h", 11, 1, r"C:\Windows\System32\powershell.exe", "")
                .with_original_file_name("PowerShell.EXE"),
        );
        assert!(!a1.iter().any(|a| a.rule_id == "SNT-B004"));
        // Binaire non sensible renommé (updater) -> pas de bruit.
        let a2 = eng.ingest(
            Event::process_start("h", 12, 1, r"C:\App\launcher.exe", "")
                .with_original_file_name("MyApp.exe"),
        );
        assert!(!a2.iter().any(|a| a.rule_id == "SNT-B004"));
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
    fn alert_carries_ancestry() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        eng.ingest(Event::process_start("h", 1, 0, r"C:\W\explorer.exe", ""));
        eng.ingest(Event::process_start("h", 2, 1, r"C:\Office\winword.exe", ""));
        let alerts = eng.ingest(
            Event::process_start("h", 3, 2, r"C:\W\powershell.exe", "").with_cmdline("powershell -enc X"),
        );
        let a = alerts.iter().find(|a| a.rule_id == "SNT-0001").unwrap();
        assert!(a.ancestors.iter().any(|x| x == "winword.exe"));
        assert!(a.ancestors.iter().any(|x| x == "explorer.exe"));
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
    fn confidence_scales_the_score() {
        use crate::rules::{Cond, Op, Rule};
        let rule = Rule {
            id: "C1".into(),
            title: "test".into(),
            description: String::new(),
            severity: Severity::High, // poids 70
            attack: vec![],
            kind: None,
            all: vec![Cond {
                field: "ImageName".into(),
                op: Op::Equals,
                values: vec!["evil.exe".into()],
            }],
            expr: None,
            lineage: None,
            confidence: 0.5,
        };
        let mut eng = Engine::from_rules(vec![rule]);
        let alerts = eng.ingest(Event::process_start("h", 1, 2, r"C:\x\evil.exe", ""));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].score, 35); // 70 * 0.5
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
    fn byovd_driver_load_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts = eng.ingest(Event::image_load(
            "h",
            4500,
            r"C:\temp\m.exe",
            r"C:\temp\RTCore64.sys",
        ));
        assert!(alerts.iter().any(|a| a.rule_id == "SNT-0200"));
    }

    #[test]
    fn ppid_spoofing_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts = eng.ingest(
            Event::process_start("h", 500, 4, r"C:\t\evil.exe", "").with_real_ppid(999),
        );
        assert!(alerts.iter().any(|a| a.rule_id == "SNT-B003"));
    }

    #[test]
    fn matching_ppid_no_spoof() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts =
            eng.ingest(Event::process_start("h", 501, 7, r"C:\t\x.exe", "").with_real_ppid(7));
        assert!(!alerts.iter().any(|a| a.rule_id == "SNT-B003"));
    }

    #[test]
    fn lsass_handle_access_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts = eng.ingest(Event::process_access(
            "h",
            50,
            r"C:\t\m.exe",
            r"C:\Windows\System32\lsass.exe",
            "0x1410",
        ));
        assert!(alerts.iter().any(|a| a.rule_id == "SNT-0300"));
    }

    #[test]
    fn remote_thread_injection_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts =
            eng.ingest(Event::remote_thread("h", 50, r"C:\W\powershell.exe", r"C:\W\explorer.exe"));
        assert!(alerts.iter().any(|a| a.rule_id == "SNT-0310"));
    }

    #[test]
    fn c2_named_pipe_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts =
            eng.ingest(Event::named_pipe("h", 50, r"C:\W\powershell.exe", r"\\.\pipe\msagent_7f"));
        assert!(alerts.iter().any(|a| a.rule_id == "SNT-0320"));
    }

    #[test]
    fn network_c2_port_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts = eng.ingest(Event::network(
            "h",
            4300,
            r"C:\W\powershell.exe",
            "185.12.0.9",
            4444,
        ));
        assert!(alerts.iter().any(|a| a.rule_id == "SNT-0100"));
    }

    #[test]
    fn ransom_note_file_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let alerts = eng.ingest(Event::file_write(
            "h",
            4900,
            r"C:\temp\locker.exe",
            r"C:\Users\x\READ_ME_TO_DECRYPT.txt",
        ));
        assert!(alerts.iter().any(|a| a.rule_id == "SNT-0101"));
    }

    #[test]
    fn mass_file_write_burst_fires() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let mut got = false;
        for i in 0..20u32 {
            let alerts = eng.ingest(Event::file_write(
                "h",
                4900,
                r"C:\temp\locker.exe",
                &format!(r"C:\d\f{i}.dat"), // sans extension de rançon : teste le seul comportement
            ));
            if alerts.iter().any(|a| a.rule_id == "SNT-B002") {
                got = true;
            }
        }
        assert!(got, "20 écritures du même pid doivent lever SNT-B002");
    }

    #[test]
    fn config_lowers_spawn_burst_threshold() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        eng.set_config(Config {
            spawn_burst_threshold: 3,
            ..Config::default()
        });
        let mut fired = false;
        for i in 0..3u32 {
            let alerts =
                eng.ingest(Event::process_start("h", 200 + i, 9, r"C:\t\x.exe", r"C:\t\p.exe"));
            if alerts.iter().any(|a| a.rule_id == "SNT-B001") {
                fired = true;
            }
        }
        assert!(fired, "seuil abaissé à 3 → rafale après 3 créations");
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
