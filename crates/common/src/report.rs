//! Génération d'un rapport d'incident lisible (Markdown) à partir des alertes.
//!
//! Fonction pure (aucune I/O) -> testable localement sans rien compiler de lourd.
//! La console la sert en téléchargement (`GET /api/report`). Le Markdown se lit
//! tel quel, s'affiche sur GitHub et se convertit en PDF d'un clic (impression
//! navigateur ou pandoc) — pas de dépendance de rendu embarquée.

use crate::incident;
use crate::{tactic_of, Alert, Severity, KILL_CHAIN};
use chrono::{DateTime, Utc};

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "Info",
        Severity::Low => "Faible",
        Severity::Medium => "Moyenne",
        Severity::High => "Élevée",
        Severity::Critical => "Critique",
    }
}

/// Action de confinement rattachée à une tactique observée (concrète, pas de blabla).
fn reco_for(tactic: &str) -> Option<&'static str> {
    Some(match tactic {
        "Impact" => "Isoler le poste du réseau immédiatement ; vérifier l'intégrité des sauvegardes avant toute restauration.",
        "Credential Access" => "Réinitialiser les identifiants des comptes utilisés sur ce poste et révoquer les sessions / tickets Kerberos.",
        "Command and Control" => "Bloquer au pare-feu les IP/domaines de C2 observés et isoler le poste.",
        "Persistence" => "Rechercher et retirer les mécanismes de persistance (tâches planifiées, clés Run, services, IFEO).",
        "Lateral Movement" => "Vérifier les postes adjacents et les comptes à privilèges potentiellement compromis.",
        "Defense Evasion" => "Contrôler l'état de l'antivirus/EDR et des journaux ; réactiver toute protection désactivée.",
        _ => return None,
    })
}

/// Rapport d'incident Markdown : synthèse, couverture ATT&CK en kill chain,
/// chronologie, détail par alerte, actions recommandées.
///
/// `generated` est passé en paramètre (et non lu de l'horloge) pour garder la
/// fonction pure et déterministe en test.
pub fn incident_markdown(host: &str, generated: DateTime<Utc>, alerts: &[Alert]) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Rapport d'incident — {host}\n\n"));
    out.push_str(&format!(
        "*Généré le {} par Sentinelle EDR.*\n\n",
        generated.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    if alerts.is_empty() {
        out.push_str("Aucune alerte sur la période. Rien à signaler.\n");
        return out;
    }

    // --- Synthèse ---
    let total = alerts.len();
    let first = alerts.iter().map(|a| a.ts).min().unwrap();
    let last = alerts.iter().map(|a| a.ts).max().unwrap();
    let worst = alerts.iter().max_by_key(|a| a.severity.weight()).unwrap();

    out.push_str("## Synthèse\n\n");
    out.push_str(&format!("- **Alertes** : {total}\n"));
    out.push_str(&format!(
        "- **Fenêtre** : {} → {}\n",
        first.format("%Y-%m-%d %H:%M:%S"),
        last.format("%Y-%m-%d %H:%M:%S")
    ));
    out.push_str(&format!(
        "- **Sévérité maximale** : {} ({})\n",
        sev_label(worst.severity),
        worst.rule_id
    ));

    // Répartition par sévérité (de la plus grave à la plus faible).
    out.push_str("- **Répartition** : ");
    let parts: Vec<String> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .iter()
    .filter_map(|&s| {
        let n = alerts.iter().filter(|a| a.severity == s).count();
        (n > 0).then(|| format!("{} {}", n, sev_label(s)))
    })
    .collect();
    out.push_str(&parts.join(" · "));
    out.push_str("\n\n");

    // --- Incidents corrélés (regroupement des alertes d'une même séquence) ---
    let incidents = incident::correlate(alerts, incident::DEFAULT_WINDOW_SECS);
    out.push_str(&format!("## Incidents corrélés ({})\n\n", incidents.len()));
    for inc in &incidents {
        out.push_str(&format!(
            "### {} — {} ({} alerte{})\n\n",
            inc.id,
            sev_label(inc.severity),
            inc.alert_count,
            if inc.alert_count > 1 { "s" } else { "" }
        ));
        out.push_str(&format!(
            "- **Fenêtre** : {} → {}\n",
            inc.started.format("%Y-%m-%d %H:%M:%S"),
            inc.ended.format("%H:%M:%S")
        ));
        if !inc.tactics.is_empty() {
            out.push_str(&format!(
                "- **Progression** : {}\n",
                inc.tactics.join(" → ")
            ));
        }
        if !inc.techniques.is_empty() {
            out.push_str(&format!(
                "- **Techniques** : {}\n",
                inc.techniques.join(", ")
            ));
        }
        out.push('\n');
    }

    // --- Couverture ATT&CK, en progression kill chain ---
    let mut techs: std::collections::BTreeSet<&str> = Default::default();
    for a in alerts {
        for t in &a.attack {
            techs.insert(t.as_str());
        }
    }
    // Regroupe les techniques par tactique.
    let mut by_tactic: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    for t in &techs {
        by_tactic.entry(tactic_of(t)).or_default().push(t);
    }
    out.push_str("## Techniques ATT&CK observées\n\n");
    for tac in KILL_CHAIN {
        if let Some(ts) = by_tactic.get(tac) {
            out.push_str(&format!("- **{tac}** : {}\n", ts.join(", ")));
        }
    }
    // Tactiques hors kill chain standard ("Autre"), s'il y en a.
    if let Some(ts) = by_tactic.get("Autre") {
        out.push_str(&format!("- **Autre** : {}\n", ts.join(", ")));
    }
    out.push('\n');

    // --- Chronologie ---
    let mut ordered: Vec<&Alert> = alerts.iter().collect();
    ordered.sort_by_key(|a| a.ts);
    out.push_str("## Chronologie\n\n");
    out.push_str("| Heure | Sévérité | Règle | Processus (PID) | ATT&CK |\n");
    out.push_str("|---|---|---|---|---|\n");
    for a in &ordered {
        out.push_str(&format!(
            "| {} | {} | {} — {} | {} ({}) | {} |\n",
            a.ts.format("%H:%M:%S"),
            sev_label(a.severity),
            a.rule_id,
            a.title,
            crate::event::base_name(&a.event.image),
            a.event.pid,
            a.attack.join(", "),
        ));
    }
    out.push('\n');

    // --- Détail par alerte (la plus grave d'abord : on lit l'essentiel en haut) ---
    let mut by_sev: Vec<&Alert> = alerts.iter().collect();
    by_sev.sort_by(|a, b| b.score.cmp(&a.score).then(a.ts.cmp(&b.ts)));
    out.push_str("## Détail des alertes\n\n");
    for a in &by_sev {
        out.push_str(&format!("### {} — {}\n\n", a.rule_id, a.title));
        out.push_str(&format!(
            "- **Sévérité** : {} (score {})\n",
            sev_label(a.severity),
            a.score
        ));
        out.push_str(&format!(
            "- **Horodatage** : {}\n",
            a.ts.format("%Y-%m-%d %H:%M:%S")
        ));
        if !a.attack.is_empty() {
            out.push_str(&format!("- **ATT&CK** : {}\n", a.attack.join(", ")));
        }
        out.push_str(&format!(
            "- **Processus** : `{}` (PID {})\n",
            a.event.image, a.event.pid
        ));
        if !a.ancestors.is_empty() {
            out.push_str(&format!("- **Ascendance** : {}\n", a.ancestors.join(" → ")));
        }
        if !a.description.is_empty() {
            out.push_str(&format!("- **Description** : {}\n", a.description));
        }
        if !a.event.command_line.is_empty() {
            // Bloc code : les pipes et guillemets de la ligne de commande n'y cassent rien.
            out.push_str(&format!("\n```\n{}\n```\n", a.event.command_line));
        }
        out.push('\n');
    }

    // --- Actions recommandées (uniquement pour les tactiques réellement observées) ---
    out.push_str("## Actions recommandées\n\n");
    out.push_str("- Collecter la mémoire et les artefacts du/des processus incriminés **avant** de terminer les processus.\n");
    let mut tactics_seen: Vec<&str> = by_tactic.keys().copied().collect();
    tactics_seen.sort_by_key(|t| KILL_CHAIN.iter().position(|k| k == t).unwrap_or(usize::MAX));
    for tac in tactics_seen {
        if let Some(reco) = reco_for(tac) {
            out.push_str(&format!("- {reco}\n"));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Engine, Event};

    /// Rejoue la chaîne d'attaque simulée, génère le rapport, et vérifie qu'il
    /// contient bien la synthèse, la kill chain et le détail.
    #[test]
    fn report_covers_the_attack_chain() {
        let mut eng = Engine::with_builtin_rules().unwrap();
        let mut alerts = Vec::new();
        for ev in crate::scenario::attack_chain("poste-x") {
            alerts.extend(eng.ingest(ev));
        }
        assert!(!alerts.is_empty(), "la chaîne doit produire des alertes");

        let gen = DateTime::parse_from_rfc3339("2026-10-05T21:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let md = incident_markdown("poste-x", gen, &alerts);

        assert!(md.contains("# Rapport d'incident — poste-x"));
        assert!(md.contains("## Synthèse"));
        assert!(md.contains("## Techniques ATT&CK observées"));
        assert!(md.contains("## Chronologie"));
        assert!(md.contains("## Détail des alertes"));
        assert!(md.contains("## Actions recommandées"));
        // La chaîne atteint l'Impact (ransomware) -> la reco d'isolation doit apparaître.
        assert!(md.contains("Isoler le poste"));
        // Au moins une technique de la kill chain doit être listée.
        assert!(md.contains("Credential Access"));
    }

    #[test]
    fn report_empty_is_clean() {
        let gen = Utc::now();
        let md = incident_markdown("vide", gen, &[]);
        assert!(md.contains("Aucune alerte"));
        assert!(!md.contains("## Chronologie"));
    }

    #[test]
    fn command_line_pipes_do_not_break_output() {
        let ev = Event::process_start("h", 9, 1, r"C:\W\powershell.exe", "")
            .with_cmdline("powershell -enc AAAA | findstr x");
        let alert = Alert {
            ts: Utc::now(),
            host: "h".into(),
            rule_id: "SNT-TEST".into(),
            title: "Test".into(),
            description: "desc".into(),
            severity: Severity::High,
            attack: vec!["T1059".into()],
            score: 70,
            event: ev,
            ancestors: vec![],
        };
        let md = incident_markdown("h", Utc::now(), &[alert]);
        // La ligne de commande est dans un bloc code, pas dans la table.
        assert!(md.contains("```\npowershell -enc AAAA | findstr x\n```"));
    }
}
