//! Importeur de regles Sigma (sous-ensemble pragmatique).
//!
//! Couvre le cas le plus courant des regles `process_creation` : blocs de
//! selection (map ou liste de maps), modificateurs `contains|startswith|endswith|re|all`,
//! et une condition booleenne (`and`/`or`/`not`, parentheses, `all of them`,
//! `1 of sel*`...). Les constructions non supportees (champ inconnu, modificateur
//! exotique) provoquent une erreur explicite : on prefere refuser une regle que
//! l'importer silencieusement morte.

use crate::event::EventKind;
use crate::rules::{Cond, Expr, Op, Rule, Severity};
use anyhow::{anyhow, bail, Context, Result};
use serde_yaml::Value;
use std::collections::BTreeMap;

/// Champs d'evenement connus (doivent exister dans `Event::field`).
const KNOWN_FIELDS: &[&str] = &[
    "Image",
    "ImageName",
    "ParentImage",
    "ParentImageName",
    "CommandLine",
    "User",
    "Sha256",
    "DestinationIp",
    "DestinationPort",
    "TargetFilename",
];

/// Charge toutes les regles Sigma (*.yml / *.yaml) d'un dossier.
/// Renvoie les regles importees et la liste des (fichier, erreur) ignores.
pub fn load_dir(dir: &std::path::Path) -> (Vec<Rule>, Vec<(String, String)>) {
    let mut rules = Vec::new();
    let mut errs = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (rules, errs);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "yml" || e == "yaml");
        if !is_yaml {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => match parse_sigma(&text) {
                Ok(r) => rules.push(r),
                Err(e) => errs.push((path.display().to_string(), format!("{e:#}"))),
            },
            Err(e) => errs.push((path.display().to_string(), e.to_string())),
        }
    }
    (rules, errs)
}

/// Parse une regle Sigma (YAML) en `Rule` interne.
pub fn parse_sigma(yaml: &str) -> Result<Rule> {
    let doc: Value = serde_yaml::from_str(yaml).context("YAML invalide")?;

    let title = doc
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("champ 'title' manquant"))?
        .to_string();
    let id = doc
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or(&title)
        .to_string();
    let description = doc
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let severity = severity_from_level(doc.get("level").and_then(Value::as_str));
    let attack = tags_to_attack(doc.get("tags"));
    let kind = kind_from_logsource(doc.get("logsource"));

    let detection = doc
        .get("detection")
        .and_then(Value::as_mapping)
        .ok_or_else(|| anyhow!("bloc 'detection' manquant"))?;

    // Separer la condition des blocs de selection.
    let condition = detection
        .get(Value::from("condition"))
        .ok_or_else(|| anyhow!("'detection.condition' manquant"))?;

    let mut selections: BTreeMap<String, Expr> = BTreeMap::new();
    for (k, v) in detection {
        let name = k.as_str().unwrap_or_default();
        if name == "condition" || name == "timeframe" {
            continue;
        }
        selections.insert(name.to_string(), parse_selection(name, v)?);
    }
    if selections.is_empty() {
        bail!("aucun bloc de selection");
    }

    let expr = parse_condition(condition, &selections)?;

    Ok(Rule {
        id,
        title,
        description,
        severity,
        attack,
        kind,
        all: vec![],
        expr: Some(expr),
        lineage: None,
    })
}

fn severity_from_level(level: Option<&str>) -> Severity {
    match level.unwrap_or("medium") {
        "informational" | "info" => Severity::Info,
        "low" => Severity::Low,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}

/// tags Sigma "attack.t1059.001" -> "T1059.001".
fn tags_to_attack(tags: Option<&Value>) -> Vec<String> {
    let Some(seq) = tags.and_then(Value::as_sequence) else {
        return vec![];
    };
    seq.iter()
        .filter_map(Value::as_str)
        .filter_map(|t| t.strip_prefix("attack."))
        .filter(|t| {
            let b = t.as_bytes();
            b.first() == Some(&b't') && b.get(1).is_some_and(|c| c.is_ascii_digit())
        })
        .map(|t| t.to_uppercase())
        .collect()
}

fn kind_from_logsource(ls: Option<&Value>) -> Option<EventKind> {
    match ls.and_then(|v| v.get("category")).and_then(Value::as_str) {
        Some("process_creation") => Some(EventKind::ProcessStart),
        Some("network_connection") => Some(EventKind::Network),
        Some("file_event") | Some("file_change") => Some(EventKind::FileWrite),
        Some("image_load") => Some(EventKind::ImageLoad),
        _ => None,
    }
}

/// Un bloc de selection : map (ET des cles) ou liste de maps (OU des maps).
fn parse_selection(name: &str, v: &Value) -> Result<Expr> {
    match v {
        Value::Mapping(_) => parse_map(v),
        Value::Sequence(seq) => {
            let mut ors = Vec::new();
            for item in seq {
                ors.push(parse_map(item).with_context(|| format!("selection '{name}'"))?);
            }
            Ok(Expr::Or(ors))
        }
        _ => bail!("selection '{name}' : format non supporte (ni map ni liste)"),
    }
}

/// Une map field|mod: value -> ET des conditions.
fn parse_map(v: &Value) -> Result<Expr> {
    let map = v
        .as_mapping()
        .ok_or_else(|| anyhow!("attendu une map de champs"))?;
    let mut ands = Vec::new();
    for (k, val) in map {
        let key = k.as_str().ok_or_else(|| anyhow!("cle non textuelle"))?;
        ands.push(parse_field(key, val)?);
    }
    Ok(Expr::And(ands))
}

/// "Field|mod1|mod2": value|list -> une (ou plusieurs) Cond.
fn parse_field(key: &str, val: &Value) -> Result<Expr> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default().to_string();
    if !KNOWN_FIELDS.contains(&field.as_str()) {
        bail!("champ non mappe : '{field}'");
    }
    let mods: Vec<&str> = parts.collect();

    let mut all_mode = false;
    let mut op = Op::Equals;
    for m in &mods {
        match *m {
            "contains" => op = Op::Contains,
            "startswith" => op = Op::StartsWith,
            "endswith" => op = Op::EndsWith,
            "re" => op = Op::Regex,
            "all" => all_mode = true,
            other => bail!("modificateur non supporte : '{other}' sur '{field}'"),
        }
    }

    let values = value_to_strings(val);
    if values.is_empty() {
        bail!("valeur vide pour '{field}'");
    }

    if all_mode {
        // chaque valeur doit matcher -> ET de Conds a valeur unique
        Ok(Expr::And(
            values
                .into_iter()
                .map(|v| {
                    Expr::Cond(Cond {
                        field: field.clone(),
                        op,
                        values: vec![v],
                    })
                })
                .collect(),
        ))
    } else {
        // OU entre les valeurs (comportement par defaut d'une Cond)
        Ok(Expr::Cond(Cond { field, op, values }))
    }
}

fn value_to_strings(val: &Value) -> Vec<String> {
    match val {
        Value::Sequence(seq) => seq.iter().filter_map(scalar_to_string).collect(),
        other => scalar_to_string(other).into_iter().collect(),
    }
}

fn scalar_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

// ---- Parsing de la condition booleenne ----

fn parse_condition(cond: &Value, selections: &BTreeMap<String, Expr>) -> Result<Expr> {
    // Une condition peut etre une liste (OU de conditions).
    if let Some(seq) = cond.as_sequence() {
        let mut ors = Vec::new();
        for c in seq {
            let s = c.as_str().ok_or_else(|| anyhow!("condition non textuelle"))?;
            ors.push(parse_condition_str(s, selections)?);
        }
        return Ok(Expr::Or(ors));
    }
    let s = cond
        .as_str()
        .ok_or_else(|| anyhow!("condition non textuelle"))?;
    parse_condition_str(s, selections)
}

fn tokenize(s: &str) -> Vec<String> {
    s.replace('(', " ( ")
        .replace(')', " ) ")
        .split_whitespace()
        .map(|t| t.to_string())
        .collect()
}

struct P<'a> {
    toks: Vec<String>,
    pos: usize,
    sels: &'a BTreeMap<String, Expr>,
}

fn parse_condition_str(s: &str, sels: &BTreeMap<String, Expr>) -> Result<Expr> {
    let mut p = P {
        toks: tokenize(s),
        pos: 0,
        sels,
    };
    let e = p.parse_or()?;
    if p.pos != p.toks.len() {
        bail!("condition : token inattendu '{}'", p.toks[p.pos]);
    }
    Ok(e)
}

impl P<'_> {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(|s| s.as_str())
    }
    fn advance(&mut self) -> Option<String> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut node = self.parse_and()?;
        while self.peek() == Some("or") {
            self.advance();
            node = Expr::Or(vec![node, self.parse_and()?]);
        }
        Ok(node)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut node = self.parse_not()?;
        while self.peek() == Some("and") {
            self.advance();
            node = Expr::And(vec![node, self.parse_not()?]);
        }
        Ok(node)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        if self.peek() == Some("not") {
            self.advance();
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.peek() {
            Some("(") => {
                self.advance();
                let e = self.parse_or()?;
                if self.advance().as_deref() != Some(")") {
                    bail!("parenthese fermante manquante");
                }
                Ok(e)
            }
            Some("all") | Some("any") | Some("1") => self.parse_quantifier(),
            Some(tok) => {
                let name = tok.to_string();
                self.advance();
                self.resolve(&name)
            }
            None => bail!("condition incomplete"),
        }
    }

    /// "all of them", "1 of them", "any of sel*", "all of sel*"...
    fn parse_quantifier(&mut self) -> Result<Expr> {
        let q = self.advance().unwrap(); // all | any | 1
        if self.advance().as_deref() != Some("of") {
            bail!("quantificateur : 'of' attendu apres '{q}'");
        }
        let target = self.advance().ok_or_else(|| anyhow!("cible de quantificateur manquante"))?;

        let names: Vec<String> = if target == "them" {
            self.sels.keys().cloned().collect()
        } else if let Some(prefix) = target.strip_suffix('*') {
            self.sels
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect()
        } else {
            vec![target.clone()]
        };
        if names.is_empty() {
            bail!("quantificateur : aucune selection ne correspond a '{target}'");
        }

        let exprs: Result<Vec<Expr>> = names.iter().map(|n| self.resolve(n)).collect();
        let exprs = exprs?;
        // "all" -> ET, "any"/"1" -> OU
        Ok(if q == "all" {
            Expr::And(exprs)
        } else {
            Expr::Or(exprs)
        })
    }

    fn resolve(&self, name: &str) -> Result<Expr> {
        self.sels
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("selection inconnue : '{name}'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    const RULE: &str = r#"
title: Encoded PowerShell
id: test-0001
description: PowerShell encode
level: high
tags:
  - attack.t1059.001
  - attack.t1027
  - car.2013-10-002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  filter:
    CommandLine|contains: 'Get-Help'
  condition: selection and not filter
"#;

    #[test]
    fn parses_and_matches() {
        let rule = parse_sigma(RULE).expect("doit parser");
        assert_eq!(rule.id, "test-0001");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.attack, vec!["T1059.001", "T1027"]); // car.* exclu
        assert_eq!(rule.kind, Some(EventKind::ProcessStart));

        // match : powershell -enc, pas de Get-Help
        let hit = Event::process_start("h", 1, 2, r"C:\W\powershell.exe", r"C:\W\x.exe")
            .with_cmdline("powershell.exe -enc ZQBj");
        assert!(rule.matches(&hit, &[]));

        // filtre actif -> pas d'alerte
        let filtered = Event::process_start("h", 1, 2, r"C:\W\powershell.exe", "")
            .with_cmdline("powershell.exe -enc ZQBj ; Get-Help");
        assert!(!rule.matches(&filtered, &[]));

        // pas d'encodage -> pas de match
        let benign = Event::process_start("h", 1, 2, r"C:\W\powershell.exe", "")
            .with_cmdline("powershell.exe -version");
        assert!(!rule.matches(&benign, &[]));
    }

    #[test]
    fn rejects_unknown_field() {
        let bad = r#"
title: x
detection:
  selection:
    IntegrityLevel: High
  condition: selection
"#;
        assert!(parse_sigma(bad).is_err());
    }

    #[test]
    fn quantifier_one_of() {
        let yaml = r#"
title: multi
level: medium
detection:
  sel_a:
    Image|endswith: '\cmd.exe'
  sel_b:
    Image|endswith: '\wscript.exe'
  condition: 1 of sel_*
"#;
        let rule = parse_sigma(yaml).unwrap();
        let cmd = Event::process_start("h", 1, 2, r"C:\W\cmd.exe", "");
        assert!(rule.matches(&cmd, &[]));
        let other = Event::process_start("h", 1, 2, r"C:\W\explorer.exe", "");
        assert!(!rule.matches(&other, &[]));
    }
}
