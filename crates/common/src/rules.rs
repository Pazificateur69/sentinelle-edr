use crate::event::{Event, EventKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Poids de base ajoute au score d'hote quand la regle se declenche.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 5,
            Severity::Low => 15,
            Severity::Medium => 40,
            Severity::High => 70,
            Severity::Critical => 100,
        }
    }
}

/// Operateur de comparaison d'un champ (sous-ensemble de la syntaxe Sigma).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
}

/// Une condition : un champ, un operateur, une liste de valeurs (OR entre elles).
/// Comparaison insensible a la casse (defaut Sigma), sauf regex qui gere sa casse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cond {
    pub field: String,
    pub op: Op,
    pub values: Vec<String>,
}

impl Cond {
    fn matches(&self, ev: &Event) -> bool {
        let Some(raw) = ev.field(&self.field) else {
            return false;
        };
        let hay = raw.to_ascii_lowercase();
        self.values.iter().any(|v| {
            let needle = v.to_ascii_lowercase();
            match self.op {
                Op::Equals => hay == needle,
                Op::Contains => hay.contains(&needle),
                Op::StartsWith => hay.starts_with(&needle),
                Op::EndsWith => hay.ends_with(&needle),
                // Regex : on compile a la volee ; une regex invalide ne matche pas.
                Op::Regex => regex::Regex::new(v).map(|re| re.is_match(&raw)).unwrap_or(false),
            }
        })
    }
}

/// Arbre booleen de conditions. Permet d'exprimer and/or/not (requis pour Sigma),
/// la ou `all` ne couvre qu'un ET plat. Les regles JSON maison utilisent `all` ;
/// les regles importees de Sigma remplissent `expr`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expr {
    Cond(Cond),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
}

impl Expr {
    pub fn eval(&self, ev: &Event) -> bool {
        match self {
            Expr::Cond(c) => c.matches(ev),
            Expr::And(v) => v.iter().all(|e| e.eval(ev)),
            Expr::Or(v) => v.iter().any(|e| e.eval(ev)),
            Expr::Not(e) => !e.eval(ev),
        }
    }
}

/// Raccourci filiation : parent -> enfant, en option par ascendance (tout ancetre).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lineage {
    pub parents: Vec<String>,
    pub children: Vec<String>,
    /// Si vrai, matche si l'un des `parents` est un ANCETRE (pas seulement le parent direct).
    #[serde(default)]
    pub ancestor: bool,
}

/// Regle de detection inspiree de Sigma.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    #[serde(default)]
    pub attack: Vec<String>,
    /// Filtre optionnel sur le type d'evenement.
    #[serde(default)]
    pub kind: Option<EventKind>,
    /// Conditions combinees en ET (regles JSON maison).
    #[serde(default)]
    pub all: Vec<Cond>,
    /// Arbre booleen (regles importees de Sigma).
    #[serde(default)]
    pub expr: Option<Expr>,
    /// Raccourci de filiation optionnel.
    #[serde(default)]
    pub lineage: Option<Lineage>,
}

impl Rule {
    /// La regle matche-t-elle ? `ancestors` = images des ancetres du processus
    /// (du parent direct vers la racine), fournies par l'arbre de processus.
    pub fn matches(&self, ev: &Event, ancestors: &[String]) -> bool {
        if let Some(k) = self.kind {
            if ev.kind != k {
                return false;
            }
        }
        if let Some(lin) = &self.lineage {
            if !lineage_matches(lin, ev, ancestors) {
                return false;
            }
        }
        // Conditions a plat (ET).
        if !self.all.iter().all(|c| c.matches(ev)) {
            return false;
        }
        // Arbre booleen Sigma, s'il existe.
        if let Some(expr) = &self.expr {
            if !expr.eval(ev) {
                return false;
            }
        }
        true
    }
}

fn lineage_matches(lin: &Lineage, ev: &Event, ancestors: &[String]) -> bool {
    let child = ev.image_name();
    let child_ok = lin
        .children
        .iter()
        .any(|c| c.eq_ignore_ascii_case(&child));
    if !child_ok {
        return false;
    }
    let parent_pool: Vec<String> = if lin.ancestor {
        ancestors
            .iter()
            .map(|a| crate::event::base_name(a))
            .collect()
    } else {
        vec![ev.parent_name()]
    };
    lin.parents
        .iter()
        .any(|p| parent_pool.iter().any(|x| x.eq_ignore_ascii_case(p)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    fn office() -> Event {
        Event::process_start("h", 100, 50, r"C:\Office\winword.exe", r"C:\Windows\explorer.exe")
    }

    #[test]
    fn contains_is_case_insensitive() {
        let c = Cond {
            field: "CommandLine".into(),
            op: Op::Contains,
            values: vec!["-enc".into()],
        };
        let ev = office().with_cmdline("powershell.exe -EncodedCommand ZQBj");
        assert!(c.matches(&ev));
    }

    #[test]
    fn endswith_matches_image() {
        let c = Cond {
            field: "Image".into(),
            op: Op::EndsWith,
            values: vec!["\\winword.exe".into()],
        };
        assert!(c.matches(&office()));
    }

    #[test]
    fn lineage_direct_vs_ancestor() {
        let lin = Lineage {
            parents: vec!["winword.exe".into()],
            children: vec!["powershell.exe".into()],
            ancestor: true,
        };
        // powershell dont l'ancetre (pas le parent direct) est winword
        let ev = Event::process_start("h", 200, 150, r"C:\W\powershell.exe", r"C:\W\cmd.exe");
        let ancestors = vec![r"C:\W\cmd.exe".into(), r"C:\Office\winword.exe".into()];
        assert!(lineage_matches(&lin, &ev, &ancestors));

        // sans ancestor=true, le parent direct est cmd.exe -> pas de match
        let direct = Lineage { ancestor: false, ..lin };
        assert!(!lineage_matches(&direct, &ev, &ancestors));
    }
}
