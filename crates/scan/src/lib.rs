//! Moteur de scan YARA (via YARA-X, réimplémentation Rust de VirusTotal).
//! Charge des règles `.yar`/`.yara` et cherche des signatures dans des octets ou
//! des fichiers. Capacité cœur d'un EDR : détecter du code malveillant connu.
//!
//! NON COMPILÉ depuis macOS (dépendance lourde) : validé par la CI.

use anyhow::Result;
use sentinelle_common::{Alert, Event, EventKind, Severity};
use std::path::Path;
use yara_x::{Compiler, Rules, Scanner};

/// Taille maximale d'image scannée par défaut (32 Mio).
pub const DEFAULT_MAX_BYTES: usize = 32 * 1024 * 1024;

pub struct YaraScanner {
    rules: Rules,
}

impl YaraScanner {
    /// Compile toutes les règles d'un dossier. `None` si aucune règle valide.
    pub fn from_dir(dir: &Path) -> Result<Option<Self>> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Ok(None);
        };
        let mut compiler = Compiler::new();
        let mut loaded = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let is_yara = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yar" || e == "yara");
            if !is_yara {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(src) => match compiler.add_source(src.as_str()) {
                    Ok(_) => loaded += 1,
                    Err(e) => tracing::warn!("règle YARA ignorée {} : {e}", path.display()),
                },
                Err(e) => tracing::warn!("lecture YARA {} : {e}", path.display()),
            }
        }
        if loaded == 0 {
            return Ok(None);
        }
        Ok(Some(Self {
            rules: compiler.build(),
        }))
    }

    /// Compile une source YARA unique (tests, règles embarquées).
    pub fn from_source(src: &str) -> Result<Self> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(src)
            .map_err(|e| anyhow::anyhow!("compilation YARA : {e}"))?;
        Ok(Self {
            rules: compiler.build(),
        })
    }

    /// Identifiants des règles qui correspondent aux octets.
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<String> {
        let mut scanner = Scanner::new(&self.rules);
        match scanner.scan(data) {
            Ok(results) => results
                .matching_rules()
                .map(|r| r.identifier().to_string())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Scanne un fichier (ignoré s'il dépasse `max_bytes` ou est illisible).
    pub fn scan_file(&self, path: &Path, max_bytes: usize) -> Vec<String> {
        match std::fs::read(path) {
            Ok(data) if data.len() <= max_bytes => self.scan_bytes(&data),
            _ => Vec::new(),
        }
    }
}

/// Scanne l'image d'un nouvel événement processus et produit une alerte par
/// règle YARA correspondante. Opération bloquante (lecture disque + scan) :
/// à appeler dans `spawn_blocking`.
pub fn scan_image_alerts(scanner: &YaraScanner, ev: &Event, max_bytes: usize) -> Vec<Alert> {
    if ev.kind != EventKind::ProcessStart || ev.image.is_empty() {
        return Vec::new();
    }
    scanner
        .scan_file(Path::new(&ev.image), max_bytes)
        .into_iter()
        .map(|name| Alert {
            ts: ev.ts,
            host: ev.host.clone(),
            rule_id: format!("YARA:{name}"),
            title: format!("Signature YARA : {name}"),
            description: format!(
                "L'image {} correspond à la règle YARA « {name} ».",
                ev.image
            ),
            severity: Severity::High,
            attack: vec!["T1204".to_string()],
            score: Severity::High.weight(),
            event: ev.clone(),
            ancestors: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_simple_rule() {
        let s = YaraScanner::from_source(
            r#"rule evil_marker { strings: $a = "EVILCODE" condition: $a }"#,
        )
        .unwrap();
        assert_eq!(
            s.scan_bytes(b"xx EVILCODE yy"),
            vec!["evil_marker".to_string()]
        );
        assert!(s.scan_bytes(b"fichier sain").is_empty());
    }

    #[test]
    fn scans_a_file() {
        let s = YaraScanner::from_source(
            r#"rule mz_payload { strings: $a = "PAYLOAD42" condition: $a }"#,
        )
        .unwrap();
        let dir = std::env::temp_dir().join("sentinelle_yara_test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("sample.bin");
        std::fs::write(&f, b"header PAYLOAD42 trailer").unwrap();
        assert_eq!(s.scan_file(&f, 1024), vec!["mz_payload".to_string()]);
        // trop gros -> ignoré
        assert!(s.scan_file(&f, 4).is_empty());
    }
}
