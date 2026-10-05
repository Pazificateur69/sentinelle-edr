use serde::Deserialize;

/// Seuils réglables du moteur (comportemental + déduplication). Chargeable depuis
/// un fichier TOML via `SENTINELLE_CONFIG`. Les champs absents prennent le défaut.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Fenêtre de déduplication : une même (règle, hôte, pid) n'alerte qu'une fois.
    pub dedup_window_secs: i64,
    /// Rafale de processus : seuil de créations par un même parent...
    pub spawn_burst_threshold: usize,
    /// ...dans cette fenêtre glissante.
    pub spawn_burst_window_secs: i64,
    /// Chiffrement massif : seuil d'écritures par un même processus...
    pub file_burst_threshold: usize,
    /// ...dans cette fenêtre glissante.
    pub file_burst_window_secs: i64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            dedup_window_secs: 60,
            spawn_burst_threshold: 8,
            spawn_burst_window_secs: 10,
            file_burst_threshold: 20,
            file_burst_window_secs: 5,
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_toml_keeps_defaults() {
        let cfg: Config = toml::from_str("spawn_burst_threshold = 3").unwrap();
        assert_eq!(cfg.spawn_burst_threshold, 3); // surchargé
        assert_eq!(cfg.dedup_window_secs, 60); // défaut conservé
        assert_eq!(cfg.file_burst_threshold, 20);
    }
}
