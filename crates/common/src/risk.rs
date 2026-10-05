use std::collections::HashMap;

/// Score de risque par hote, avec decroissance : une rafale d'alertes fait
/// monter le score, qui redescend tout seul si plus rien ne se passe. Evite
/// qu'un hote reste "rouge" a vie a cause d'un incident ancien.
#[derive(Debug, Default)]
pub struct RiskTracker {
    /// score courant + instant (secondes epoch) de la derniere mise a jour.
    scores: HashMap<String, (f64, i64)>,
    /// demi-vie en secondes (defaut 1h).
    half_life_secs: f64,
}

impl RiskTracker {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            half_life_secs: 3600.0,
        }
    }

    pub fn with_half_life(secs: f64) -> Self {
        Self {
            scores: HashMap::new(),
            half_life_secs: secs.max(1.0),
        }
    }

    fn decayed(&self, cur: f64, last: i64, now: i64) -> f64 {
        let dt = (now - last).max(0) as f64;
        cur * 0.5_f64.powf(dt / self.half_life_secs)
    }

    /// Ajoute `points` au score de l'hote a l'instant `now` (epoch secondes),
    /// renvoie le nouveau score (borne 0..=1000).
    pub fn add(&mut self, host: &str, points: u32, now: i64) -> f64 {
        let (cur, last) = self.scores.get(host).copied().unwrap_or((0.0, now));
        let next = (self.decayed(cur, last, now) + points as f64).clamp(0.0, 1000.0);
        self.scores.insert(host.to_string(), (next, now));
        next
    }

    /// Score courant de l'hote a l'instant `now`, sans le modifier.
    pub fn score(&self, host: &str, now: i64) -> f64 {
        self.scores
            .get(host)
            .map(|&(cur, last)| self.decayed(cur, last, now))
            .unwrap_or(0.0)
    }

    /// Tous les hotes connus avec leur score courant a l'instant `now`.
    pub fn hosts(&self, now: i64) -> Vec<(String, f64)> {
        self.scores
            .iter()
            .map(|(h, &(cur, last))| (h.clone(), self.decayed(cur, last, now)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_then_decays() {
        let mut r = RiskTracker::with_half_life(100.0);
        let t0 = 1_000_000;
        assert_eq!(r.add("h", 100, t0), 100.0);
        // deux alertes rapprochees s'additionnent
        assert_eq!(r.add("h", 50, t0), 150.0);
        // apres une demi-vie, moitie du score
        let s = r.score("h", t0 + 100);
        assert!((s - 75.0).abs() < 0.01, "attendu ~75, obtenu {s}");
    }

    #[test]
    fn unknown_host_is_zero() {
        let r = RiskTracker::new();
        assert_eq!(r.score("absent", 0), 0.0);
    }
}
