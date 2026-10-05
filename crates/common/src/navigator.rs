//! Export d'une couche MITRE ATT&CK Navigator (format JSON standard).
//!
//! On dépose le fichier sur <https://mitre-attack.github.io/attack-navigator/>
//! et la matrice ATT&CK se colore selon le nombre de règles Sentinelle par
//! technique. C'est la façon dont les SOC visualisent (et comparent) une
//! couverture de détection.

use serde_json::json;
use std::collections::BTreeMap;

/// Construit une couche Navigator à partir du nombre de règles par technique.
pub fn layer(name: &str, counts: &BTreeMap<String, u32>) -> String {
    let max = counts.values().copied().max().unwrap_or(1).max(1);
    let techniques: Vec<_> = counts
        .iter()
        .map(|(id, n)| {
            json!({
                "techniqueID": id,
                "score": n,
                "comment": format!("{n} règle(s) Sentinelle"),
                "enabled": true,
            })
        })
        .collect();

    let layer = json!({
        "name": name,
        "versions": { "attack": "14", "navigator": "4.9.1", "layer": "4.5" },
        "domain": "enterprise-attack",
        "description": "Couverture de détection Sentinelle EDR — le score d'une technique est le nombre de règles qui la couvrent.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#e8f5e9", "#2ce6a6", "#0b6b4f"],
            "minValue": 0,
            "maxValue": max
        },
        "legendItems": [],
        "showTacticRowBackground": true,
        "tacticRowBackground": "#0d1117",
        "selectTechniquesAcrossTactics": true,
        "sorting": 3
    });
    serde_json::to_string_pretty(&layer).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_is_valid_navigator_json() {
        let mut counts = BTreeMap::new();
        counts.insert("T1059".to_string(), 3u32);
        counts.insert("T1003.001".to_string(), 1u32);
        let s = layer("Test", &counts);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["domain"], "enterprise-attack");
        assert_eq!(v["gradient"]["maxValue"], 3);
        let techs = v["techniques"].as_array().unwrap();
        assert!(techs.iter().any(|t| t["techniqueID"] == "T1059" && t["score"] == 3));
    }
}
