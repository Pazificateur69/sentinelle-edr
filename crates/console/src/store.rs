//! Persistance SQLite des alertes : l'historique survit aux redémarrages et
//! reste interrogeable pour l'investigation. Optionnel (activé par
//! `SENTINELLE_DB=chemin.db`). L'alerte complète est stockée en JSON ; des
//! colonnes indexables (hôte, règle, sévérité, score) facilitent les requêtes.

use rusqlite::Connection;
use sentinelle_common::Alert;
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS alerts (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       TEXT NOT NULL,
                host     TEXT NOT NULL,
                rule_id  TEXT NOT NULL,
                title    TEXT NOT NULL,
                severity TEXT NOT NULL,
                score    INTEGER NOT NULL,
                attack   TEXT NOT NULL,
                json     TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);
            CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert_alert(&self, a: &Alert) -> anyhow::Result<()> {
        let json = serde_json::to_string(a)?;
        let severity = serde_json::to_value(a.severity)?
            .as_str()
            .unwrap_or("medium")
            .to_string();
        self.conn.lock().unwrap().execute(
            "INSERT INTO alerts (ts,host,rule_id,title,severity,score,attack,json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![
                a.ts.to_rfc3339(),
                a.host,
                a.rule_id,
                a.title,
                severity,
                a.score,
                a.attack.join(","),
                json,
            ],
        )?;
        Ok(())
    }

    /// Les `limit` alertes les plus récentes (plus récente d'abord).
    pub fn recent(&self, limit: usize) -> anyhow::Result<Vec<Alert>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT json FROM alerts ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(a) = serde_json::from_str::<Alert>(&row?) {
                out.push(a);
            }
        }
        Ok(out)
    }

    pub fn count(&self) -> anyhow::Result<u64> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0))?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelle_common::rules::Severity;
    use sentinelle_common::Event;

    fn alert(rule: &str) -> Alert {
        Alert {
            ts: chrono::Utc::now(),
            host: "h".into(),
            rule_id: rule.into(),
            title: "test".into(),
            description: "d".into(),
            severity: Severity::High,
            attack: vec!["T1059".into()],
            score: 70,
            event: Event::process_start("h", 1, 2, r"C:\a.exe", ""),
        }
    }

    #[test]
    fn insert_count_recent_roundtrip() {
        let store = Store::open(":memory:").unwrap();
        store.insert_alert(&alert("R1")).unwrap();
        store.insert_alert(&alert("R2")).unwrap();
        assert_eq!(store.count().unwrap(), 2);
        let recent = store.recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].rule_id, "R2"); // plus récente d'abord
    }
}
