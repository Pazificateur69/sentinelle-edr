//! Persistance SQLite des alertes : l'historique survit aux redémarrages et
//! reste interrogeable pour l'investigation. Optionnel (activé par
//! `SENTINELLE_DB=chemin.db`). L'alerte complète est stockée en JSON ; des
//! colonnes indexables (hôte, règle, sévérité, score) facilitent les requêtes.

use rusqlite::Connection;
use sentinelle_common::{Alert, Event};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Rétention par défaut : nombre maximal d'alertes conservées.
const DEFAULT_RETENTION: usize = 100_000;
/// Rétention des événements (plus volumineux que les alertes).
const EVENT_RETENTION: usize = 50_000;
/// Purge appliquée tous les N inserts.
const PRUNE_EVERY: u64 = 1000;
const EVENT_PRUNE_EVERY: u64 = 5000;

pub struct Store {
    conn: Mutex<Connection>,
    retention: usize,
    inserts: AtomicU64,
    event_inserts: AtomicU64,
}

impl Store {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        Self::open_with_retention(path, DEFAULT_RETENTION)
    }

    pub fn open_with_retention(path: &str, retention: usize) -> anyhow::Result<Self> {
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
            CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
            CREATE TABLE IF NOT EXISTS events (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                ts    TEXT NOT NULL,
                host  TEXT NOT NULL,
                kind  TEXT NOT NULL,
                image TEXT NOT NULL,
                pid   INTEGER NOT NULL,
                json  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            retention,
            inserts: AtomicU64::new(0),
            event_inserts: AtomicU64::new(0),
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
        // Purge périodique (évite une croissance illimitée de la base).
        if (self.inserts.fetch_add(1, Ordering::Relaxed) + 1) % PRUNE_EVERY == 0 {
            let _ = self.prune();
        }
        Ok(())
    }

    pub fn insert_event(&self, e: &Event) -> anyhow::Result<()> {
        let json = serde_json::to_string(e)?;
        let kind = serde_json::to_value(e.kind)?
            .as_str()
            .unwrap_or("")
            .to_string();
        self.conn.lock().unwrap().execute(
            "INSERT INTO events (ts,host,kind,image,pid,json) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![e.ts.to_rfc3339(), e.host, kind, e.image, e.pid, json],
        )?;
        if (self.event_inserts.fetch_add(1, Ordering::Relaxed) + 1) % EVENT_PRUNE_EVERY == 0 {
            let _ = self.prune_events();
        }
        Ok(())
    }

    pub fn recent_events(&self, limit: usize) -> anyhow::Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT json FROM events ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(e) = serde_json::from_str::<Event>(&row?) {
                out.push(e);
            }
        }
        Ok(out)
    }

    pub fn prune_events(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?1",
            [EVENT_RETENTION as i64],
        )?;
        Ok(n)
    }

    /// Ne conserve que les `retention` alertes les plus récentes. Renvoie le
    /// nombre de lignes supprimées.
    pub fn prune(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM alerts WHERE id <= (SELECT MAX(id) FROM alerts) - ?1",
            [self.retention as i64],
        )?;
        Ok(n)
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
            ancestors: vec![],
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

    #[test]
    fn event_roundtrip() {
        let store = Store::open(":memory:").unwrap();
        store
            .insert_event(&Event::process_start("h", 10, 1, r"C:\x.exe", ""))
            .unwrap();
        store
            .insert_event(&Event::network("h", 11, r"C:\y.exe", "1.2.3.4", 443))
            .unwrap();
        let recent = store.recent_events(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].pid, 11); // plus récent d'abord
    }

    #[test]
    fn retention_prunes_old_alerts() {
        let store = Store::open_with_retention(":memory:", 5).unwrap();
        for i in 0..8 {
            store.insert_alert(&alert(&format!("R{i}"))).unwrap();
        }
        assert_eq!(store.count().unwrap(), 8);
        store.prune().unwrap();
        assert_eq!(store.count().unwrap(), 5); // ne garde que les 5 plus récentes
        assert_eq!(store.recent(10).unwrap()[0].rule_id, "R7");
    }
}
