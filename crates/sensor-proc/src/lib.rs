//! Capteur multi-OS par scrutation de la table des processus (via `sysinfo`).
//!
//! Tourne sous Linux, macOS et Windows. Émet un `process_start` pour chaque
//! nouveau PID observé entre deux passes, avec image, parent et ligne de commande.
//! Expose la même signature `run(host, handler)` que le capteur ETW, pour être
//! interchangeable dans les agents.
//!
//! ponytail: scrutation (poll), pas de hook noyau. Rate les processus très
//! brefs (nés et morts entre deux passes) et ne voit ni réseau, ni écritures
//! fichier, ni accès mémoire. C'est la couverture multi-OS honnête ; l'ETW
//! Windows reste supérieur pour la profondeur de télémétrie.

use sentinelle_common::Event;
use std::collections::HashSet;
use std::time::Duration;
use sysinfo::{Process, ProcessesToUpdate, System};

/// Intervalle de scrutation par défaut.
pub const DEFAULT_POLL_MS: u64 = 1000;

/// Démarre le capteur (bloquant) avec l'intervalle par défaut.
pub fn run<F>(host: String, handler: F) -> anyhow::Result<()>
where
    F: Fn(Event) + Send + Sync + 'static,
{
    run_with_poll(host, handler, DEFAULT_POLL_MS)
}

/// Variante avec intervalle de scrutation réglable (ms).
pub fn run_with_poll<F>(host: String, handler: F, poll_ms: u64) -> anyhow::Result<()>
where
    F: Fn(Event) + Send + Sync + 'static,
{
    let mut sys = System::new();

    // Première passe : on enregistre l'existant SANS alerter — sinon tout ce qui
    // tourne déjà au démarrage ressemblerait à un flot de « nouveaux » processus.
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut known: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
    tracing::info!(
        "Capteur multi-OS actif (scrutation {poll_ms} ms ; {} processus déjà en cours).",
        known.len()
    );

    loop {
        std::thread::sleep(Duration::from_millis(poll_ms));
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let current: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
        for (pid, proc_) in sys.processes() {
            let p = pid.as_u32();
            if !known.contains(&p) {
                handler(build_event(&host, p, proc_, &sys));
            }
        }
        // `current` remplace `known` : les PID disparus sont oubliés (évite la
        // croissance mémoire et gère la réutilisation de PID par l'OS).
        known = current;
    }
}

/// Construit un `process_start` à partir d'un processus `sysinfo`. Le parent est
/// résolu dans le même instantané pour renseigner `parent_image`.
fn build_event(host: &str, pid: u32, proc_: &Process, sys: &System) -> Event {
    let image = proc_
        .exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| proc_.name().to_string_lossy().into_owned());
    let ppid = proc_.parent().map(|p| p.as_u32()).unwrap_or(0);
    let parent_image = proc_
        .parent()
        .and_then(|pp| sys.process(pp))
        .and_then(|pp| pp.exe())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let cmd = proc_
        .cmd()
        .iter()
        .map(|s| s.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    Event::process_start(host, pid, ppid, &image, &parent_image).with_cmdline(&cmd)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    /// Vérifie que le capteur voit un processus lancé APRÈS son démarrage
    /// (et pas l'existant). Unix uniquement (dépend de `sleep`).
    #[test]
    fn observes_a_newly_spawned_process() {
        let (tx, rx) = mpsc::channel::<Event>();
        std::thread::spawn(move || {
            let _ = run_with_poll("test".into(), move |ev| { let _ = tx.send(ev); }, 100);
        });
        // Laisse la première passe enregistrer l'existant.
        std::thread::sleep(Duration::from_millis(300));

        let mut child = std::process::Command::new("sleep").arg("3").spawn().unwrap();
        let target = child.id();

        let mut found = false;
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(ev) if ev.pid == target => {
                    found = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        let _ = child.kill();
        assert!(found, "le capteur multi-OS doit détecter le processus enfant (pid {target})");
    }
}
