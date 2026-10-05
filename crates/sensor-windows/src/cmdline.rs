//! Enrichissement best-effort de la ligne de commande d'un processus par PID.
//!
//! Le provider ETW Kernel-Process ne fournit PAS la ligne de commande. On la
//! recupere via `sysinfo` (multiplateforme, pas d'unsafe). C'est intrinsequement
//! racy : un processus tres bref peut disparaitre avant qu'on l'interroge ; dans
//! ce cas on renvoie une chaine vide et les regles basees sur CommandLine ne se
//! declenchent pas pour cet evenement. Compromis assume en phase 1.

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// Ligne de commande du PID, ou chaine vide si indisponible.
pub fn cmdline_of(pid: u32) -> String {
    let mut sys = System::new();
    let p = Pid::from_u32(pid);
    // Rafraichit uniquement ce PID (pas tout le systeme) pour limiter le cout, en
    // demandant EXPLICITEMENT la ligne de commande : le rafraichissement par defaut
    // ne la recupere pas sous Windows (elle restait vide).
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[p]),
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    sys.process(p)
        .map(|proc_| {
            proc_
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}
