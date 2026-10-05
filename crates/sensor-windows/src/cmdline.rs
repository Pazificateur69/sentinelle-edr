//! Enrichissement best-effort de la ligne de commande d'un processus par PID.
//!
//! Le provider ETW Kernel-Process ne fournit PAS la ligne de commande. On la
//! recupere via `sysinfo` (multiplateforme, pas d'unsafe). C'est intrinsequement
//! racy : un processus tres bref peut disparaitre avant qu'on l'interroge ; dans
//! ce cas on renvoie une chaine vide et les regles basees sur CommandLine ne se
//! declenchent pas pour cet evenement. Compromis assume en phase 1.

use sysinfo::{Pid, ProcessesToUpdate, System};

/// Ligne de commande du PID, ou chaine vide si indisponible.
pub fn cmdline_of(pid: u32) -> String {
    let mut sys = System::new();
    let p = Pid::from_u32(pid);
    // Rafraichit uniquement ce PID (pas tout le systeme) pour limiter le cout.
    sys.refresh_processes(ProcessesToUpdate::Some(&[p]), true);
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
