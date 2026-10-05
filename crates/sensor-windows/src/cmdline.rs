//! Enrichissement best-effort d'un processus par PID (via `sysinfo`).
//!
//! Le provider ETW Kernel-Process ne fournit NI la ligne de commande, NI un chemin
//! d'image exploitable : l'`ImageName` ETW est un chemin NT (`\Device\HarddiskVolumeX\...`),
//! pas un chemin DOS (`C:\...`). On enrichit donc via `sysinfo` (multiplateforme, pas
//! d'unsafe) :
//!   - la ligne de commande (sinon les regles CommandLine ne se declenchent pas) ;
//!   - le chemin DOS de l'image (necessaire pour lire la ressource de version du PE
//!     — detection de masquerading — et pour les regles basees sur le chemin).
//!
//! Intrinsequement racy : un processus tres bref peut disparaitre avant qu'on
//! l'interroge ; on renvoie alors des chaines vides et l'appelant retombe sur ce
//! que l'ETW a fourni. Compromis assume en phase 1.

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// Chemin DOS de l'image ET ligne de commande du PID (via sysinfo), ou chaines
/// vides si indisponible.
pub fn image_and_cmdline_of(pid: u32) -> (String, String) {
    let mut sys = System::new();
    let p = Pid::from_u32(pid);
    // Rafraichit uniquement ce PID, en demandant EXPLICITEMENT l'image et la ligne
    // de commande (le rafraichissement par defaut ne les recupere pas sous Windows).
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[p]),
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );
    match sys.process(p) {
        Some(proc_) => {
            let image = proc_
                .exe()
                .map(|e| e.to_string_lossy().into_owned())
                .unwrap_or_default();
            let cmd = proc_
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            (image, cmd)
        }
        None => (String::new(), String::new()),
    }
}
