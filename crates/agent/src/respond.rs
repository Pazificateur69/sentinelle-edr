//! Exécution locale des ordres de réponse reçus du serveur. Terminaison de
//! processus par PID (Windows). Même implémentation que l'agent mono-poste.

#[cfg(windows)]
pub fn kill_process(pid: u32) -> anyhow::Result<()> {
    use windows::Win32::Foundation::{CloseHandle, FALSE};
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    // SAFETY : handles Win32 fermés systématiquement ; échecs remontés en erreur.
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid)
            .map_err(|e| anyhow::anyhow!("OpenProcess({pid}) : {e}"))?;
        let res = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
        res.map_err(|e| anyhow::anyhow!("TerminateProcess({pid}) : {e}"))?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn kill_process(_pid: u32) -> anyhow::Result<()> {
    anyhow::bail!("La terminaison de processus n'est implémentée que sous Windows")
}
