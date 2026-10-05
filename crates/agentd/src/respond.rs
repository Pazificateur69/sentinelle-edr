//! Actions de reponse. Phase actuelle : terminaison de processus par PID.
//! Quarantaine de fichier et isolation reseau (WFP) : etapes suivantes.

/// Termine un processus par PID. `Ok(())` si la demande a abouti.
#[cfg(windows)]
pub fn kill_process(pid: u32) -> anyhow::Result<()> {
    use windows::Win32::Foundation::{CloseHandle, FALSE};
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_TERMINATE,
    };
    // SAFETY : handles Win32 fermes systematiquement ; echecs remontes en erreur.
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
    anyhow::bail!("La terminaison de processus n'est implementee que sous Windows")
}
