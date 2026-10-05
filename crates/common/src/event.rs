use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Nature de l'evenement. On couvre les sources ETW visees en phase 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessStart,
    ProcessStop,
    Network,
    FileWrite,
    ImageLoad,
    /// Ouverture d'un handle sur un autre processus (ex. accès LSASS).
    ProcessAccess,
    /// Création d'un thread distant (injection).
    RemoteThread,
    /// Connexion à un tube nommé (C2 / latéral).
    NamedPipe,
}

/// Evenement a plat facon ECS/OCSF : un seul type pour toutes les sources, avec
/// des champs optionnels. Le moteur de regles interroge les champs par nom, ce
/// qui garde l'evaluation uniforme quelle que soit la source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: DateTime<Utc>,
    pub host: String,
    pub kind: EventKind,

    pub pid: u32,
    /// PID du parent déclaré.
    pub ppid: u32,
    /// PID réel du créateur (fourni par ETW) ; 0 = inconnu. Un écart avec `ppid`
    /// révèle une usurpation de parent (PPID spoofing).
    #[serde(default)]
    pub real_ppid: u32,

    /// Chemin complet de l'image (ou nom si le chemin manque).
    #[serde(default)]
    pub image: String,
    /// Image du parent, resolue par le capteur via sa table PID -> image.
    #[serde(default)]
    pub parent_image: String,
    #[serde(default)]
    pub command_line: String,
    #[serde(default)]
    pub parent_command_line: String,
    /// Nom d'origine du binaire (champ PE OriginalFilename), résistant au renommage.
    #[serde(default)]
    pub original_file_name: String,
    /// Niveau d'intégrité du processus (Low/Medium/High/System).
    #[serde(default)]
    pub integrity_level: String,
    #[serde(default)]
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    // Reseau
    #[serde(default)]
    pub dst_ip: String,
    #[serde(default)]
    pub dst_port: u16,

    // Fichier / image chargee
    #[serde(default)]
    pub file_path: String,

    // Accès interprocessus / injection / tube nommé
    #[serde(default)]
    pub target_image: String,
    #[serde(default)]
    pub granted_access: String,
    #[serde(default)]
    pub pipe_name: String,
}

impl Event {
    /// Evenement processus minimal, le cas le plus courant.
    pub fn process_start(host: &str, pid: u32, ppid: u32, image: &str, parent_image: &str) -> Self {
        Event {
            ts: Utc::now(),
            host: host.to_string(),
            kind: EventKind::ProcessStart,
            pid,
            ppid,
            real_ppid: 0,
            image: image.to_string(),
            parent_image: parent_image.to_string(),
            command_line: String::new(),
            parent_command_line: String::new(),
            original_file_name: String::new(),
            integrity_level: String::new(),
            user: String::new(),
            sha256: None,
            dst_ip: String::new(),
            dst_port: 0,
            file_path: String::new(),
            target_image: String::new(),
            granted_access: String::new(),
            pipe_name: String::new(),
        }
    }

    /// Accès à un autre processus (handle), ex. lecture de LSASS.
    pub fn process_access(host: &str, pid: u32, image: &str, target_image: &str, granted_access: &str) -> Self {
        let mut e = Self::process_start(host, pid, 0, image, "");
        e.kind = EventKind::ProcessAccess;
        e.target_image = target_image.to_string();
        e.granted_access = granted_access.to_string();
        e
    }

    /// Création d'un thread distant (injection) dans `target_image`.
    pub fn remote_thread(host: &str, pid: u32, image: &str, target_image: &str) -> Self {
        let mut e = Self::process_start(host, pid, 0, image, "");
        e.kind = EventKind::RemoteThread;
        e.target_image = target_image.to_string();
        e
    }

    /// Connexion à un tube nommé.
    pub fn named_pipe(host: &str, pid: u32, image: &str, pipe_name: &str) -> Self {
        let mut e = Self::process_start(host, pid, 0, image, "");
        e.kind = EventKind::NamedPipe;
        e.pipe_name = pipe_name.to_string();
        e
    }

    /// Connexion reseau sortante.
    pub fn network(host: &str, pid: u32, image: &str, dst_ip: &str, dst_port: u16) -> Self {
        let mut e = Self::process_start(host, pid, 0, image, "");
        e.kind = EventKind::Network;
        e.dst_ip = dst_ip.to_string();
        e.dst_port = dst_port;
        e
    }

    /// Ecriture de fichier.
    pub fn file_write(host: &str, pid: u32, image: &str, file_path: &str) -> Self {
        let mut e = Self::process_start(host, pid, 0, image, "");
        e.kind = EventKind::FileWrite;
        e.file_path = file_path.to_string();
        e
    }

    /// Chargement d'une image/DLL/driver (`loaded` = chemin du module chargé).
    pub fn image_load(host: &str, pid: u32, image: &str, loaded: &str) -> Self {
        let mut e = Self::process_start(host, pid, 0, image, "");
        e.kind = EventKind::ImageLoad;
        e.file_path = loaded.to_string();
        e
    }

    pub fn with_cmdline(mut self, cmd: &str) -> Self {
        self.command_line = cmd.to_string();
        self
    }

    /// Renseigne le vrai PID créateur (pour la détection d'usurpation de parent).
    pub fn with_real_ppid(mut self, real_ppid: u32) -> Self {
        self.real_ppid = real_ppid;
        self
    }

    pub fn with_user(mut self, user: &str) -> Self {
        self.user = user.to_string();
        self
    }

    /// Valeur d'un champ nomme (nommage facon Sigma), pour le moteur de regles.
    /// Renvoie None si le champ est vide/absent.
    pub fn field(&self, name: &str) -> Option<String> {
        let v = match name {
            "Image" => self.image.clone(),
            "ImageName" => base_name(&self.image),
            "ParentImage" => self.parent_image.clone(),
            "ParentImageName" => base_name(&self.parent_image),
            "CommandLine" => self.command_line.clone(),
            "ParentCommandLine" => self.parent_command_line.clone(),
            "OriginalFileName" => self.original_file_name.clone(),
            "IntegrityLevel" => self.integrity_level.clone(),
            "User" => self.user.clone(),
            "Sha256" | "Hashes" => self.sha256.clone().unwrap_or_default(),
            "DestinationIp" => self.dst_ip.clone(),
            "DestinationPort" => self.dst_port.to_string(),
            "TargetFilename" => self.file_path.clone(),
            "ImageLoaded" => self.file_path.clone(),
            "TargetImage" => self.target_image.clone(),
            "TargetImageName" => base_name(&self.target_image),
            "GrantedAccess" => self.granted_access.clone(),
            "PipeName" => self.pipe_name.clone(),
            _ => return None,
        };
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    }

    pub fn image_name(&self) -> String {
        base_name(&self.image)
    }
    pub fn parent_name(&self) -> String {
        base_name(&self.parent_image)
    }
}

/// Dernier segment d'un chemin Windows ou Unix, en minuscules.
pub fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_lookup_and_basename() {
        let e = Event::process_start(
            "host-1",
            10,
            4,
            r"C:\Office\WINWORD.EXE",
            r"C:\Windows\explorer.exe",
        )
        .with_cmdline("winword.exe /n");
        assert_eq!(e.field("ImageName").unwrap(), "winword.exe");
        assert_eq!(e.field("Image").unwrap(), r"C:\Office\WINWORD.EXE");
        assert_eq!(e.field("CommandLine").unwrap(), "winword.exe /n");
        assert!(e.field("User").is_none()); // vide -> None
        assert!(e.field("ChampInconnu").is_none());
    }
}
