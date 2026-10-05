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
    pub ppid: u32,

    /// Chemin complet de l'image (ou nom si le chemin manque).
    #[serde(default)]
    pub image: String,
    /// Image du parent, resolue par le capteur via sa table PID -> image.
    #[serde(default)]
    pub parent_image: String,
    #[serde(default)]
    pub command_line: String,
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
            image: image.to_string(),
            parent_image: parent_image.to_string(),
            command_line: String::new(),
            user: String::new(),
            sha256: None,
            dst_ip: String::new(),
            dst_port: 0,
            file_path: String::new(),
        }
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

    pub fn with_cmdline(mut self, cmd: &str) -> Self {
        self.command_line = cmd.to_string();
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
            "User" => self.user.clone(),
            "Sha256" => self.sha256.clone().unwrap_or_default(),
            "DestinationIp" => self.dst_ip.clone(),
            "DestinationPort" => self.dst_port.to_string(),
            "TargetFilename" => self.file_path.clone(),
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
