use crate::event::{Event, EventKind};
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct Node {
    ppid: u32,
    image: String,
}

/// Arbre de processus avec etat : resout l'ascendance d'un PID pour la
/// correlation (ex. "powershell dont un ancetre est Office").
#[derive(Debug, Default)]
pub struct ProcTree {
    nodes: HashMap<u32, Node>,
}

impl ProcTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Met a jour l'arbre et resout `parent_image` sur l'evenement si vide.
    /// A appeler avant l'evaluation des regles.
    pub fn observe(&mut self, ev: &mut Event) {
        match ev.kind {
            EventKind::ProcessStart => {
                if ev.parent_image.is_empty() {
                    if let Some(p) = self.nodes.get(&ev.ppid) {
                        ev.parent_image = p.image.clone();
                    }
                }
                self.nodes.insert(
                    ev.pid,
                    Node {
                        ppid: ev.ppid,
                        image: ev.image.clone(),
                    },
                );
            }
            EventKind::ProcessStop => {
                // ponytail: suppression immediate = simple. Un PID reutilise juste
                // apres un stop pourrait perdre son ascendance ; borner par TTL si besoin.
                self.nodes.remove(&ev.pid);
            }
            _ => {}
        }
    }

    /// Images des ancetres du PID, du parent direct vers la racine.
    /// Borne a 32 niveaux pour couper tout cycle accidentel.
    pub fn ancestors(&self, pid: u32) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = self.nodes.get(&pid).map(|n| n.ppid);
        let mut guard = 0;
        while let Some(ppid) = cur {
            guard += 1;
            if guard > 32 {
                break;
            }
            match self.nodes.get(&ppid) {
                Some(node) => {
                    out.push(node.image.clone());
                    cur = Some(node.ppid);
                    if node.ppid == ppid {
                        break; // auto-reference
                    }
                }
                None => break,
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(tree: &mut ProcTree, pid: u32, ppid: u32, image: &str) {
        let mut ev = Event::process_start("h", pid, ppid, image, "");
        tree.observe(&mut ev);
    }

    #[test]
    fn resolves_ancestry_chain() {
        let mut t = ProcTree::new();
        start(&mut t, 1, 0, r"C:\Windows\explorer.exe");
        start(&mut t, 2, 1, r"C:\Office\winword.exe");
        start(&mut t, 3, 2, r"C:\W\cmd.exe");
        start(&mut t, 4, 3, r"C:\W\powershell.exe");

        let anc = t.ancestors(4);
        let names: Vec<String> = anc.iter().map(|a| crate::event::base_name(a)).collect();
        assert_eq!(names, vec!["cmd.exe", "winword.exe", "explorer.exe"]);
    }

    #[test]
    fn observe_fills_parent_image() {
        let mut t = ProcTree::new();
        start(&mut t, 10, 0, r"C:\Office\winword.exe");
        let mut child = Event::process_start("h", 11, 10, r"C:\W\powershell.exe", "");
        t.observe(&mut child);
        assert_eq!(child.parent_name(), "winword.exe");
    }
}
