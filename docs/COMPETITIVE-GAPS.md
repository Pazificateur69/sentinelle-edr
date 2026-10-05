# Manques compétitifs & feuille de route de détection

Priorisation issue d'une revue externe (Codex/GPT), filtrée pour un dev solo
(pas de threat intel à l'échelle, pas de MVI/anti-tamper noyau). Classement par
rapport **impact / effort**, axé « couverture observable et vérifiable ».
État dans ce dépôt : ✅ fait · 🟡 logique faite, source de données à brancher · ⬜ à faire.

## 1. Accès interprocessus & tubes nommés — impact très fort
Ferme les angles morts LSASS, injection, communication latérale.
Événements Sysmon 10 (ProcessAccess), 8 (CreateRemoteThread), 17/18 (pipes),
25 (ProcessTampering), consommés via `EvtSubscribe` (crate `windows`).
Corréler source/cible, droits accordés, signature, chronologie.
- 🟡 **Détection livrée** : `SNT-0300` (accès LSASS par handle + masque de droits),
  `SNT-0310` (injection par thread distant), `SNT-0320` (tube nommé de C2 connu).
  Schéma d'événement étendu (`process_access`, `remote_thread`, `named_pipe`).
- ⬜ **Source à brancher** : connecteur Sysmon (`Microsoft-Windows-Sysmon/Operational`)
  pour alimenter ces événements. Dépendance Sysmon à déclarer explicitement.

## 2. Persistance observée côté système — impact fort
Les règles sur lignes de commande ratent les tâches créées via COM et les
abonnements WMI.
- ⬜ Événements Security **4698/4702** (audit activé), parsing XML via `quick-xml` ;
  inventaire différentiel `ITaskService` (`windows`).
- ⬜ WMI `root\subscription` (filtres/consommateurs/bindings) via la crate `wmi` ;
  Sysmon 19–21.

## 3. Ascendance fiable & contexte de sécurité — impact fort
Le **PPID spoofing** peut tromper le moteur actuel (qui fait confiance au parent déclaré).
- 🟡 **Détection livrée** : `SNT-B003` compare le parent déclaré (`ppid`) au créateur
  réel (`real_ppid`) ; un écart lève une alerte (T1134.004). Schéma étendu.
- ⬜ **Source à brancher** : renseigner `real_ppid` depuis le PID émetteur des
  événements ETW `Microsoft-Windows-Kernel-Process` ; identité = PID + date de création.
- ⬜ Contexte de sécurité : `OpenProcessToken`/`GetTokenInformation` (SID, intégrité,
  privilèges, AuthenticationId) ; détecter les transitions incohérentes (exceptions UAC).

## 4. Inspection mémoire ciblée — impact très fort, effort élevé
Deuxième preuve pour injection/hollowing.
- 🟡 **Moteur YARA-X livré** (`crates/scan`) et branché sur les images de processus (fichiers) ; reste à l'appliquer aux **buffers mémoire**.
- ⬜ Sur signal suspect : `VirtualQueryEx` / `ReadProcessMemory` / `QueryWorkingSetEx`
  (crate `windows`) sur les régions exécutables privées et pages image modifiées,
  puis **`yara-x`** sur les buffers. Borner durée/octets/concurrence ; filtrer les JIT.

## 5. Santé des capteurs — impact crédibilité très fort
Une console silencieuse doit distinguer *absence d'attaque* de *perte de visibilité*.
- 🟡 Files d'ingestion bornées avec **pertes mesurées** (fait).
- ⬜ Heartbeat agent→serveur + état « dégradé/silencieux » par hôte dans la console.
- ⬜ `ControlTraceW(QUERY)`, compteurs de pertes ETW, événements témoins (canaris).

## Ensuite
- **DNS / tunnels** : Sysmon 22, fenêtres par processus/domaine, combinaison
  volume + entropie + NXDOMAIN + périodicité (DoH reste partiellement opaque).

---

*Pour chaque ajout : livrer des scénarios reproductibles, mesurer les faux
positifs et le coût CPU/RAM (méthode constante de ce projet).*
