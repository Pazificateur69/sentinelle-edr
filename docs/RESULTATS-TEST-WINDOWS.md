# Résultats des tests — Windows

Campagne de validation à l'exécution de **Sentinelle EDR** sur une machine Windows réelle,
en suivant [`docs/TEST-CE-SOIR.md`](TEST-CE-SOIR.md) et la suite de tests du workspace.

| | |
|---|---|
| **Date** | 2026-10-05 |
| **Machine** | `DIZY69` — Windows 11 Pro 26200 (x64) |
| **Toolchain** | rustc / cargo 1.98.1 |
| **Privilèges** | session **non-admin** (voir limites §ETW) |
| **Commit testé** | `main` au 2026-10-05 |

---

## 🧭 Verdict en une ligne

Le **cœur du produit est solide et vérifié sur Windows** : 57/57 tests verts, pipeline de
détection → corrélation → score → exports entièrement fonctionnel, réponse `kill` Win32
effective, transport parc gRPC + mTLS établi entre process séparés. **Les limites tiennent à
la plateforme et au câblage du capteur**, pas au moteur : sans droits admin il n'existe
aucune source de télémétrie live sous Windows, et le mode démo de l'agent de parc est absent
du build Windows. Détails et correctifs proposés plus bas.

---

## 🔧 Mise à jour — correctifs appliqués (PR #2)

Tous les problèmes listés plus bas (**A → G**) ont depuis été traités dans la PR
`fix(windows)` et **validés en live sur cette machine** (session non-admin) :

- **B** : repli automatique sur la scrutation multi-OS quand l'ETW ne démarre pas →
  `agentd` capte désormais de vrais processus **sans admin**.
- **B-bis** : `sensor-proc`/`cmdline_of` récupèrent enfin la **ligne de commande** sous
  Windows (elle était vide) → les règles cmdline se déclenchent.
- **C** : le **mode démo** de l'agent de parc fonctionne sous Windows (télémétrie live via mTLS).
- **D** : nom de session ETW unique par PID (fin des `AlreadyExist`).
- **E/F** : import inutilisé retiré ; port de `agentd` configurable (`SENTINELLE_HTTP`).
- **G** : lecture du **`OriginalFilename` du PE** → la détection de **masquerading
  `SNT-B004` se déclenche sur un vrai processus** (powershell renommé en svchost),
  y compris sans admin via la scrutation.
- **H** (PR #3) : l'`ImageName` ETW est un chemin NT (`\Device\HarddiskVolumeX\...`),
  qui empêchait la lecture du PE et les règles de chemin via l'ETW. Résolu : le chemin
  DOS (`C:\...`) et la ligne de commande sont résolus par PID via sysinfo sur le chemin ETW.

**Capture ETW noyau confirmée en session administrateur** (run du 2026-10-05, non élevé
→ repli ; élevé → ETW actif). Validé en live, en admin :
- l'ETW capte de **vrais processus système** (ex. `git.exe`, `conhost.exe`) ;
- détections live : **SNT-0012** (PowerShell furtif), **SNT-B001** (rafale de processus) ;
- après **H**, **SNT-B004** (masquerading) se déclenche aussi **via l'ETW** : event
  `image=C:\...\svchost.exe`, `original_file_name=PowerShell.EXE`.

Il ne reste donc **aucun point ouvert** issu de cette campagne. Le reste du document
conserve l'état **au moment des tests** (avant correctifs), comme journal.

---

## ✅ Ce qui a été validé

### 1. Suite de tests du workspace — **57/57 vertes, 0 échec**

Commande identique à la CI : `cargo test --workspace`.

| Binaire de test | Tests | Couvre |
|---|--:|---|
| `sentinelle-common` (lib) | **50 ✅** | règles, arbre booléen façon Sigma, import Sigma, scoring, corrélation |
| lib console / proto | 4 ✅ | état, sérialisation |
| autre lib | 2 ✅ | — |
| `tests/fleet.rs` → `mtls_fleet_roundtrip` | **1 ✅** | handshake mTLS mutuel + flux gRPC bidi + ingestion + routage d'un ordre de kill |

> Le test d'intégration parc passe **à l'exécution sur Windows** (pas seulement en
> compilation) : il monte un vrai serveur et un vrai client, établit le mTLS et route un
> ordre de kill jusqu'au client.

### 2. Rejeu de la kill chain (§1) — **7/7 alertes, 1 incident corrélé**

`SENTINELLE_REPLAY_FILE=./captures/demo.jsonl` → 7 événements ingérés, puis via l'API :

| Règle | Sévérité | Étape de la chaîne | ATT&CK |
|---|---|---|---|
| SNT-0001 | critical | Office lance un interpréteur (macro) | T1059 |
| SNT-0010 | high | PowerShell encodé | T1027 |
| SNT-0012 | medium | PowerShell furtif (hidden/bypass) | T1562.001 |
| SNT-0300 | critical | Accès mémoire LSASS | T1003.001 |
| SNT-0320 | high | Tube nommé C2 | T1572 |
| SNT-B003 | high | PPID spoofing | T1134.004 |
| SNT-B004 | high | Binaire renommé (masquerading) | T1036.003 |

**Corrélation** (`/api/incidents`) : les 7 alertes regroupées en **1 incident**
`INC-poste-test-20261005-200002` — sévérité `critical`, **score cumulé 520**, 10 techniques,
5 tactiques (`Execution → Privilege Escalation → Defense Evasion → Credential Access →
Command and Control`). La corrélation par arbre de processus fonctionne de bout en bout.

### 3. Exports (§1)

- **Rapport d'incident** (`GET /api/report`) : HTTP 200, `content-type: text/markdown`,
  `content-disposition: attachment; filename="rapport-incident-….md"`, 126 lignes, structure
  complète (*Synthèse → Incidents corrélés → Techniques ATT&CK → Chronologie → Détail des
  alertes → Actions recommandées*).
- **Couche MITRE ATT&CK Navigator** (`GET /api/navigator`) : JSON valide, schéma
  `layer 4.5 / navigator 4.9.1 / attack 14`, `domain: enterprise-attack`, techniques scorées
  par nombre de règles. Prête à déposer sur l'ATT&CK Navigator.
- **Couverture par tactique** (`GET /api/coverage`) : Defense Evasion 17, Execution 14,
  Persistence 9, C2 8, Credential Access 5, Discovery 3, Impact 3, Priv Esc 2, Lateral Mvt 2,
  Exfiltration 1.

### 4. Simulation d'attaque (§2)

`POST /api/simulate` → **HTTP 202**. `total_events` 7→14, `total_alerts` 7→14, nouvel hôte
`DIZY69` à score 580 (`critical`). La chaîne simulée se génère sans entrée externe.

### 5. Réponse — terminaison `kill` Win32 (réelle)

Process bénin lancé par le testeur (`ping -n 600`, PID 8236, propriété de l'utilisateur) :
`POST /api/respond/kill/DIZY69/8236` → `{"ok":true,"pid":8236}` → **process terminé**
(vérifié : absent de la table après l'appel). La réponse Win32 (`TerminateProcess`) est
**effective en conditions réelles** — l'un des deux points que le README laissait « à valider ».

### 6. Parc gRPC + mTLS (§4) — transport validé live

- **PKI** : `certgen ./certs` → `ca.pem`, `server.pem/key`, `client.pem/key` générés (pur Rust).
- **Serveur** : gRPC mTLS sur `0.0.0.0:50051`, console sur `127.0.0.1:8090`.
- **Agent** : *« Connecté à https://localhost:50051 en tant que poste-demo »* ; côté serveur
  l'hôte `poste-demo` apparaît en `live`. **Le handshake mTLS bidirectionnel entre deux process
  séparés fonctionne sur Windows.**

> Réserve : aucune **télémétrie** n'a circulé dans ce run live (0 événement côté serveur) —
> cause identifiée et documentée au problème **B** ci-dessous. La plomberie mTLS/gRPC
> elle-même est validée (ici + `fleet.rs`).

### 7. Options (§3)

| Option | Variable | Résultat |
|---|---|---|
| Persistance SQLite | `SENTINELLE_DB` | ✅ `Persistance SQLite : …` ; `/api/history` = 7 lignes ; **survit au redémarrage** (relance DB seule → 7 alertes rechargées) |
| Règles Sigma supplémentaires | `SENTINELLE_RULES_DIR=./rules.d` | ✅ `Sigma : 3 regle(s) importee(s) (0 ignoree)` ; `rule_count` 51 → **54** |
| Scan YARA | `SENTINELLE_YARA_DIR=./yara.d` | ✅ `YARA actif : règles chargées depuis …yara.d` |

---

## ⚠️ Problèmes rencontrés & pistes d'amélioration

### A. Windows Defender met les binaires en quarantaine (faux positif) — *bloquant au 1er run*

**Observé.** Au premier `cargo test`, échec avec `os error 225` (`ERROR_VIRUS_INFECTED`).
Journal Defender : `sentinelle_common-*.exe` (binaire de test) **et** `sentinelle-server.exe`
mis en quarantaine (ThreatID `2147739704`), supprimés avant exécution. Cause : les binaires
embarquent les 51 règles de détection (signatures reverse-shell, PowerShell encodé, patterns
LSASS/Mimikatz…) → l'heuristique de Defender les prend pour du malware.

**Aggravant.** La **Protection contre les falsifications** (Tamper Protection) étant active,
`Add-MpPreference -ExclusionPath` lancé en PowerShell admin est **ignoré silencieusement** :
l'exclusion doit passer par l'interface graphique de Sécurité Windows.

**Résolution appliquée pour cette campagne.** Exclusion de dossier (via l'UI) sur le repo →
`cargo test` passe, binaires exécutables.

**À améliorer.**
- Documenter dans le README / `TEST-CE-SOIR.md` que c'est **attendu** pour un EDR, avec la
  marche à suivre (exclusion dossier via l'UI, ou désactivation ponctuelle de Tamper
  Protection). Un développeur qui clone le repo tombe sinon sur un « échec de test » trompeur.
- À terme : **signer** les binaires release (Authenticode) réduit nettement les faux positifs.

### B. Aucun capteur live sous Windows sans droits admin — *important*

**Observé.** `agentd` : `capteur ETW arrete : … Accès refusé (0x80070005)`. L'ETW noyau exige
l'admin — attendu. **Mais il n'existe aucun repli.**

**Cause (code).** Dans `crates/agentd/src/main.rs` et `crates/agent/src/main.rs`, le capteur
ETW est câblé sous `#[cfg(windows)]`, et le capteur multi-OS `sentinelle-sensor-proc`
(scrutation `sysinfo`) **uniquement sous `#[cfg(not(windows))]`**. Résultat : sur Windows,
`sensor-proc` n'est jamais utilisé, même en dernier recours. Un utilisateur non-admin n'a donc
**aucune télémétrie** (ni `agentd`, ni `agent`) — seuls le rejeu et la simulation marchent.

> Cela contredit la table du README (« Capteur multi-OS | ETW (Windows) **+ scrutation de la
> table des processus via sysinfo (Linux/macOS/Windows)** ») : le volet sysinfo n'est pas
> câblé côté Windows.

**À améliorer.** Activer `sensor-proc` en **repli automatique sous Windows** quand l'ETW
échoue (non-admin), ou le proposer en option. Cela offre une détection de base sans admin et
aligne le comportement sur la promesse « multi-OS ». Puis corriger le README.

### C. Mode démo de l'agent de parc inopérant sous Windows — *important*

**Observé.** L'agent lancé avec `SENTINELLE_HOST=poste-demo SENTINELLE_REPLAY_SECS=20`
(la « variante démo » de `TEST-CE-SOIR.md` §4) se connecte en mTLS mais **ne pousse aucun
événement** (serveur : 0 événement).

**Cause (code).** La branche `SENTINELLE_REPLAY_SECS` (boucle de rejeu de la chaîne simulée)
se trouve dans `crates/agent/src/main.rs` sous `#[cfg(not(windows))]` (lignes ~141-152).
Sous Windows (`#[cfg(windows)]`, lignes ~120-135), l'agent ne fait **que** l'ETW ; la variable
est ignorée. La commande de démo documentée ne produit donc rien sur Windows.

**À améliorer.** Sortir la branche rejeu/démo du `cfg` pour la rendre disponible sur toutes
les plateformes (indépendamment du capteur). C'est aussi le moyen le plus simple de **démontrer
le parc live sous Windows** sans admin.

### D. Nom de session ETW fixe → collision `AlreadyExist` — *robustesse*

**Observé.** Après un premier échec ETW, la seconde instance (agent) remonte
`EtwNativeError(AlreadyExist)` au lieu de `Accès refusé`.

**Cause (code).** `crates/sensor-windows/src/etw.rs:55` : `UserTrace::new().named("sentinelle-kproc")`
— nom de session **en dur**. Les sessions ETW survivent à la mort du process ; une session
résiduelle d'un run précédent fait échouer le `start` suivant.

**À améliorer.** Suffixer le nom par le PID (ou un identifiant unique), et/ou **arrêter une
session homonyme existante avant** le `start`. Sinon, même en admin, l'utilisateur peut rester
bloqué jusqu'à purge manuelle (`logman stop sentinelle-kproc -ets`) ou reboot.

### E. Import inutilisé — *mineur (propreté)*

`crates/sensor-windows/src/etw.rs:22` : `use ferrisetw::trace::{TraceTrait, UserTrace};` —
`TraceTrait` est inutilisé (`warning: unused_imports`). Un `cargo fix --lib -p
sentinelle-sensor-windows` ou le retrait manuel suffit.

### F. Port de `agentd` non configurable — *mineur*

Pendant les tests, le port `8080` était pris par un autre logiciel (Steam). Le **serveur** de
parc expose `SENTINELLE_HTTP`/`SENTINELLE_GRPC` (bascule facile, utilisée ici vers `8090`),
mais **`agentd` code `127.0.0.1:8787` en dur** (`crates/agentd/src/main.rs:100`). Ajouter un
`SENTINELLE_HTTP` à `agentd` éviterait un conflit de port occasionnel.

---

## 🧪 Non validé (hors périmètre de cette session)

Ces points nécessitent une session **administrateur** et restent à confirmer :

- **Capture ETW live de vrais processus** (déclencher p. ex. SNT-B004 avec un `powershell`
  renommé en `svchost.exe` et le voir remonter) — bloqué par l'absence d'admin (problème B).
- **Ingestion de télémétrie live dans le parc** — bloquée par B et C sous Windows non-admin.

> Recommandation : rejouer A→ETW une fois en PowerShell **admin** (après correctifs B/C/D) pour
> clore la case « ETW capte réellement les processus » du README.

---

## 📋 Récapitulatif

| # | Élément | État |
|---|---|---|
| 1 | Tests workspace (57) + `fleet.rs` mTLS | ✅ |
| 2 | Rejeu kill chain + corrélation incident | ✅ |
| 3 | Export rapport `.md` + couche ATT&CK | ✅ |
| 4 | Simulation d'attaque | ✅ |
| 5 | Réponse `kill` Win32 réelle | ✅ |
| 6 | Parc : PKI + handshake mTLS live | ✅ (transport) |
| 7 | Options SQLite / Sigma / YARA | ✅ |
| A | Faux positif Defender (doc + signature) | ✅ documenté (README + TEST-CE-SOIR) ; signature Authenticode au backlog |
| B | Pas de repli sysinfo sous Windows (non-admin) | ✅ corrigé (PR #2) |
| B-bis | `command_line` vide sous Windows | ✅ corrigé (PR #2) |
| C | Mode démo agent absent du build Windows | ✅ corrigé (PR #2) |
| D | Nom de session ETW fixe (`AlreadyExist`) | ✅ corrigé (PR #2) |
| E | Import inutilisé `TraceTrait` | ✅ corrigé (PR #2) |
| F | Port `agentd` non configurable | ✅ corrigé (PR #2) |
| G | Masquerading `SNT-B004` muet en live (PE OriginalFilename) | ✅ corrigé (PR #2) |
| H | Chemin NT ETW (masquerading/chemin muets via ETW) | ✅ corrigé (PR #3) |
| — | ETW **noyau** live (capture profonde, admin) | ✅ confirmé en admin (SNT-0012/B001/B004) |
