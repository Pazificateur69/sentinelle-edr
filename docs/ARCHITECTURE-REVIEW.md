# Revue d'architecture compétitive (EDR Windows, Rust)

Synthèse d'une revue externe (Codex/GPT, oct. 2026), filtrée et annotée. Sert de
cap technique pour passer d'une base fonctionnelle à un produit présentable.
Chaque section indique l'**état dans ce dépôt** : ✅ fait, 🟡 partiel, ⬜ à faire.

## 1. Capteur Windows (user-mode, sans driver, sans MVI)

Service privilégié, **collecte séparée du moteur**. Crates : `ferrisetw`, `windows` (ETW/TDH).

Socle : session **NT Kernel Logger** (SystemTraceProvider), événements classiques —
- `EVENT_TRACE_FLAG_PROCESS` → Process_V2 : démarrage/arrêt, parent, SID, **CommandLine natif**. 🟡 *(on utilise le provider manifeste + enrichissement `sysinfo` ; migrer vers le logger classique pour la cmdline native — noté dans `etw.rs`)*
- `EVENT_TRACE_FLAG_NETWORK_TCPIP` → TcpIp/UdpIp, attribution par PID. ⬜
- `EVENT_TRACE_FLAG_FILE_IO` → correspondance FileObject→chemin. ⬜
- `EVENT_TRACE_FLAG_IMAGE_LOAD` → images/DLL (chargements manuels hors loader invisibles). ⬜

**ETW tampering : aucun provider universel.** Surveiller `ControlTraceW(QUERY)`, le
compteur `EventsLost`, des événements canaris, un heartbeat distant. Une anomalie =
**perte de visibilité**, pas forcément une attaque. `Microsoft-Windows-Threat-Intelligence`
exige PPL → hors périmètre sans MVI. ⬜

## 2. Moteur de détection

Normaliser en événements typés ✅, puis **compiler Sigma vers un AST interne**
(logsource, mapping de champs, modifiers, conditions, valeurs absentes), en
**rejetant explicitement** les constructions non supportées. La crate
[`tau-engine`](https://github.com/WithSecureLabs/tau-engine) (WithSecure) exécute
les prédicats après conversion ; corrélation dans une couche distincte. 🟡
*(on a un moteur type Sigma maison en JSON + lineage/ascendance ; l'import Sigma YAML reste à faire)*

État indexé par **machine+boot+PID+heure de création** 🟡 *(actuellement PID ;
ajouter boot+création pour éviter la collision de PID réutilisés)*. Score
explicable : **poids × confiance, décroissance, déduplication**, seuils distincts
alerte/réponse. 🟡 *(poids + décroissance ✅ ; confiance, dedup, seuil de réponse ⬜)*.
Crates : `serde` ✅, `regex` ✅, `tokio` ✅, `rusqlite` ⬜ (persistance).

## 3. Réponse (crate `windows`)

- **Kill** : `OpenProcess(PROCESS_TERMINATE)` → `TerminateProcess` ; revérifier
  l'identité, exclure les processus critiques. 🟡 *(kill implémenté ; garde-fou processus critiques ⬜)*
- **Quarantaine** : hash, `MoveFileExW`, coffre chiffré + ACL restrictives,
  restauration journalisée, gestion des fichiers verrouillés. ⬜
- **Isolation réseau** : `FwpmEngineOpen0` / `FwpmTransactionBegin0` / `FwpmFilterAdd0`,
  `FWP_ACTION_BLOCK` aux couches `ALE_AUTH_CONNECT_V4/V6` et `ALE_AUTH_RECV_ACCEPT_V4/V6`.
  Exceptions administration, transactions, désisolation. Pas de callout driver nécessaire. ⬜

## 4. Anti-tamper (sans driver signé ni PPL)

`windows-service`, ACL service/fichiers/IPC, privilèges minimaux, mises à jour
signées, watchdog temporisé, heartbeat distant. **Limite honnête : un
Admin/SYSTEM peut arrêter/modifier l'agent ; un adversaire noyau est hors
garantie.** Ne jamais promettre l'inviolabilité. ⬜

## 5. Les cinq erreurs fatales

| Erreur | Parade |
|--------|--------|
| Faux positifs | corpus bénin, exceptions étroites, **mode observation** d'abord |
| Saturation | files **bornées**, filtrage, budgets CPU/RAM, pertes mesurées |
| Mauvaise attribution | identités stables (boot+PID+création), parent falsifiable |
| **Crash en boucle (type CrowdStrike)** | workers séparés, fuzzing, redémarrages plafonnés, version saine de secours |
| Réponse/MAJ destructrice | actions **graduées**, canaris, rollback indépendant, protection des process critiques |

## 6. Backlog priorisé (→ produit présentable)

1. Contrat d'événements + matrice de couverture ATT&CK. 🟡 *(schéma ✅, matrice ⬜)*
2. Collecte processus/DLL fiable (logger noyau, cmdline native). 🟡
3. Réseau/fichier avec budgets mesurés. ⬜
4. Graphe de processus + **replay déterministe** (rejouer une capture). 🟡 *(graphe ✅, replay ⬜)*
5. Sous-ensemble Sigma testé, ~20 détections ciblées. 🟡 *(18 règles maison ✅, import Sigma ⬜)*
6. Alertes explicables + console d'investigation. ✅ *(console temps réel livrée)*
7. Réponses réversibles, authentifiées, auditées. 🟡 *(kill ✅ ; audit/auth/réversibilité ⬜)*
8. Installateur signé, MAJ progressives, rollback, pilote terrain. ⬜

---

*Les points ⬜/🟡 sont la vraie distance qui sépare cette base d'un produit
commercial. Aucun n'est bloqué techniquement ; ils demandent du temps et, pour
le capteur/réponse, une VM Windows de validation.*
