# Changelog

Toutes les évolutions notables de Sentinelle. Format libre, ordre antéchronologique.

## 0.1.0 (en cours)

### Détection
- Moteur de règles façon Sigma : opérateurs `equals`/`contains`/`starts_with`/`ends_with`/`regex`/`cidr`, arbre booléen `and`/`or`/`not`.
- **Import de règles Sigma** (YAML) : modificateurs `base64`/`windash`/`cidr`/`all`, quantificateurs `1 of`/`all of`, champs non mappés rejetés.
- Corrélation par **arbre de processus** (ascendance) ; **scoring** avec décroissance par hôte + **confiance** par règle.
- **Allowlist/suppression** et **déduplication** (anti-faux-positifs, anti-bruit).
- Détecteurs **comportementaux** : rafale de créations de processus (SNT-B001), chiffrement massif de fichiers (SNT-B002), **PPID spoofing** (SNT-B003), **masquerading** (SNT-B004 — binaire sensible renommé, détecté via le nom d'origine du PE).
- **51 règles + détecteurs comportementaux** (LSASS handle, injection, pipes C2, BYOVD...) couvrant **10 tactiques** ATT&CK ; télémétrie processus + réseau + fichier + chargement d'image.
- **Règles Linux/macOS** : `curl|bash`, reverse shell (`/dev/tcp`, `nc -e`), base64→shell, exécution depuis `/tmp`, lecture `/etc/shadow` + clés SSH, persistance cron / `.bashrc` / LaunchAgent, désactivation SIP/Gatekeeper, `osascript do shell script`, effacement d'historique.
- **Corrélation en incidents** : les alertes d'une même séquence (hôte + proximité temporelle) sont regroupées en un incident avec progression kill chain, sévérité et score cumulés.
- **Seuils réglables** par fichier TOML (`SENTINELLE_CONFIG`).

### Collecte & plateforme
- **Scan YARA (YARA-X)** de l'image des nouveaux processus (`SENTINELLE_YARA_DIR`), hors thread async, taille bornée.
- Capteur **ETW** Windows (processus) + enrichissement ligne de commande.
- **Capteur multi-OS** (`sentinelle-sensor-proc`) : scrutation de la table des processus via `sysinfo` — tourne sous **Linux, macOS et Windows**. Vraie télémétrie hors Windows (plus seulement la simulation).
- Files d'ingestion **bornées** (backpressure, pertes mesurées).

### Parc
- Agents ↔ serveur central en **gRPC + mTLS bidirectionnel**.
- **Réponse à distance** : terminaison de processus sur n'importe quel poste depuis la console.
- Génération de PKI intégrée (`sentinelle-certgen`).
- **Santé des capteurs** : heartbeat agent→serveur ; statut de vivacité par hôte (live/ralenti/silencieux) dans la console — distingue « calme » de « capteur mort/aveuglé ».

### Console & persistance
- Console SOC temps réel (SSE) : filtres par sévérité, recherche, répartition, couverture ATT&CK, mode démo autonome.
- **Persistance SQLite** optionnelle (`SENTINELLE_DB`) : historique d'**alertes et d'événements**, avec **rétention/purge automatique** bornée.
- **Exports** : rapport d'incident **Markdown** (`/api/report`), **incidents corrélés** (`/api/incidents`), couche **MITRE ATT&CK Navigator** JSON (`/api/navigator`) — boutons dédiés dans la console.
- Endpoints `/healthz`, `/api/coverage`, `/api/history`.

### Qualité
- **CI GitHub Actions** : build + tests sur **Ubuntu et Windows**.
- Suite de tests unitaires du cœur de détection.
- **Test d'intégration du parc** : handshake mTLS + flux bidirectionnel + ingestion + ordre de kill routé, validés au runtime en CI (Ubuntu + Windows).
