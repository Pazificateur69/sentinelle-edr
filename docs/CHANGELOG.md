# Changelog

Toutes les évolutions notables de Sentinelle. Format libre, ordre antéchronologique.

## 0.1.0 (en cours)

### Détection
- Moteur de règles façon Sigma : opérateurs `equals`/`contains`/`starts_with`/`ends_with`/`regex`/`cidr`, arbre booléen `and`/`or`/`not`.
- **Import de règles Sigma** (YAML) : modificateurs `base64`/`windash`/`cidr`/`all`, quantificateurs `1 of`/`all of`, champs non mappés rejetés.
- Corrélation par **arbre de processus** (ascendance) ; **scoring** avec décroissance par hôte + **confiance** par règle.
- **Allowlist/suppression** et **déduplication** (anti-faux-positifs, anti-bruit).
- Détecteurs **comportementaux** : rafale de créations de processus (SNT-B001), chiffrement massif de fichiers (SNT-B002).
- **36 règles** couvrant les **10 tactiques** ATT&CK ; télémétrie processus + réseau + fichier + chargement d'image (détection **BYOVD**).
- **Seuils réglables** par fichier TOML (`SENTINELLE_CONFIG`).

### Collecte & plateforme
- Capteur **ETW** Windows (processus) + enrichissement ligne de commande.
- Files d'ingestion **bornées** (backpressure, pertes mesurées).

### Parc
- Agents ↔ serveur central en **gRPC + mTLS bidirectionnel**.
- **Réponse à distance** : terminaison de processus sur n'importe quel poste depuis la console.
- Génération de PKI intégrée (`sentinelle-certgen`).

### Console & persistance
- Console SOC temps réel (SSE) : filtres par sévérité, recherche, répartition, couverture ATT&CK, mode démo autonome.
- **Persistance SQLite** optionnelle (`SENTINELLE_DB`) : historique d'**alertes et d'événements**, avec **rétention/purge automatique** bornée.
- Endpoints `/healthz`, `/api/coverage`, `/api/history`.

### Qualité
- **CI GitHub Actions** : build + tests sur **Ubuntu et Windows**.
- Suite de tests unitaires du cœur de détection.
- **Test d'intégration du parc** : handshake mTLS + flux bidirectionnel + ingestion + ordre de kill routé, validés au runtime en CI (Ubuntu + Windows).
