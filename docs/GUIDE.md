# Guide d'utilisation — Sentinelle

Guide pratique pour installer, lancer et régler Sentinelle. Pour l'architecture,
voir le [README](../README.md) ; pour le détail technique, [ARCHITECTURE-REVIEW.md](ARCHITECTURE-REVIEW.md).

## 1. Prérequis

- Rust stable (1.80+ ; développé/validé avec 1.95).
- Windows pour le capteur ETW réel (en **Administrateur**). Le reste tourne partout.

## 2. Mode mono-poste

Le plus simple : un seul binaire = capteur + moteur + console + réponse.

```bash
cargo run --release -p sentinelle-agentd
```

Ouvrir http://localhost:8787. Sans Windows, cliquer **« Simuler une attaque »**
(ou `POST /api/simulate`) pour voir le moteur réagir. Sous Windows en admin, les
vrais processus de la machine sont analysés.

Variables utiles :

| Variable | Effet |
|----------|-------|
| `SENTINELLE_RULES_DIR` | dossier de règles **Sigma** à charger en plus (ex. `./rules.d`) |
| `SENTINELLE_ALLOWLIST` | fichier JSON d'exceptions (réduction de faux positifs) |
| `SENTINELLE_CONFIG` | fichier TOML de seuils (voir `sentinelle.example.toml`) |
| `SENTINELLE_DB` | fichier SQLite : l'historique d'alertes survit aux redémarrages |
| `SENTINELLE_YARA_DIR` | dossier de règles **YARA** (`.yar`) : scan de l'image de chaque nouveau processus |

Exemple complet :

```bash
SENTINELLE_RULES_DIR=./rules.d \
SENTINELLE_CONFIG=./sentinelle.toml \
SENTINELLE_DB=./sentinelle.db \
cargo run --release -p sentinelle-agentd
```

## 3. Mode parc (plusieurs postes)

Les agents poussent leur télémétrie au serveur central en **gRPC + mTLS**, et
reçoivent en retour les ordres de réponse. La console du serveur agrège tous les
postes et permet de **tuer un processus à distance**.

```bash
# 1. Générer la PKI (CA + cert serveur + cert client), pur Rust
cargo run -p sentinelle-certgen -- ./certs

# 2. Serveur central (console http://localhost:8080, ingestion gRPC :50051)
cargo run --release -p sentinelle-server

# 3. Un agent par poste (nom d'hôte distinct)
SENTINELLE_HOST=poste-compta    cargo run --release -p sentinelle-agent
SENTINELLE_HOST=poste-direction cargo run --release -p sentinelle-agent
```

Variables côté serveur : `SENTINELLE_HTTP` (défaut `127.0.0.1:8080`),
`SENTINELLE_GRPC` (défaut `0.0.0.0:50051`), `SENTINELLE_CERTS_DIR`, `SENTINELLE_DB`.
Variables côté agent : `SENTINELLE_SERVER` (défaut `https://localhost:50051`),
`SENTINELLE_HOST`, `SENTINELLE_CERTS_DIR`, `SENTINELLE_RULES_DIR`,
`SENTINELLE_CONFIG`, `SENTINELLE_REPLAY_SECS` (rejoue la simulation en boucle).

## 4. Écrire une détection

**Règle native** (JSON) : ajouter une entrée dans
[`crates/common/rules.json`](../crates/common/rules.json).

```json
{
  "id": "SNT-9001",
  "title": "Mon interpréteur suspect",
  "severity": "high",
  "attack": ["T1059"],
  "kind": "process_start",
  "confidence": 0.8,
  "all": [
    { "field": "ImageName", "op": "equals", "values": ["mon_outil.exe"] },
    { "field": "CommandLine", "op": "contains", "values": ["-suspect"] }
  ]
}
```

Opérateurs : `equals`, `contains`, `starts_with`, `ends_with`, `regex`, `cidr`.
Champs : `Image`, `ImageName`, `ParentImage`, `CommandLine`, `User`, `Sha256`,
`DestinationIp`, `DestinationPort`, `TargetFilename`, `ImageLoaded`.

**Règle Sigma** : déposer un `.yml` dans un dossier pointé par
`SENTINELLE_RULES_DIR`. Modificateurs gérés : `contains`, `startswith`,
`endswith`, `re`, `base64`, `windash`, `cidr`, `all` ; condition `and`/`or`/`not`
+ quantificateurs `1 of ...` / `all of ...`. Un champ non mappé fait rejeter la
règle (jamais importée « morte »).

## 5. Réduire un faux positif

Ajouter une entrée dans `SENTINELLE_ALLOWLIST` (ou
[`crates/common/allowlist.json`](../crates/common/allowlist.json)) :

```json
[
  { "id": "ALLOW-1", "rule_id": "SNT-0031",
    "all": [ { "field": "CommandLine", "op": "contains", "values": ["\\notre_outil\\"] } ] }
]
```

`rule_id` absent = s'applique à toutes les règles. Une allowlist sans condition
ne supprime rien (garde-fou).

## 6. Régler les seuils

Copier `sentinelle.example.toml` → `sentinelle.toml`, ajuster, et lancer avec
`SENTINELLE_CONFIG=./sentinelle.toml`. Champs : fenêtre de déduplication, seuils
et fenêtres des détecteurs de rafale (processus) et de chiffrement massif.

## 7. Endpoints

`/` (console) · `/healthz` · `/api/stream` (SSE) · `/api/alerts` · `/api/events`
· `/api/stats` · `/api/history` · `/api/coverage` · `/api/simulate` (mono-poste)
· `/api/respond/kill/{host}/{pid}`.
