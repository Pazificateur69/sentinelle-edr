# Guide de test — Sentinelle EDR

Pas-à-pas pour valider le produit. **Toutes les commandes de déclenchement ci-dessous sont bénignes** (elles ne font que produire une ligne de commande reconnaissable — aucune connexion réelle, aucun fichier malveillant).

---

## 0. Récupérer et lancer (marche partout : Windows, Linux, macOS)

```bash
git clone https://github.com/Pazificateur69/sentinelle-edr
cd sentinelle-edr
cargo run --release -p sentinelle-agentd
```

Ouvre **http://localhost:8787**.

- **Windows** : lance le terminal **en Administrateur** → capteur ETW réel. Sans admin, repli automatique sur la scrutation (vraie télémétrie, moins profonde).
- **Linux / macOS** : capteur multi-OS (scrutation des processus) → vraie télémétrie.

> ⚠️ **Windows Defender met les binaires en quarantaine — c'est attendu pour un EDR.** Au 1er `cargo test`/`run`, Defender peut supprimer `sentinelle-*.exe` (les binaires embarquent des signatures reverse-shell, LSASS, PowerShell encodé → l'heuristique les prend pour du malware). Symptôme : `os error 225` (`ERROR_VIRUS_INFECTED`).
> **Solution** : Sécurité Windows → *Protection contre les virus* → *Gérer les paramètres* → *Exclusions* → ajouter le **dossier du repo**. ⚠️ Avec la **Protection contre les falsifications** active, `Add-MpPreference -ExclusionPath` en PowerShell est **ignoré silencieusement** : passe par l'**interface graphique**. (À terme : signer les binaires release en Authenticode règle le souci.)

---

## 1. Test « ça marche » en 10 secondes — rejeu de capture

Même sans rien installer d'autre, rejoue une kill chain complète à travers tout le pipeline :

```bash
SENTINELLE_REPLAY_FILE=./captures/demo.jsonl cargo run --release -p sentinelle-agentd
```

Sur http://localhost:8787 tu dois voir apparaître, dans l'ordre :
macro Office → PowerShell encodé → **accès LSASS** → **tube C2** → **PPID spoofing** → **binaire renommé (masquerading `SNT-B004`)**.

**Puis clique :**
- **⬇ Rapport d'incident** → télécharge un `.md` : synthèse, incident corrélé, progression kill chain, détail par alerte, actions recommandées.
- **⬇ Couche ATT&CK** → télécharge un JSON. Dépose-le sur https://mitre-attack.github.io/attack-navigator/ (bouton « Open Existing Layer » → « Upload from local ») : la matrice se colore selon la couverture.

---

## 2. Déclencher de vraies alertes (bénin)

Laisse `cargo run -p sentinelle-agentd` tourner dans un terminal, ouvre-en un autre et lance selon l'OS.

> ⚠️ **Hors Windows**, le capteur fonctionne par **scrutation (~1 s)** : un processus trop bref peut passer entre deux passes. Les commandes ci-dessous incluent un petit `sleep` pour rester visibles. Pour une démo 100 % fiable, préfère le **§1 (rejeu)** ou le bouton **« Simuler »**. Sous **Windows**, l'ETW capte tout, même l'instantané.

### Linux / macOS

```bash
# SNT-1000 : curl | bash (curl vers un port fermé, bash ne reçoit rien)
bash -c 'curl -s http://127.0.0.1:9/ | bash; sleep 2'

# SNT-1002 : signature reverse shell (echo d'une chaîne, AUCUNE connexion)
bash -c 'echo /dev/tcp/127.0.0.1/4444; sleep 2'

# SNT-1004 : exécution depuis /tmp (copie de « sleep », vit 2 s puis meurt)
cp "$(command -v sleep)" /tmp/payload && /tmp/payload 2
```

### macOS en plus

```bash
# SNT-1009 : osascript do shell script (dort 2 s, inoffensif)
osascript -e 'do shell script "sleep 2"'
```

### Windows

```bat
:: SNT-B004 : masquerading — powershell.exe renommé, trahi par le nom d'origine du PE
copy "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" "%TEMP%\svchost.exe"
"%TEMP%\svchost.exe" -Command "exit"
```

> Le bouton **« ▶ Simuler une attaque »** de la console déclenche la chaîne complète sans rien taper — utile pour une démo rapide sur n'importe quel OS.

---

## 3. Options utiles

```bash
# Historique persistant (SQLite) — survit aux redémarrages
SENTINELLE_DB=sentinelle.db cargo run --release -p sentinelle-agentd

# Charger des règles Sigma en plus
SENTINELLE_RULES_DIR=./rules.d cargo run --release -p sentinelle-agentd

# Scan YARA des images de processus (Windows surtout)
SENTINELLE_YARA_DIR=./yara.d cargo run --release -p sentinelle-agentd
```

---

## 4. Mode parc (agent ↔ serveur central, gRPC + mTLS)

```bash
# 1. PKI (pur Rust, pas d'openssl)
cargo run -p sentinelle-certgen -- ./certs

# 2. Serveur central (console multi-hôtes sur http://localhost:8080)
cargo run --release -p sentinelle-server

# 3. Un agent (sur cette machine : capteur réel ; ailleurs : idem)
SENTINELLE_HOST=poste-test cargo run --release -p sentinelle-agent

# Variante démo (rejoue la chaîne simulée en boucle toutes les 20 s)
SENTINELLE_HOST=poste-demo SENTINELLE_REPLAY_SECS=20 cargo run --release -p sentinelle-agent
```

La console du serveur montre tous les postes, leur risque, et l'état de vivacité du capteur (live / ralenti / silencieux).

---

## À vérifier / me remonter

- Les alertes du §2 apparaissent-elles bien (bon ID de règle, bonne sévérité) ?
- Le rapport et la couche Navigator se téléchargent-ils et s'ouvrent-ils correctement ?
- Sous Windows : l'ETW capte-t-il les vrais processus (pas seulement la simulation) ?
- Faux positifs éventuels sur ton usage réel (à mettre en allowlist).
