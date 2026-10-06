# tools/ — outillage du site (site/)

Le site est statique (aucun build). Deux scripts Python 3 sans dépendance le gardent
cohérent avec le code ; la CI (`.github/workflows/pages.yml`) les lance avant chaque
publication et échoue en cas d'écart.

## Quand `crates/common/rules.json` change

```sh
# depuis la racine du dépôt
python3 tools/gen_site.py . site/index.html fr
python3 tools/gen_site.py . site/en/index.html en
python3 tools/check_site.py site/index.html site/en/index.html site/404.html
```

- `gen_site.py` remplit les blocs entre marqueurs (`<!-- gen:… -->`, `/*gen:titles*/`) :
  catalogue des règles, égaliseur et table ATT&CK, grille live / simulation, titres des
  règles pour le banc d'essai, JSON-LD (FAQPage recopiée de la FAQ visible). Il copie aussi
  `rules.json` dans `site/assets/data/`. Il est idempotent : sans changement, aucun diff.
- Nouvelle règle : ajouter son titre FR et EN dans `titles.json` (le générateur refuse un id
  sans titre). En FR, mettre une espace insécable (` `) avant `:` `;` `?` `!`.
- `check_site.py` signale tout chiffre écrit en clair qui ne correspond plus à `rules.json`
  (51 règles, 45 live / 6 en simulation, techniques, sévérités…) : mettre alors le texte des
  deux pages à jour, FR et EN, puis relancer les deux scripts.
- Une réponse de FAQ modifiée à la main : relancer `gen_site.py` pour resynchroniser le JSON-LD.

`og-card.html` sert à produire `site/assets/img/og-image.png` (voir le commentaire du fichier).
