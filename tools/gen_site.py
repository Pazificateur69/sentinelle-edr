#!/usr/bin/env python3
"""Generateur des blocs statiques du site Sentinelle a partir de crates/common/rules.json.

Usage (depuis la racine du depot) :
  python3 tools/gen_site.py . site/index.html fr
  python3 tools/gen_site.py . site/en/index.html en
Idempotent : relance sans changement de rules.json/titles.json => aucun diff (verifie en CI).
Remplit, entre marqueurs, dans la page :
  /*gen:titles*/.../*/gen:titles*/      -> map ruleTitles de SENTINELLE_I18N
  <!-- gen:eq -->...<!-- /gen:eq -->     -> egaliseur ATT&CK (14 tactiques)
  <!-- gen:eqtable -->...                -> table accessible equivalente
  <!-- gen:catalog -->...                -> table des 51 regles
  <!-- gen:grid -->...                   -> 51 cellules de la grille de verite
  <!-- gen:jsonld -->...                 -> JSON-LD (@graph) dont FAQPage = FAQ visible
Copie aussi rules.json dans site/assets/data/.
"""
import html, json, os, re, shutil, sys
from collections import Counter

REPO, PAGE, LANG = sys.argv[1], sys.argv[2], sys.argv[3]
rules = json.load(open(f"{REPO}/crates/common/rules.json", encoding="utf-8"))
T = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "titles.json"), encoding="utf-8"))
missing = [r["id"] for r in rules if r["id"] not in T]
assert not missing, f"titres manquants dans tools/titles.json : {missing}"
shutil.copy(f"{REPO}/crates/common/rules.json", f"{REPO}/site/assets/data/rules.json")

# copie de tactic_of() (crates/common/src/lib.rs)
TAC = {"Initial Access": "T1189 T1566", "Execution": "T1059 T1203 T1047 T1569 T1106",
       "Persistence": "T1547 T1053 T1543 T1136 T1546 T1197", "Privilege Escalation": "T1548 T1068 T1134",
       "Defense Evasion": "T1218 T1027 T1562 T1070 T1140 T1211 T1112 T1055 T1036 T1222",
       "Credential Access": "T1003 T1552 T1555",
       "Discovery": "T1087 T1082 T1016 T1049 T1018 T1482 T1033 T1007", "Lateral Movement": "T1021",
       "Command and Control": "T1105 T1071 T1571 T1095 T1090 T1572", "Exfiltration": "T1048 T1567",
       "Impact": "T1486 T1490"}
def tactic_of(t):
    b = t.split(".")[0]
    return next((k for k, v in TAC.items() if b in v.split()), "Autre")

ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
         "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
         "Collection", "Command and Control", "Exfiltration", "Impact"]
L = {
    "fr": dict(sev={"critical": "critique", "high": "haute", "medium": "moyenne", "low": "basse", "info": "info"},
               live="live", sim="simulation-seulement", none="0 — non couvert",
               cap="Catalogue des 51 règles de détection natives de Sentinelle EDR",
               cols=["ID", "Titre", "Sévérité", "Techniques ATT&CK", "Tactiques", "Statut"],
               eqcap="Nombre de règles Sentinelle par tactique MITRE ATT&CK Enterprise",
               eqcols=["Tactique", "Règles"], uncovered="non couvert"),
    "en": dict(sev={"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"},
               live="live", sim="simulation-only", none="0 — not covered",
               cap="Catalog of the 51 native Sentinelle EDR detection rules",
               cols=["ID", "Title", "Severity", "ATT&CK techniques", "Tactics", "Status"],
               eqcap="Number of Sentinelle rules per MITRE ATT&CK Enterprise tactic",
               eqcols=["Tactic", "Rules"], uncovered="not covered"),
}[LANG]
e = html.escape

def tlink(t):
    return f'<a class="ttp" href="https://attack.mitre.org/techniques/{t.replace(".", "/")}/">{t}</a>'

per_tac = Counter()
for r in rules:
    for tac in {tactic_of(t) for t in r["attack"]}:
        per_tac[tac] += 1
# Les chiffres affiches en clair dans les pages (51 regles, 45/6, 10 tactiques...) sont
# controles contre rules.json par tools/check_site.py, pas ici.

def sub(src, name, body, js=False):
    a, b = (f"/*gen:{name}*/", f"/*/gen:{name}*/") if js else (f"<!-- gen:{name} -->", f"<!-- /gen:{name} -->")
    pat = re.compile(re.escape(a) + r".*?" + re.escape(b), re.S)
    assert pat.search(src), name
    return pat.sub(lambda m: a + body + b, src)

page = open(PAGE, encoding="utf-8").read()

# ruleTitles
titles = {r["id"]: T[r["id"]][LANG] for r in rules}
page = sub(page, "titles", "ruleTitles:" + json.dumps(titles, ensure_ascii=False, separators=(",", ":")), js=True)

# egaliseur
cols = []
for ci, tac in enumerate(ORDER):
    n = per_tac.get(tac, 0)
    segs = "".join(f'<i style="--i:{k}"></i>' for k in range(n))
    cls = "eq-col" + ("" if n else " is-zero")
    val = str(n) if n else L["none"]
    cols.append(f'<div class="{cls}" style="--col:{ci}"><span class="eq-v">{val}</span>'
                f'<div class="eq-bar">{segs}</div><span class="eq-l">{tac}</span></div>')
page = sub(page, "eq", "\n" + "\n".join(cols) + "\n")

rows = "".join(f'<tr><th scope="row">{tac}</th><td>{per_tac.get(tac, 0) or "0 (" + L["uncovered"] + ")"}</td></tr>' for tac in ORDER)
# Table dans un conteneur masqué visuellement : une table ne rétrécit pas sous son contenu,
# masquée seule elle élargissait la page sur mobile.
page = sub(page, "eqtable", f'<div class="sr-only-lg"><table><caption>{L["eqcap"]}</caption><thead><tr><th scope="col">{L["eqcols"][0]}</th><th scope="col">{L["eqcols"][1]}</th></tr></thead><tbody>{rows}</tbody></table></div>')

# catalogue
body = []
for r in rules:
    tacs = sorted({tactic_of(t) for t in r["attack"]}, key=ORDER.index)
    sim = r["kind"] != "process_start"
    st = f'<span class="st-sim">{L["sim"]}</span>' if sim else f'<span class="st-live">{L["live"]}</span>'
    tr = '<tr class="is-sim">' if sim else "<tr>"
    body.append(f'{tr}<th scope="row"><code>{r["id"]}</code></th><td>{e(T[r["id"]][LANG])}</td>'
                f'<td><span class="pill sev-{r["severity"]}">{L["sev"][r["severity"]]}</span></td>'
                f'<td>{" ".join(tlink(t) for t in r["attack"])}</td><td>{", ".join(tacs)}</td><td>{st}</td></tr>')
head = "".join(f'<th scope="col">{e(c)}</th>' for c in L["cols"])
page = sub(page, "catalog", f'\n<table class="catalog"><caption>{L["cap"]}</caption><thead><tr>{head}</tr></thead><tbody>\n' + "\n".join(body) + "\n</tbody></table>\n")

# grille de verite
SIMC = ' class="sim"'
cells = "".join(f'<i data-rule="{r["id"]}" style="--i:{k}"{SIMC if r["kind"] != "process_start" else ""}></i>' for k, r in enumerate(rules))
page = sub(page, "grid", cells)

# JSON-LD : FAQ extraite du HTML visible (texte identique par construction)
def txt(s):
    return re.sub(r"[ \t\r\n]+", " ", html.unescape(re.sub(r"<[^>]+>", "", s))).strip()
faq = re.findall(r'<details class="faq-item">\s*<summary>(.*?)</summary>\s*<div class="faq-a">(.*?)</div>\s*</details>', page, re.S)
assert len(faq) == 12, len(faq)
desc = re.search(r'<meta name="description" content="([^"]+)"', page).group(1)
ROOT = "https://pazificateur69.github.io/sentinelle-edr/"
url = ROOT + ("en/" if LANG == "en" else "")
app = ROOT + "#app"
# Le noeud logiciel est identique (meme @id, meme url) sur les deux pages ; la langue est
# portee par le noeud WebPage propre a chaque page.
graph = {"@context": "https://schema.org", "@graph": [
    {"@type": "WebPage", "@id": url + "#page", "url": url, "name": html.unescape(re.search(r"<title>([^<]+)</title>", page).group(1)),
     "inLanguage": LANG, "about": {"@id": app}},
    {"@type": "SoftwareApplication", "@id": app, "name": "Sentinelle EDR", "applicationCategory": "SecurityApplication",
     "operatingSystem": "Windows, Linux, macOS", "description": html.unescape(desc), "url": ROOT,
     "license": "https://opensource.org/licenses/MIT", "offers": {"@type": "Offer", "price": "0", "priceCurrency": "EUR"},
     "author": {"@type": "Person", "name": "Pazificateur69", "url": "https://github.com/Pazificateur69"},
     "sameAs": ["https://github.com/Pazificateur69/sentinelle-edr"]},
    {"@type": "SoftwareSourceCode", "name": "sentinelle-edr", "codeRepository": "https://github.com/Pazificateur69/sentinelle-edr",
     "programmingLanguage": "Rust", "license": "https://opensource.org/licenses/MIT", "targetProduct": {"@id": app}},
    {"@type": "FAQPage", "inLanguage": LANG, "mainEntity": [
        {"@type": "Question", "name": txt(q), "acceptedAnswer": {"@type": "Answer", "text": txt(a)}} for q, a in faq]},
]}
ld = json.dumps(graph, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
page = sub(page, "jsonld", f'<script type="application/ld+json">{ld}</script>')

open(PAGE, "w", encoding="utf-8").write(page)
print("ok", PAGE, dict(per_tac))
