#!/usr/bin/env python3
"""Contrôles statiques du site Sentinelle (zéro dépendance).

Usage (depuis la racine du dépôt) :
  python3 tools/check_site.py site/index.html site/en/index.html site/404.html
Code de sortie 1 au moindre échec.

Vérifie : structure HTML équilibrée, un seul h1, ids uniques, liens relatifs résolus, ancres
internes existantes, aucune ressource tierce chargée, JSON-LD valide (FAQPage identique à la
FAQ visible, pas de note/avis), formulations interdites, chiffres-clés cohérents avec
crates/common/rules.json, typographie française (espaces insécables) sur les pages FR.
"""
import html, json, os, re, sys
from collections import Counter
from html.parser import HTMLParser

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr",
        "path", "circle", "rect", "polygon", "line", "polyline", "stop"}
OPTIONAL_CLOSE = {"p", "li", "tr", "td", "th", "thead", "tbody", "option"}
NO_TYPO = {"pre", "code", "script", "style", "head", "title", "textarea", "kbd"}
FORBIDDEN = ["meilleur que", "protège votre entreprise", "zéro faux positif", "zero faux positif",
             "100 % des attaques", "100% des attaques", "utilisé par", "témoignage", "étoiles",
             "better than", "protects your business", "protect your business", "zero false positive",
             "100% of attacks", "used by", "testimonial", "aggregaterating"]


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.refs, self.ids, self.h1, self.err, self.typo = [], [], [], 0, [], []
        self.lang = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "html": self.lang = a.get("lang")
        if tag == "h1": self.h1 += 1
        if "id" in a: self.ids.append(a["id"])
        for k in ("href", "src"):
            if a.get(k): self.refs.append((tag, k, a[k], a.get("rel", "")))
        if tag not in VOID: self.stack.append((tag, self.getpos()[0]))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID: self.stack.pop()

    def handle_endtag(self, tag):
        if tag in VOID: return
        while self.stack and self.stack[-1][0] != tag and self.stack[-1][0] in OPTIONAL_CLOSE:
            self.stack.pop()
        if not self.stack or self.stack[-1][0] != tag:
            self.err.append(f"</{tag}> inattendu l.{self.getpos()[0]}"); return
        self.stack.pop()

    def handle_data(self, data):
        if any(t in NO_TYPO for t, _ in self.stack): return
        for m in re.finditer(r" [:;?!»]|« ", data):
            self.typo.append((self.getpos()[0], data[max(0, m.start() - 25):m.end() + 10].strip()))


def text_of(s):
    return re.sub(r"[ \t\r\n]+", " ", html.unescape(re.sub(r"<[^>]+>", "", s))).strip()


def site_root(path):
    d = os.path.dirname(os.path.abspath(path))
    while not os.path.isdir(os.path.join(d, "assets")):
        if os.path.dirname(d) == d: sys.exit(f"{path} : racine du site (dossier assets/) introuvable")
        d = os.path.dirname(d)
    return d


def figures(rules):
    tech = {t for r in rules for t in r["attack"]}
    sev = Counter(r["severity"] for r in rules)
    live = sum(r["kind"] == "process_start" for r in rules)
    unix = sum(r["id"].startswith("SNT-1") for r in rules)
    return dict(n=len(rules), live=live, sim=len(rules) - live, tech=len(tech), base=len({t.split(".")[0] for t in tech}),
                win=len(rules) - unix, unix=unix, crit=sev["critical"], high=sev["high"], med=sev["medium"],
                low=sev["low"], info=sev["info"])


# Chiffres-clés écrits en clair dans les pages : chaque motif doit être présent (sinon, mettre le texte à jour).
KEYS = {
    "fr": [r"<b>{n}</b> règles", r"<b>{live}</b> live / <b>{sim}</b> en simulation", r"<b>{tech}</b> \(sous-\)(<wbr>)?techniques",
           r"{tech} techniques et sous-techniques", r"\({base} techniques", r"{win} règles Windows et {unix} règles Linux/macOS",
           r"{crit} critiques", r"{high} hautes", r"{med} moyennes", r"{low} basses", r"{info} info",
           r'ratio-n">{live}<', r'ratio-d">/ {n}<', r"des {live} règles <code>process_start", r"Voir les {n} règles",
           r"{live} règles sur {n}"],
    "en": [r"<b>{n}</b> rules", r"<b>{live}</b> live / <b>{sim}</b> simulation-only", r"<b>{tech}</b> ATT&amp;CK \(sub-\)(<wbr>)?techniques",
           r"{tech} techniques and sub-techniques", r"\({base} (base )?techniques", r"{win} Windows rules and {unix} Linux/macOS rules",
           r"{crit} critical<", r"{high} high<", r"{med} medium<", r"{low} low<", r"{info} info<",
           r'ratio-n">{live}<', r'ratio-d">/ {n}<', r"of the {live} <code>process_start", r"Show all {n} rules",
           r"{live} of the {n} rules"],
}


def check(path, fails):
    src = open(path, encoding="utf-8").read()
    root = site_root(path)
    name = os.path.relpath(path, root)
    f = lambda msg: fails.append(f"{name} : {msg}")
    p = Page(); p.feed(src); p.close()
    left = [x for x in p.stack if x[0] not in OPTIONAL_CLOSE]
    if p.err or left: f(f"structure HTML {p.err[:3]} non fermés={left[:3]}")
    if p.h1 != 1: f(f"{p.h1} h1 (attendu : 1)")
    dup = sorted({i for i in p.ids if p.ids.count(i) > 1})
    if dup: f(f"ids dupliqués {dup}")
    is404 = os.path.basename(path) == "404.html"

    for tag, attr, ref, rel in p.refs:
        if ref.startswith("#"):
            if len(ref) > 1 and ref[1:] not in p.ids: f(f"ancre sans cible {ref}")
            continue
        if re.match(r"^(mailto:|data:)", ref): continue
        if re.match(r"^https?:", ref):
            if tag in ("script", "img", "iframe", "source") or (tag == "link" and re.search(r"stylesheet|preload|icon", rel or "")):
                f(f"ressource tierce chargée {ref}")
            continue
        if ref.startswith("/"):
            if not (is404 and ref.startswith("/sentinelle-edr/")): f(f"chemin absolu {ref}"); continue
            local = os.path.join(root, ref[len("/sentinelle-edr/"):])
        else:
            if is404: f(f"404 servie à toute profondeur : chemin relatif interdit {ref}"); continue
            local = os.path.normpath(os.path.join(os.path.dirname(path), ref.split("#")[0].split("?")[0]))
        if os.path.isdir(local): local = os.path.join(local, "index.html")
        if not os.path.exists(local): f(f"lien cassé {ref}")

    low = html.unescape(src).lower()
    for bad in FORBIDDEN:
        if bad in low: f(f"formulation interdite « {bad} »")
    if re.search(r"crowdstrike[^<]{0,80}2024|driver c\+\+", low): f("argument CrowdStrike 2024 / driver C++")
    if "rule_count" in low or "poste-demo" in low: f("donnée du mode démo de la console")
    if p.lang == "fr":
        for line, ctx in p.typo[:5]: f(f"l.{line} espace sécable avant ponctuation (utiliser &nbsp;) : {ctx!r}")
    if is404: return

    # JSON-LD : valide, FAQPage == FAQ visible, aucune note/avis, logiciel identique sur toutes les langues
    ld = re.findall(r'<script type="application/ld\+json">(.*?)</script>', src, re.S)
    if len(ld) != 1: f(f"{len(ld)} bloc(s) JSON-LD (attendu : 1)"); return
    try: g = json.loads(ld[0])["@graph"]
    except Exception as e: f(f"JSON-LD invalide : {e}"); return
    if re.search(r"aggregateRating|\"review\"", ld[0]): f("JSON-LD : note/avis interdits")
    app = [x for x in g if x.get("@type") == "SoftwareApplication"]
    if len(app) != 1 or "inLanguage" in app[0] or app[0].get("url") != "https://pazificateur69.github.io/sentinelle-edr/":
        f("JSON-LD : nœud SoftwareApplication non invariant (url racine, sans inLanguage)")
    faq_ld = next((x["mainEntity"] for x in g if x.get("@type") == "FAQPage"), [])
    vis = re.findall(r'<details class="faq-item">\s*<summary>(.*?)</summary>\s*<div class="faq-a">(.*?)</div>\s*</details>', src, re.S)
    if not vis or len(vis) != len(faq_ld): f(f"FAQ : {len(vis)} visibles / {len(faq_ld)} JSON-LD")
    for (q, a), e in zip(vis, faq_ld):
        if text_of(q) != e["name"] or text_of(a) != e["acceptedAnswer"]["text"]:
            f(f"FAQ JSON-LD différente du visible : {text_of(q)[:60]} (relancer tools/gen_site.py)")
    for s in re.findall(r'<script type="application/json" id="replay-data">(.*?)</script>', src, re.S):
        try: json.loads(s)
        except Exception as e: f(f"replay-data invalide : {e}")

    # Chiffres-clés contre rules.json (source : crates/common/rules.json)
    src_rules = os.path.join(root, "..", "crates", "common", "rules.json")
    rules = json.load(open(src_rules, encoding="utf-8"))
    if open(src_rules, "rb").read() != open(os.path.join(root, "assets", "data", "rules.json"), "rb").read():
        f("assets/data/rules.json diffère de crates/common/rules.json (relancer tools/gen_site.py)")
    v = figures(rules)
    flat = src.replace("\u00a0", " ").replace("&nbsp;", " ")
    for pat in KEYS.get(p.lang, []):
        rx = pat.format(**v)
        if not re.search(rx, flat): f(f"chiffre-clé absent ou périmé : /{rx}/ (rules.json : {v})")
    if len(re.findall(r'<tr(?: class="is-sim")?><th scope="row"><code>SNT-', src)) != v["n"]: f("catalogue : nombre de lignes ≠ rules.json")
    cells = re.findall(r'<i data-rule="SNT-[^"]+" style="--i:\d+"( class="sim")?>', src)
    if len(cells) != v["n"] or sum(bool(c) for c in cells) != v["sim"]: f("grille de vérité ≠ rules.json")
    titles = re.search(r"/\*gen:titles\*/ruleTitles:(\{.*?\})/\*/gen:titles\*/", src, re.S)
    if not titles or set(json.loads(titles.group(1))) != {r["id"] for r in rules}: f("ruleTitles ≠ ids de rules.json")


def main(paths):
    if not paths: sys.exit(__doc__)
    fails = []
    for path in paths: check(path, fails)
    print("ÉCHECS :" if fails else f"OK : {len(paths)} page(s), aucune anomalie", *fails, sep="\n  ")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
