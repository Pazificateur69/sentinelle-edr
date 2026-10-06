// Sentinelle EDR — site vitrine. Aucune chaîne visible ici : les textes viennent du HTML
// ou de window.SENTINELLE_I18N (une page par langue).
const I = window.SENTINELLE_I18N || { sev: {} };
const t = (k, v = {}) => {
  let s = I[k] ?? k;
  if (typeof s === 'object') s = s[new Intl.PluralRules(I.lang).select(+v.n || 0)] ?? s.other; // { one, other }
  return String(s).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? '');
};
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const root = document.documentElement;
const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
const paused = () => root.dataset.motion === 'paused';
const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };
const IO = 'IntersectionObserver' in window;
const live = el('p', 'sr-only'); live.setAttribute('aria-live', 'polite'); document.body.append(live);
const say = (msg) => { live.textContent = ''; requestAnimationFrame(() => { live.textContent = msg; }); };

/* ---------- pause globale (WCAG 2.2.2) ---------- */
const mt = $('#motion-toggle');
if (mt) {
  mt.setAttribute('aria-pressed', String(paused()));
  mt.addEventListener('click', () => {
    const p = !paused();
    if (p) root.dataset.motion = 'paused'; else delete root.dataset.motion;
    mt.setAttribute('aria-pressed', String(p));
    try { localStorage.setItem('snt-motion', p ? 'paused' : 'on'); } catch (e) { /* stockage indisponible */ }
    document.dispatchEvent(new Event('snt-motion'));
  });
}

/* ---------- nav : verre au scroll + section courante ---------- */
const nav = $('#nav');
if (IO && nav) {
  new IntersectionObserver(([e]) => nav.classList.toggle('scrolled', !e.isIntersecting)).observe($('#top-sentinel'));
  const links = $$('nav a[href^="#"]');
  const io = new IntersectionObserver(es => es.forEach(e => {
    if (!e.isIntersecting) return;
    links.forEach(a => a.getAttribute('href') === '#' + e.target.id ? a.setAttribute('aria-current', 'true') : a.removeAttribute('aria-current'));
  }), { rootMargin: '-45% 0px -50% 0px' });
  // Toutes les sections : une section absente de la nav éteint le lien précédent.
  $$('main > section').forEach(s => io.observe(s));
}
const menu = $('.nav-menu');
if (menu) {
  const sum = $('summary', menu);
  menu.addEventListener('click', e => { if (e.target.closest('a')) menu.open = false; });
  menu.addEventListener('keydown', e => { if (e.key === 'Escape' && menu.open) { menu.open = false; sum.focus(); } });
  menu.addEventListener('focusout', e => { if (!menu.contains(e.relatedTarget)) menu.open = false; });
}

/* ---------- révélations + boucles ---------- */
const revealSel = '.reveal,.eq,.truth,.ratio';
if (!IO || RM) $$(revealSel).forEach(e => e.classList.add('is-in'));
else {
  const io = new IntersectionObserver(es => es.forEach(e => {
    if (e.isIntersecting) { e.target.classList.add('is-in'); io.unobserve(e.target); }
  }), { threshold: 0.25 });
  $$(revealSel).forEach(e => io.observe(e));
}
// Filet de sécurité : le script inline repasse en .no-js si ce module ne s'exécute pas à temps.
window.__snt = 1;
root.classList.replace('no-js', 'js');
if (IO) {
  const lo = new IntersectionObserver(es => es.forEach(e => e.target.classList.toggle('is-visible', e.isIntersecting)));
  $$('[data-loop]').forEach(e => lo.observe(e));
}

/* ---------- hero : fil d'alertes en boucle (14 s) ---------- */
const heroC = $('#hero-console'), heroBtn = $('#hero-play');
if (heroC && !RM) {
  const cards = $$('#hero-feed .alert-card').reverse(); // ordre chronologique
  let k = 0, local = false;
  const tick = () => {
    if (!paused() && !local && heroC.classList.contains('is-visible')) {
      if (k === 0) cards.forEach(c => { c.classList.add('off'); c.classList.remove('in'); });
      if (k < cards.length) { cards[k].classList.remove('off'); cards[k].classList.add('in'); }
      k = (k + 1) % 15;
    }
    setTimeout(tick, 900);
  };
  tick();
  if (heroBtn) {
    heroBtn.addEventListener('click', () => { local = !local; heroBtn.setAttribute('aria-pressed', String(local)); });
    // Pause globale active : le fil est déjà figé, ce bouton local n'a plus d'effet.
    const sync = () => { heroBtn.hidden = paused(); };
    sync(); document.addEventListener('snt-motion', sync);
  }
} else if (heroBtn) heroBtn.hidden = true;

/* ---------- rejeu ---------- */
const scene = $('#scene');
if (scene) {
  const data = JSON.parse($('#replay-data').textContent);
  const ats = $$('[data-at]', scene);
  const feed = $('#feed-list'), inc = $('#inc-cards');
  const cards = $$('.alert-card', feed);
  const strips = $$('.odo-s', scene);
  const steps = $$('#steps li');
  const range = $('#rj-range'), time = $('#rj-time'), liveR = $('#rj-live'), play = $('#rj-play');
  const pan = $('.svg-scroll', scene);
  const PAN = [0, 0, 0, .75, 1, 0, 1, .5]; // < 640 px : partie du schéma à montrer à chaque étape
  const total = data.length - 1;
  let cur = -1, timer = 0, playing = false, userPlay = false;

  const render = (step, { anim = !RM, announce = true } = {}) => {
    step = Math.max(0, Math.min(total, step));
    const fwd = anim && step === cur + 1;
    ats.forEach(e => {
      const on = +e.dataset.at <= step, was = e.classList.contains('on');
      e.classList.toggle('on', on);
      if (e.classList.contains('alert-card')) e.classList.toggle('cut', on && !was && fwd);
    });
    const inIncident = cards[0].parentNode === inc;
    if (step === total && !inIncident) {
      cards.forEach(c => c.classList.remove('cut'));
      const first = cards.map(c => c.getBoundingClientRect());
      cards.forEach(c => inc.append(c));
      if (anim) cards.forEach((c, i) => {
        const l = c.getBoundingClientRect(), f = first[i];
        c.style.willChange = 'transform';
        c.animate([{ transform: `translate(${f.left - l.left}px,${f.top - l.top}px)` }, { transform: 'none' }],
          { duration: 700, easing: 'cubic-bezier(.65,0,.35,1)', delay: i * 60, fill: 'backwards' })
          .finished.then(() => { c.style.willChange = ''; }, () => {});
      });
    } else if (step < total && inIncident) {
      cards.forEach(c => { c.classList.remove('cut'); c.getAnimations().forEach(a => a.cancel()); feed.append(c); });
    }
    String(data[step].score).padStart(3, '0').split('').forEach((d, i) => strips[i].style.setProperty('--d', d));
    steps.forEach((li, i) => { li.classList.toggle('cur', i === step); li.classList.toggle('future', i > step); });
    scene.dataset.step = step;
    range.value = step;
    time.textContent = data[step].t;
    const label = $('.st-title', steps[step]);
    const msg = t('step', { n: step, total, label: label ? label.textContent : '' });
    range.setAttribute('aria-valuetext', msg);
    if (announce) liveR.textContent = msg;
    if (pan && pan.scrollWidth > pan.clientWidth) pan.scrollTo({ left: (PAN[step] ?? 0) * (pan.scrollWidth - pan.clientWidth), behavior: anim ? 'smooth' : 'auto' });
    cur = step;
  };
  const stop = () => { clearTimeout(timer); playing = false; play.setAttribute('aria-pressed', 'false'); };
  // Lecture demandée (▶) : elle avance même en pause globale ; seule elle est annoncée.
  const tick = () => {
    timer = setTimeout(() => {
      render(cur + 1, { announce: userPlay });
      if (cur >= total) stop(); else tick();
    }, 1100);
  };
  const start = (user = true) => { userPlay = user; if (cur >= total) render(0, { announce: user }); playing = true; play.setAttribute('aria-pressed', 'true'); tick(); };

  play.addEventListener('click', () => (playing ? stop() : start()));
  document.addEventListener('snt-motion', () => { if (paused() && !userPlay) stop(); });
  $('#rj-reset').addEventListener('click', () => { stop(); render(0); });
  $('#rj-prev').addEventListener('click', () => { stop(); render(cur - 1); });
  $('#rj-next').addEventListener('click', () => { stop(); render(cur + 1); });
  range.addEventListener('input', () => { stop(); render(+range.value, { anim: false }); });

  if (RM || paused() || !IO) render(total, { anim: false, announce: false });
  else {
    render(0, { anim: false, announce: false });
    // Lecture auto seulement quand le défilement s'arrête sur la scène : traversée pendant un saut
    // d'ancre, elle ferait grandir la scène et repousserait la cible du saut.
    let visible = false, armT = 0;
    const arm = () => {
      clearTimeout(armT);
      armT = setTimeout(() => {
        if (!visible || playing || cur !== 0) return;
        io.disconnect(); removeEventListener('scroll', onScroll);
        if (!paused()) start(false);
      }, 600);
    };
    const onScroll = () => { if (visible) arm(); };
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; if (visible) arm(); }, { threshold: 0.4 });
    io.observe(scene);
    addEventListener('scroll', onScroll, { passive: true });
  }
}

/* ---------- fonctionnement : rail de télémétrie ---------- */
const flow = $('#fonctionnement');
if (flow) {
  const lis = $$('.flow-steps li', flow), nodes = $$('.rail-nodes g', flow);
  const setActive = (n, act = true) => {
    flow.dataset.active = n;
    flow.style.setProperty('--p', (n - 1) / (lis.length - 1));
    nodes.forEach((g, i) => { g.classList.toggle('on', i < n); g.classList.toggle('is-active', act && i === n - 1); });
    lis.forEach((l, i) => l.classList.toggle('is-active', act && i === n - 1));
    flow.classList.toggle('hot', n >= 4);
  };
  if (RM || !IO) setActive(lis.length, false);
  else {
    setActive(1);
    const io = new IntersectionObserver(es => es.forEach(e => e.isIntersecting && setActive(+e.target.dataset.step)),
      { rootMargin: '-45% 0px -45% 0px' });
    lis.forEach(l => io.observe(l));
  }
}

/* ---------- anatomie d'une règle : annotations ---------- */
const rule = $('#regle');
if (rule) {
  const btns = $$('[data-hl]', rule);
  const show = k => {
    $$('[data-k].hit', rule).forEach(e => e.classList.remove('hit'));
    btns.forEach(b => b.classList.toggle('hit', b.dataset.hl === k));
    if (k) $$(`[data-k~="${k}"]`, rule).forEach(e => e.classList.add('hit'));
  };
  btns.forEach(b => {
    const k = b.dataset.hl;
    b.addEventListener('pointerenter', () => show(k));
    b.addEventListener('pointerleave', e => { if (e.pointerType === 'mouse') show(null); });
    b.addEventListener('focus', () => show(k));
    b.addEventListener('blur', () => show(null));
    b.addEventListener('click', () => show(k));
  });
}

/* ---------- banc d'essai ---------- */
const bench = $('#banc-essai');
if (bench) {
  const f = { img: $('#b-img'), anc: $('#b-anc'), cmd: $('#b-cmd') };
  const out = $('#bench-out'), sum = $('#b-sum'), totalEl = $('#b-total'), list = $('#b-hits'), none = $('#b-none');
  const lesson = $('[data-lesson]', bench), presetBtns = $$('[data-preset]', bench);
  const ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  let eng, rules, loading, preset = 'macro', deb = 0, shown = 210, lastEv;

  const load = () => loading || (loading = Promise.all([
    import('./engine.js'),
    fetch(new URL('../data/rules.json', import.meta.url)).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); }),
  ]).then(([m, r]) => { eng = m; rules = r; }, e => {
    loading = null; // un prochain essai relancera le chargement
    list.replaceChildren(); none.hidden = true; out.dataset.max = 'none'; sum.textContent = t('loadErr');
    throw e;
  }));
  const ok = () => {}; // erreur déjà affichée dans #b-sum

  const display = (ev, field) => {
    if (field === 'CommandLine') return ev.commandLine;
    if (field === 'Image' || field === 'ImageName') return ev.image;
    if (field === 'ParentImage' || field === 'ParentImageName') return ev.ancestors[0];
    if (field === 'lineage') return ev.ancestors.join(', ');
    return '';
  };
  const markInto = (node, s, w) => {
    const L = eng.lo(s), V = eng.lo(w.value);
    const i = w.op === 'ends_with' || /Name$|lineage/.test(w.field) ? L.lastIndexOf(V) : L.indexOf(V);
    if (i < 0 || !V) { node.textContent = s; return; }
    node.append(document.createTextNode(s.slice(0, i)), el('mark', null, s.slice(i, i + V.length)), document.createTextNode(s.slice(i + V.length)));
  };
  const card = (h, ev) => {
    const r = h.rule, li = el('li', `alert-card sev-${r.severity}${RM ? '' : ' cut'}`);
    const row = el('div', 'ac-row');
    row.append(el('span', `pill sev-${r.severity}`, I.sev[r.severity] || r.severity), el('span', 'rid', r.id));
    const tt = el('span', 'ttps');
    r.attack.forEach(x => { const a = el('a', 'ttp', x); a.href = `https://attack.mitre.org/techniques/${x.replace('.', '/')}/`; tt.append(a); });
    let sc = `${t('score')} ${h.score}`;
    if ((r.confidence ?? 1) < 1) sc += ` · ${t('conf')} ${r.confidence.toLocaleString(I.lang)}`;
    row.append(tt, el('span', 'sc', sc));
    li.append(row, el('p', 'ac-title', (I.ruleTitles && I.ruleTitles[r.id]) || r.title));
    const why = el('div', 'why'), ul = el('ul');
    why.append(el('p', 'hud', t('why')));
    h.why.forEach(w => {
      const it = el('li');
      it.append(el('code', null, `${w.field} ${w.op} "${w.value}"`));
      const s = display(ev, w.field);
      if (s) { const v = el('span', 'why-v'); markInto(v, s, w); it.append(v); }
      ul.append(it);
    });
    why.append(ul); li.append(why);
    return li;
  };
  const rollTo = (to) => {
    const from = shown; shown = to;
    if (RM) { totalEl.textContent = to; return; }
    const t0 = performance.now();
    const step = (now) => {
      const p = Math.min(1, (now - t0) / 400), e = 1 - Math.pow(1 - p, 3);
      totalEl.textContent = Math.round(from + (to - from) * e);
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };
  const run = () => {
    if (!eng) return;
    const ev = eng.toEvent(f.img.value, f.anc.value, f.cmd.value);
    lastEv = ev;
    const hits = eng.evaluate(rules, ev);
    list.replaceChildren(...hits.map(h => card(h, ev)));
    const counts = {};
    hits.forEach(h => { counts[h.rule.severity] = (counts[h.rule.severity] || 0) + 1; });
    const parts = ORDER.filter(s => counts[s]).map(s => `${counts[s]} ${I.sev[s] || s}`);
    sum.textContent = hits.length ? `${t('hits', { n: hits.length })}${t('sep')}${parts.join(', ')}` : t('none');
    out.dataset.max = ORDER.find(s => counts[s]) || 'none';
    rollTo(hits.reduce((a, h) => a + h.score, 0));
    const wasHidden = none.hidden;
    none.hidden = hits.length > 0;
    if (!hits.length && wasHidden && !RM) { none.classList.remove('draw'); void none.offsetWidth; none.classList.add('draw'); }
    lesson.hidden = !(preset === lesson.dataset.lesson && !hits.length);
  };
  const setPreset = (k) => {
    if (!eng || !eng.PRESETS[k]) return;
    preset = k;
    [f.img.value, f.anc.value, f.cmd.value] = eng.PRESETS[k];
    presetBtns.forEach(b => b.setAttribute('aria-pressed', String(b.dataset.preset === k)));
    run();
  };
  presetBtns.forEach(b => b.addEventListener('click', () => load().then(() => setPreset(b.dataset.preset)).catch(ok)));
  $$('[data-preset-link]').forEach(a => a.addEventListener('click', () => load().then(() => setPreset(a.dataset.presetLink)).catch(ok)));
  $('#bench-form').addEventListener('submit', e => e.preventDefault());
  Object.values(f).forEach(i => i.addEventListener('input', () => {
    preset = null;
    presetBtns.forEach(b => b.setAttribute('aria-pressed', 'false'));
    clearTimeout(deb);
    deb = setTimeout(() => load().then(run).catch(ok), 150);
  }));
  const fromHash = () => {
    const m = /^#banc-essai\?preset=(\w+)/.exec(location.hash);
    if (!m) return;
    bench.scrollIntoView({ behavior: RM ? 'auto' : 'smooth' });
    load().then(() => setPreset(m[1])).catch(ok);
  };
  addEventListener('hashchange', fromHash);
  fromHash();
  if (IO) {
    const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { io.disconnect(); load().then(run).catch(ok); } }, { rootMargin: '600px' });
    io.observe(bench);
  } else load().then(run).catch(ok);

  const jb = $('#b-jsonl'), js = $('#b-jsonl-s');
  jb && jb.addEventListener('click', () => {
    const ev = lastEv || { image: f.img.value.trim(), commandLine: f.cmd.value.trim(), ancestors: f.anc.value.split(',').map(s => s.trim()).filter(Boolean) };
    const chain = [...ev.ancestors].reverse().concat(ev.image).filter(Boolean);
    const t0 = Date.now();
    const lines = chain.map((img, i) => {
      const o = { ts: new Date(t0 + i * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'), host: 'banc-essai', kind: 'process_start', pid: 1000 + i, ppid: i ? 999 + i : 0, image: img };
      if (i === chain.length - 1 && ev.commandLine) o.command_line = ev.commandLine;
      return JSON.stringify(o);
    });
    const text = lines.join('\n');
    copyText(text, null).then(done => {
      if (done) { js.textContent = t('copied'); setTimeout(() => { js.textContent = ''; }, 1600); return; }
      // Presse-papiers refusé : on affiche les lignes et on les sélectionne.
      let pre = $('pre.jsonl-out', jb.parentNode);
      if (!pre) { pre = el('pre', 'insp jsonl-out'); jb.parentNode.append(pre); }
      pre.textContent = text; selectNode(pre); js.textContent = t('selected');
    });
  });
}

/* ---------- copier ---------- */
function selectNode(node) { const r = document.createRange(); r.selectNodeContents(node); const s = getSelection(); s.removeAllRanges(); s.addRange(r); }
async function copyText(text, pre) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch (e) { if (pre) selectNode(pre); return false; }
}
$$('.cmd').forEach(c => {
  const b = $('.copy', c), pre = $('pre', c), l = $('.copy-l', c);
  if (!b) return;
  b.addEventListener('click', () => copyText(pre.textContent, pre).then(ok => {
    if (!ok) { l.textContent = t('copy'); say(t('selected')); return; }
    l.textContent = t('copied'); b.classList.add('done'); say(t('copied'));
    setTimeout(() => { l.textContent = t('copy'); b.classList.remove('done'); }, 1600);
  }));
});

/* ---------- bento : spotlight ---------- */
const bento = $('#bento');
if (bento && !RM && matchMedia('(hover:hover) and (pointer:fine)').matches) {
  let raf = 0, last;
  bento.addEventListener('pointermove', e => {
    last = e;
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      const tile = last.target.closest('.tile');
      if (!tile) return;
      const r = tile.getBoundingClientRect();
      tile.style.setProperty('--mx', `${last.clientX - r.left}px`);
      tile.style.setProperty('--my', `${last.clientY - r.top}px`);
    });
  });
}

/* ---------- multi-OS : rejouer les traces ---------- */
const osBtn = $('#os-replay');
osBtn && osBtn.addEventListener('click', () => $$('.os-col').forEach(c => {
  c.classList.add('re'); void c.offsetWidth; c.classList.remove('re');
}));

/* ---------- parc : kill + coupure ---------- */
const fleet = $('#fleet');
if (fleet) {
  const dot = $('#kill-dot'), chk = $('#h2 .kchk'), cut = $('#fleet-cut'), st = $('#h3-st');
  const states = $$('.fleet-state [data-s]');
  let tm = [];
  $('#fleet-kill').addEventListener('click', () => {
    chk.classList.remove('on');
    const a = dot.animate([{ transform: 'translate(262px,150px)', opacity: 1 }, { transform: 'translate(170px,150px)', opacity: 1 }],
      { duration: RM ? 1 : 700, easing: 'cubic-bezier(.65,0,.35,1)' });
    a.finished.then(() => { void chk.getBoundingClientRect(); chk.classList.add('on'); say(t('killed')); }, () => {});
  });
  const setState = s => {
    st.classList.toggle('stale', s === 'stale'); st.classList.toggle('silent', s === 'silent');
    states.forEach(x => { x.hidden = x.dataset.s !== s; });
  };
  cut.addEventListener('click', () => {
    const on = cut.getAttribute('aria-pressed') !== 'true';
    cut.setAttribute('aria-pressed', String(on));
    tm.forEach(clearTimeout); tm = [];
    fleet.classList.toggle('cut3', on);
    if (!on) return setState('live');
    if (RM) return setState('silent');
    tm = [setTimeout(() => setState('stale'), 2000), setTimeout(() => setState('silent'), 4000)];
  });
}

/* ---------- couverture réelle : liste ↔ grille (survol souris seulement : la liste porte déjà l'info) ---------- */
$$('#sim-list [data-rule]').forEach(li => {
  const cell = $(`#truth [data-rule="${li.dataset.rule}"]`);
  if (!cell) return;
  li.addEventListener('pointerenter', () => cell.classList.add('ring'));
  li.addEventListener('pointerleave', () => cell.classList.remove('ring'));
});
