// Sentinelle EDR — site vitrine. Aucune chaîne visible ici : les textes viennent du HTML
// ou de window.SENTINELLE_I18N (une page par langue).
window.__snt = 1;
const I = window.SENTINELLE_I18N || { sev: {} };
const t = (k, v = {}) => {
  let s = I[k] ?? k;
  if (typeof s === 'object') s = s[new Intl.PluralRules(I.lang).select(+v.n || 0)] ?? s.other; // { one, other }
  return String(s).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? '');
};
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const root = document.documentElement;
root.classList.replace('no-js', 'js');
const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
const paused = () => root.dataset.motion === 'paused';
const still = () => RM || paused();
const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };
const IO = 'IntersectionObserver' in window;
const live = el('p', 'sr-only'); live.setAttribute('aria-live', 'polite'); document.body.append(live);
const say = (msg) => { live.textContent = ''; requestAnimationFrame(() => { live.textContent = msg; }); };
// Entrée unique dans la vue : ajoute .play (le CSS n'anime que sous .play ; sans JS, état final).
const onEnter = (els, cb = e => e.classList.add('play'), opt = { threshold: .2 }) => {
  if (!IO) return els.forEach(cb);
  const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { io.unobserve(e.target); cb(e.target); } }), opt);
  els.forEach(e => io.observe(e));
};

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
  $$('main > section').forEach(s => io.observe(s));
}
const menu = $('.nav-menu');
if (menu) {
  const sum = $('summary', menu);
  menu.addEventListener('click', e => { if (e.target.closest('a')) menu.open = false; });
  menu.addEventListener('keydown', e => { if (e.key === 'Escape' && menu.open) { menu.open = false; sum.focus(); } });
  menu.addEventListener('focusout', e => { if (!menu.contains(e.relatedTarget)) menu.open = false; });
}

/* ---------- boucles : actives seulement à l'écran ---------- */
if (IO) {
  const lo = new IntersectionObserver(es => es.forEach(e => e.target.classList.toggle('is-visible', e.isIntersecting)));
  $$('[data-loop],.tile,.term,.stage').forEach(e => lo.observe(e));
}
onEnter($$('.tile,.eq,.sevbar,.truth,.weights'));

/* ---------- la trace : hero (boucle) + rejeu (étapes) ---------- */
const heroFig = $('#hero-stage'), rjFig = $('#rj-stage'), dataEl = $('#replay-data');
let stageRj = null, rjGo = null;
if (dataEl && (heroFig || rjFig)) {
  import('./scene.js').then(({ mountStage }) => {
    const data = JSON.parse(dataEl.textContent);
    if (heroFig) {
      const hero = mountStage(heroFig, data, { mode: 'loop', I });
      const hb = $('#hero-play');
      if (hb) {
        let off = false;
        hb.addEventListener('click', () => {
          off = !off; off ? hero.pause() : hero.play();
          hb.classList.toggle('is-off', off); hb.setAttribute('aria-label', t(off ? 'heroPlay' : 'heroPause'));
        });
        const sync = () => { hb.hidden = still(); };
        sync(); document.addEventListener('snt-motion', sync);
      }
    }
    if (rjFig) { stageRj = mountStage(rjFig, data, { mode: 'steps', I }); if (rjGo) rjGo(); }
  }).catch(() => { /* canvas ou import indisponible : le poster et le HTML (état final) restent */ });
}

/* ---------- rejeu : étapes au scroll, transport, interrupteur Live ---------- */
if (rjFig && dataEl) {
  const states = JSON.parse(dataEl.textContent).states, total = states.length - 1;
  const beats = $$('.beat'), range = $('#rj-range'), time = $('#rj-time'), liveR = $('#rj-live'), play = $('#rj-play');
  let cur = 0, timer = 0, playing = false;
  const go = (s, { announce = false } = {}) => {
    cur = Math.max(0, Math.min(total, s));
    if (stageRj) stageRj.setTarget(cur);
    let b = null; beats.forEach(x => { if (+x.dataset.state <= cur) b = x; });
    beats.forEach(x => x.classList.toggle('cur', x === b));
    rjFig.dataset.state = cur;
    if (range) {
      range.value = cur; time.textContent = states[cur].t;
      const msg = t('step', { n: cur, total, label: states[cur].label });
      range.setAttribute('aria-valuetext', msg);
      if (announce) liveR.textContent = msg;
    }
  };
  rjGo = () => go(cur);
  const stop = () => { clearTimeout(timer); playing = false; play && play.setAttribute('aria-pressed', 'false'); };
  // Lecture demandée (▶) : avance même en pause globale (action explicite), par sauts si figé.
  const tick = () => { timer = setTimeout(() => { go(cur + 1, { announce: true }); if (cur >= total) stop(); else tick(); }, 1100); };
  if (play) {
    play.addEventListener('click', () => { if (playing) return stop(); if (cur >= total) go(0, { announce: true }); playing = true; play.setAttribute('aria-pressed', 'true'); tick(); });
    $('#rj-reset').addEventListener('click', () => { stop(); go(0, { announce: true }); });
    $('#rj-prev').addEventListener('click', () => { stop(); go(cur - 1, { announce: true }); });
    $('#rj-next').addEventListener('click', () => { stop(); go(cur + 1, { announce: true }); });
    range.addEventListener('input', () => { stop(); go(+range.value, { announce: true }); });
  }
  // Le scroll suit : le beat qui franchit la bande centrale devient courant.
  if (IO) {
    const wide = matchMedia('(min-width:1024px)').matches;
    const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { stop(); go(+e.target.dataset.state); } }),
      { rootMargin: wide ? '-45% 0px -45% 0px' : '-62% 0px -28% 0px' });
    beats.forEach(b => io.observe(b));
  }
  go(0);
  const help = $('#live-help');
  $$('#view-switch input').forEach(r => r.addEventListener('change', () => {
    const on = r.value === 'live' && r.checked;
    if (!r.checked) return;
    if (stageRj) stageRj.setLive(on);
    rjFig.classList.toggle('is-live', on);
    if (help) help.hidden = !on;
  }));
}

/* ---------- onglets ARIA génériques ---------- */
$$('[data-tabs]').forEach(box => {
  const tabs = $$('[role=tab]', box), pans = tabs.map(b => document.getElementById(b.getAttribute('aria-controls')));
  const sel = (i, focus) => {
    tabs.forEach((b, j) => { b.setAttribute('aria-selected', String(i === j)); b.tabIndex = i === j ? 0 : -1; pans[j].hidden = i !== j; });
    if (focus) tabs[i].focus();
  };
  tabs.forEach((b, i) => {
    b.addEventListener('click', () => sel(i));
    b.addEventListener('keydown', e => {
      const n = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
      if (n === undefined) return;
      e.preventDefault(); sel((n + tabs.length) % tabs.length, true);
    });
  });
  if (tabs.length) sel(0);
});

/* ---------- tuile 03 : survol d'un fragment = surlignage manuel ---------- */
$$('.codecard').forEach(cc => {
  const show = k => { cc.classList.toggle('manual', !!k); $$('[data-k]', cc).forEach(e => e.classList.toggle('hit', !!k && e.dataset.k === k)); };
  $$('[data-k]', cc).forEach(e => { e.addEventListener('pointerenter', () => show(e.dataset.k)); e.addEventListener('pointerleave', () => show(null)); });
});

/* ---------- tuile 04 : svchost.exe se brouille puis se fixe sur PowerShell.EXE ---------- */
const mask = $('.mask'), mA = $('#mask-a');
if (mask && mA) {
  const a = mA.textContent, b = $('.mask-b', mask).textContent, G = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._', tile = mask.closest('.tile');
  let k = 0;
  setInterval(() => {
    if (still() || !tile.classList.contains('is-visible')) { mask.classList.remove('anim'); mA.textContent = a; return; }
    mask.classList.add('anim');
    k = (k + 1) % 80; // pas de 50 ms → boucle de 4 s
    const q = Math.min(1, Math.max(0, (k - 30) / 10)), lock = Math.floor(q * b.length);
    mA.classList.toggle('fixed', k >= 40);
    mA.textContent = k < 30 ? a : k >= 40 ? b : [...b].map((c, i) => (i < lock ? c : G[(i * 7 + k * 13) % G.length])).join('');
  }, 50);
}

/* ---------- banc d'essai ---------- */
const bench = $('#banc-essai');
if (bench) {
  const f = { img: $('#b-img'), anc: $('#b-anc'), cmd: $('#b-cmd') };
  const out = $('#bench-out'), sum = $('#b-sum'), totalEl = $('#b-total'), list = $('#b-hits'), none = $('#b-none');
  const lesson = $('[data-lesson]', bench), presetBtns = $$('[data-preset]', bench), matrix = $('#matrix');
  const ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  let eng, rules, loading, preset = 'macro', deb = 0, shown = 210, lastEv, cells = [];

  const load = () => loading || (loading = Promise.all([
    import('./engine.js'),
    fetch(new URL('../data/rules.json', import.meta.url)).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); }),
  ]).then(([m, r]) => {
    eng = m; rules = r;
    if (matrix) {
      cells = rules.filter(x => x.kind === 'process_start').map((x, i) => {
        const c = el('i'); c.title = `${x.id} — ${(I.ruleTitles && I.ruleTitles[x.id]) || x.title}`; c.dataset.id = x.id; c.style.setProperty('--i', i); return c;
      });
      matrix.replaceChildren(...cells);
    }
  }, e => {
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
    const r = h.rule, li = el('li', `alert-card sev-${r.severity}${still() ? '' : ' cut'}`);
    const row = el('div', 'ac-row');
    row.append(el('span', `pill sev-${r.severity}`, I.sev[r.severity] || r.severity), el('span', 'rid', r.id));
    const tt = el('span', 'ttps');
    r.attack.forEach(x => { const a = el('a', 'ttp', x); a.href = `https://attack.mitre.org/techniques/${x.replace('.', '/')}/`; tt.append(a); });
    let sc = `${t('score')} ${h.score}`;
    if ((r.confidence ?? 1) < 1) sc += ` · ${t('conf')} ${r.confidence.toLocaleString(I.lang)}`;
    row.append(tt, el('span', 'sc', sc));
    li.append(row, el('p', 'ac-title', (I.ruleTitles && I.ruleTitles[r.id]) || r.title));
    const why = el('div', 'why'), ul = el('ul');
    why.append(el('p', 'side-h', t('why')));
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
    if (still()) { totalEl.textContent = to; return; }
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
    if (!hits.length && wasHidden && !still()) { none.classList.remove('draw'); void none.offsetWidth; none.classList.add('draw'); }
    lesson.hidden = !(preset === lesson.dataset.lesson && !hits.length);
    if (cells.length) {
      const sev = Object.fromEntries(hits.map(h => [h.rule.id, h.rule.severity]));
      cells.forEach(c => { c.className = sev[c.dataset.id] ? `on sev-${sev[c.dataset.id]}` : ''; });
      if (!still()) { matrix.classList.remove('wave'); void matrix.offsetWidth; matrix.classList.add('wave'); }
    }
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
    bench.scrollIntoView({ behavior: still() ? 'auto' : 'smooth' });
    load().then(() => setPreset(m[1])).catch(ok);
  };
  addEventListener('hashchange', fromHash);
  fromHash();
  onEnter([bench], () => load().then(run).catch(ok), { rootMargin: '600px' });

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
      if (!pre) { pre = el('pre', 'jsonl-out'); jb.parentNode.append(pre); }
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
const bento = $('#fonctionnalites');
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

/* ---------- parc : kill + coupure ---------- */
const fleet = $('#fleet');
if (fleet) {
  const dot = $('#kill-dot'), chk = $('#h2 .kchk'), cut = $('#fleet-cut'), st = $('#h3-st');
  const states = $$('.fleet-state [data-s]');
  let tm = [];
  $('#fleet-kill').addEventListener('click', () => {
    chk.classList.remove('on');
    const a = dot.animate([{ transform: 'translate(176px,100px)', opacity: 1 }, { transform: 'translate(118px,100px)', opacity: 1 }],
      { duration: still() ? 1 : 700, easing: 'cubic-bezier(.65,0,.35,1)' });
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
    if (still()) return setState('silent');
    tm = [setTimeout(() => setState('stale'), 2000), setTimeout(() => setState('silent'), 4000)];
  });
}

/* ---------- couverture réelle : ratio qui roule + liste ↔ grille ---------- */
const ratio = $('#ratio-n');
if (ratio && !still()) onEnter([ratio], () => {
  const to = +ratio.textContent, t0 = performance.now();
  const step = now => { const p = Math.min(1, (now - t0) / 600); ratio.textContent = Math.round(to * (1 - (1 - p) ** 3)); if (p < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}, { threshold: .6 });
$$('#sim-list [data-rule]').forEach(li => {
  const cell = $(`#truth [data-rule="${li.dataset.rule}"]`);
  if (!cell) return;
  li.addEventListener('pointerenter', () => cell.classList.add('ring'));
  li.addEventListener('pointerleave', () => cell.classList.remove('ring'));
});
