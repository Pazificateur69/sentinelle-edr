// « La trace » : le scénario captures/demo.jsonl dessiné en Canvas 2D. Tout est fonction d'un seul
// temps de scène T (secondes) : figer T fige tout (pause WCAG), poser T donne l'image exacte.
import { WEIGHT } from './engine.js';

const cl = (v, a = 0, b = 1) => Math.max(a, Math.min(b, v));
const eo = p => 1 - (1 - p) ** 3;
const pop = p => 1 + 2.7 * (p - 1) ** 3 + 1.7 * (p - 1) ** 2;
const LOOP = 12, CORR = 7.6, FADE0 = 10.6, REST = 9;
const at = s => 0.6 + s;
export const targetT = s => (s < 7 ? 0.6 + s + 0.9 : 8.6);
const SEVC = { critical: '--crit', high: '--high', medium: '--med', low: '--low', info: '--info' };
const GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._';
const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
const paused = () => document.documentElement.dataset.motion === 'paused';

// Alertes horodatées (rang dans la seconde → décalage de 150 ms), score et tactiques à l'instant T.
export function timeline(data) {
  const per = {};
  return data.alerts.map((a, i) => { const k = per[a.t] = (per[a.t] ?? -1) + 1; return { ...a, i, k, ta: at(a.t) + 0.15 * (k + 1) }; });
}
export function stateAt(al, T, live) {
  const on = al.filter(a => a.ta <= T), cnt = on.filter(a => !(live && a.sim));
  return { n: on.length, score: cnt.reduce((s, a) => s + WEIGHT[a.sev], 0), tacs: new Set(cnt.flatMap(a => a.tac)) };
}

export function mountStage(fig, data, { mode = 'loop', I = {} } = {}) {
  const wrap = fig.querySelector('.stage-canvas'), cv = wrap.querySelector('canvas');
  const ctx = cv.getContext('2d');
  if (!ctx) throw new Error('canvas 2d');
  const css = getComputedStyle(document.documentElement), v = n => css.getPropertyValue(n).trim();
  const C = { txt: v('--txt'), ink: v('--ink-2'), mut: v('--muted'), acc: v('--accent'), info: v('--info'), bg: v('--surface-1') };
  const sevC = s => v(SEVC[s]);
  const rgba = (hex, a) => { const n = parseInt(hex.slice(1), 16); return `rgba(${n >> 16},${n >> 8 & 255},${n & 255},${a})`; };
  const al = timeline(data), rows = data.rows, R = Object.fromEntries(rows.map((r, i) => [r.id, i]));
  if (!mountStage.ok) {
    mountStage.ok = 1;
    const chk = (live, exp) => exp.every((v, s) => stateAt(al, targetT(s), live).score === v);
    console.assert(chk(false, [0, 0, 210, 310, 380, 450, 520, 520]) && chk(true, [0, 0, 210, 210, 210, 210, 280, 280]) &&
      stateAt(al, targetT(7), false).tacs.size === 5 && stateAt(al, targetT(7), true).tacs.size === 2, 'trace : scores du scénario');
  }
  const lis = [...fig.querySelectorAll('.al-list li')], segs = [...fig.querySelectorAll('.compo i')];
  const tacEls = [...fig.querySelectorAll('.tacs li')], sc = fig.querySelector('.sc-n'), sum = fig.querySelector('.inc-sum');
  const strips = [...fig.querySelectorAll('.odo-s')];
  const MONO = '"Geist Mono",ui-monospace,monospace';

  // sprites de halo et motifs hachurés, un par couleur
  const cache = {};
  const halo = col => cache['h' + col] || (cache['h' + col] = (() => {
    const c = document.createElement('canvas'); c.width = c.height = 64; const g = c.getContext('2d');
    const r = g.createRadialGradient(32, 32, 0, 32, 32, 32); r.addColorStop(0, rgba(col, .55)); r.addColorStop(1, rgba(col, 0));
    g.fillStyle = r; g.fillRect(0, 0, 64, 64); return c;
  })());
  const hatch = col => cache['p' + col] || (cache['p' + col] = (() => {
    const c = document.createElement('canvas'); c.width = c.height = 6; const g = c.getContext('2d');
    g.strokeStyle = col; g.lineWidth = 1.6; g.beginPath(); g.moveTo(-1, 7); g.lineTo(7, -1); g.stroke(); return ctx.createPattern(c, 'repeat');
  })());

  let cw = 0, ch = 0, dpr = 1, port = false, X, Y, NX, dots = null, dotPath = null, bg = null, tgt = [], slow = 0, noDots = false;
  let T = mode === 'loop' ? (RM || paused() ? REST : 2.4) : targetT(0), target = T, liveK = 0, liveTo = 0;
  let raf = 0, last = 0, visible = false, local = false, shown = null, key = '';

  function layout() {
    cw = Math.round(wrap.clientWidth); port = cw < 640;
    wrap.classList.toggle('is-portrait', port);
    ch = Math.round(wrap.clientHeight);
    if (!cw || !ch) return false;
    dpr = Math.min(devicePixelRatio || 1, 2);
    cv.width = cw * dpr; cv.height = ch * dpr;
    if (port) {
      const depth = [0, 1, 2, 3, 3, 3];
      X = () => 0; Y = i => 30 + i * Math.min(44, (ch - 50) / 5); NX = i => 18 + depth[i] * 20;
    } else {
      const span = (cw - 56 - 16 - 150) / 6, rh = (ch - 100) / 5;
      X = s => 44 + s * span; Y = i => 60 + i * rh; NX = i => X(rows[i].t);
    }
    // champ de points (≥ 480 px) : positions précalculées + chemin de base mis en cache
    dots = null; dotPath = null;
    if (cw >= 480 && !noDots) {
      const p = []; for (let y = 12; y < ch; y += 24) for (let x = 12; x < cw; x += 24) p.push(x, y);
      dots = new Float32Array(p); dotPath = new Path2D();
      for (let j = 0; j < dots.length; j += 2) dotPath.rect(dots[j] - .6, dots[j + 1] - .6, 1.2, 1.2);
    }
    // fond : graduations du temps (paysage)
    bg = document.createElement('canvas'); bg.width = cv.width; bg.height = cv.height;
    const b = bg.getContext('2d'); b.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (!port) {
      b.font = `10px ${MONO}`; b.textAlign = 'center'; b.textBaseline = 'middle';
      for (let s = 0; s <= 6; s++) {
        const x = X(s); b.fillStyle = 'rgba(120,140,190,.08)'; b.fillRect(x - .5, 32, 1, ch - 44);
        b.fillStyle = C.mut; b.fillText(data.states[s].t, x, 16); b.fillRect(x - .5, 26, 1, 4);
      }
    }
    targets();
    return true;
  }
  // cibles des fils de corrélation : chaque li de la carte Incident, ramenée au bord du canvas
  function targets() {
    const cr = cv.getBoundingClientRect();
    // li sans boîte (liste masquée) ou sous le canvas : pas de fil (sinon écheveau ou coin haut-gauche)
    tgt = lis.map(li => { const r = li.getBoundingClientRect(), cy = r.top + r.height / 2 - cr.top; return r.width && cy <= ch ? [cl(r.left - cr.left, 8, cw - 2), cl(cy, 8, ch - 2)] : null; });
  }

  const rowPos = i => [NX(i), Y(i)];
  const tickPos = a => {
    const i = R[a.row];
    if (!port) return [X(a.t) + 14 * (a.k + 1), Y(i)];
    const same = al.filter(b => b.row === a.row), j = same.indexOf(a);
    return [cw - 16 - 14 * (same.length - 1 - j), Y(i)];
  };
  // coude de lignée tracé jusqu'à la fraction p de sa longueur
  function elbow(xv, y1, y2, xe, p) {
    const lv = Math.max(0, y2 - 8 - y1), la = 12.6, lh = Math.max(0, xe - xv - 8), d = p * (lv + la + lh);
    ctx.beginPath(); ctx.moveTo(xv, y1); ctx.lineTo(xv, y1 + Math.min(d, lv));
    if (d > lv) ctx.quadraticCurveTo(xv, y2, xv + 8, y2);
    if (d > lv + la) ctx.lineTo(xv + 8 + Math.min(d - lv - la, lh), y2);
    ctx.stroke();
  }
  const font = (w, s) => { ctx.font = `${w} ${s}px ${MONO}`; };
  // étiquette avec halo couleur du fond (jamais barrée par un trait) ; pointillé coupé pour le halo
  const lab = (s, x, y) => { ctx.save(); ctx.setLineDash([]); ctx.lineJoin = 'round'; ctx.lineWidth = 4; ctx.strokeStyle = C.bg; ctx.strokeText(s, x, y); ctx.restore(); ctx.fillText(s, x, y); };
  const scramble = (a, b, q, seed) => {
    const n = Math.round(a.length + (b.length - a.length) * q), lock = Math.floor(q * b.length);
    let s = ''; for (let i = 0; i < n; i++) s += i < lock ? b[i] : GLYPHS[(i * 7 + seed * 13) % GLYPHS.length];
    return s;
  };

  function draw() {
    const sim = 1 - .75 * liveK, fadeA = mode === 'loop' && T > FADE0 ? cl(1 - (T - FADE0) / .8) : 1;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, cw, ch);
    ctx.lineCap = 'round';
    const rev = mode === 'loop' ? eo(cl(T / .6)) : 1;
    if (!port && rev > 0) { ctx.save(); ctx.globalAlpha = fadeA; ctx.beginPath(); ctx.rect(0, 0, cw * rev, ch); ctx.clip(); ctx.drawImage(bg, 0, 0, cw, ch); ctx.restore(); }
    // champ de points + ondes
    if (dots) {
      ctx.fillStyle = C.ink; ctx.globalAlpha = .09 * fadeA * rev; ctx.fill(dotPath);
      for (const a of al) {
        const age = T - a.ta; if (age < 0 || age > .9) continue;
        const [ox, oy] = tickPos(a), r = age * 620, k = .5 * (1 - age / .9) * fadeA * (a.sim ? sim : 1);
        ctx.fillStyle = a.sim ? C.info : sevC(a.sev);
        for (let j = 0; j < dots.length; j += 2) {
          const d = Math.hypot(dots[j] - ox, dots[j + 1] - oy), w = k * Math.max(0, 1 - Math.abs(d - r) / 40);
          if (w > .01) { ctx.globalAlpha = w; ctx.fillRect(dots[j] - 1, dots[j + 1] - 1, 2, 2); }
        }
      }
    }
    ctx.globalAlpha = fadeA;
    const p = cl(T - .6, 0, 6), head = port ? cw : X(p) + (T > 6.6 ? 44 * eo(cl((T - 6.6) / .4)) : 0);
    // tête de lecture et fils de corrélation : sous les étiquettes (qui portent un halo)
    // tête de lecture
    if (!port && T > .6) {
      const pa = fadeA * (T < CORR ? 1 : cl(1 - (T - CORR) / .6)), x = X(p);
      if (pa > 0) {
        ctx.save(); ctx.globalAlpha = pa;
        let g = ctx.createLinearGradient(x - 20, 0, x + 20, 0); g.addColorStop(0, rgba(C.acc, 0)); g.addColorStop(.5, rgba(C.acc, .07)); g.addColorStop(1, rgba(C.acc, 0));
        ctx.fillStyle = g; ctx.fillRect(x - 20, 30, 40, ch - 40);
        g = ctx.createLinearGradient(0, 30, 0, ch - 10); g.addColorStop(0, rgba(C.acc, .5)); g.addColorStop(1, rgba(C.acc, 0));
        ctx.fillStyle = g; ctx.fillRect(x - .75, 30, 1.5, ch - 40);
        ctx.fillStyle = C.acc; ctx.beginPath(); ctx.arc(x, 28, 2.5, 0, 7); ctx.fill(); ctx.restore();
      }
    }
    // fils de corrélation vers la carte Incident
    if (!port && T >= CORR && T < CORR + 1.2) targets();
    if (!port && T >= CORR) al.forEach((a, j) => {
      const q = eo(cl((T - CORR - .05 * j) / .5)); if (q <= 0 || !tgt[j]) return;
      const [x1, y1] = tickPos(a), [x2, y2] = tgt[j], len = Math.hypot(x2 - x1, y2 - y1) * 1.25;
      ctx.save(); ctx.globalAlpha = fadeA * .75 * (a.sim ? sim * .7 : 1); ctx.strokeStyle = sevC(a.sev); ctx.lineWidth = 1.2;
      ctx.setLineDash([len * q, len]);
      ctx.beginPath(); ctx.moveTo(x1, y1);
      ctx.bezierCurveTo(x1 + (x2 - x1) * .5, y1, x2 - (x2 - x1) * .35, y2, x2, y2);
      ctx.stroke(); ctx.restore();
    });
    // lignes de vie
    if (!port) rows.forEach((r, i) => {
      const x0 = NX(i), y = Y(i); if (T < at(r.t) || head <= x0) return;
      ctx.save(); ctx.lineWidth = 1.5;
      if (r.target) { ctx.setLineDash([3, 5]); ctx.strokeStyle = rgba(C.mut, .7); ctx.globalAlpha = fadeA * sim; }
      else {
        const hot = al.filter(a => a.row === r.id && a.ta <= T && !(liveK > .5 && a.sim));
        const g = ctx.createLinearGradient(x0, 0, head, 0); g.addColorStop(0, 'rgba(150,170,210,.35)');
        g.addColorStop(1, hot.length ? rgba(sevC(hot.sort((m, n) => WEIGHT[n.sev] - WEIGHT[m.sev])[0].sev), .8) : 'rgba(150,170,210,.35)');
        ctx.strokeStyle = g;
      }
      ctx.beginPath(); ctx.moveTo(x0 + 6, y); ctx.lineTo(head, y); ctx.stroke(); ctx.restore();
    });
    // coudes de lignée (evil.exe : parent déclaré, barré, puis parent réel)
    ctx.lineWidth = 1.5;
    rows.forEach((r, i) => {
      if (!r.parent) return;
      const t0 = at(r.t); if (T < t0) return;
      const [xn, y] = rowPos(i), pi = R[r.parent], xv = port ? NX(pi) : xn - 14, y1 = Y(pi) + (port ? 6 : 0);
      ctx.save();
      if (r.real) {
        const lie = cl((T - t0 - .3) / .2);
        ctx.strokeStyle = lie > 0 ? rgba(sevC('critical'), .6) : rgba(C.ink, .7); if (lie > 0) ctx.setLineDash([2, 4]);
        elbow(xv, y1, y, xn - 6, eo(cl((T - t0) / .25)));
        if (lie > 0) {
          // « ✕ parent déclaré » en rouge, empilé au-dessus de « parent réel », juste au-dessus d'evil.exe
          const my = port ? (Y(1) + Y(2)) / 2 : (Y(R[r.real] + 1) + y) / 2 - 12;
          ctx.globalAlpha = fadeA * lie; ctx.fillStyle = sevC('critical'); font(500, 10); ctx.textBaseline = 'middle';
          ctx.textAlign = port ? 'left' : 'right'; lab('✕ ' + (I.declared || ''), port ? xv + 6 : xn - 36, my);
        }
        const rp = cl((T - t0 - .5) / .25);
        if (rp > 0) {
          const ri = R[r.real], xr = port ? NX(ri) : xn - 30;
          ctx.setLineDash([2, 4]); ctx.globalAlpha = fadeA * .85 * sim; ctx.strokeStyle = C.ink;
          elbow(xr, Y(ri) + (port ? 6 : 0), y, xn - 6, eo(rp));
          if (!port && rp >= 1) { ctx.fillStyle = C.ink; ctx.textAlign = 'right'; lab(I.real || '', xr - 6, (Y(ri + 1) + y) / 2); }
        }
      } else { ctx.strokeStyle = 'rgba(180,195,225,.55)'; elbow(xv, y1, y, xn - 6, eo(cl((T - t0) / .25))); }
      ctx.restore();
    });
    // marques simulation-seulement : accès LSASS, tube nommé
    for (const m of data.marks) {
      const q = cl((T - at(m.t)) / .3); if (q <= 0) continue;
      ctx.save(); ctx.globalAlpha = fadeA * sim * q; ctx.strokeStyle = C.info; ctx.setLineDash([3, 4]); ctx.lineWidth = 1.3;
      font(400, 10); ctx.fillStyle = C.mut; ctx.textBaseline = 'middle'; ctx.textAlign = 'left';
      if (m.kind === 'access') {
        const [x1, y1] = rowPos(R[m.from]), [x2, y2] = rowPos(R[m.to]), bx = port ? x2 + 4 : X(m.t) + 52;
        const sx = port ? x1 : X(m.t);
        ctx.beginPath(); ctx.moveTo(sx, y1 + 4); ctx.quadraticCurveTo(bx, (y1 + y2) / 2, x2 + 5, y2 - 3); ctx.stroke();
        if (!port) lab(m.label, X(m.t) + 34, (y1 + y2) / 2 - 2);
      } else {
        const y = Y(R[m.row]), x = port ? cw - 16 - 14 * 4 - 12 : X(m.t), s = 5 * pop(q);
        ctx.beginPath(); ctx.moveTo(x, y - s); ctx.lineTo(x + s, y); ctx.lineTo(x, y + s); ctx.lineTo(x - s, y); ctx.closePath();
        ctx.fillStyle = 'rgba(7,10,18,.9)'; ctx.fill(); ctx.stroke();
        if (!port) { ctx.fillStyle = C.mut; lab(m.label, x + 10, y + 16); }
      }
      ctx.restore();
    }
    // nœuds + étiquettes
    rows.forEach((r, i) => {
      const t0 = at(r.t), q = cl((T - t0) / .3); if (q <= 0) return;
      const [x, y] = rowPos(i), s = pop(q);
      ctx.save(); ctx.globalAlpha = fadeA * (r.target ? sim : 1);
      if (r.target) { ctx.setLineDash([2, 3]); ctx.strokeStyle = C.mut; ctx.lineWidth = 1.3; ctx.beginPath(); ctx.arc(x, y, 5 * s, 0, 7); ctx.stroke(); }
      else { ctx.drawImage(halo(C.acc), x - 16, y - 16, 32, 32); ctx.fillStyle = '#fff'; ctx.beginPath(); ctx.arc(x, y, 4.5 * s, 0, 7); ctx.fill(); }
      // svchost.exe → brouillage 500 ms → PowerShell.EXE (pas de brouillage figé ou réduit)
      let name = r.name, sub = r.sub;
      if (r.alias) {
        const sq = cl((T - t0 - .25) / .5);
        if (sq >= 1) { name = r.alias; sub = r.aliasSub; } else if (sq > 0 && !RM) name = scramble(r.name, r.alias, sq, Math.floor(T * 24));
      }
      ctx.globalAlpha *= q; ctx.textBaseline = 'middle'; ctx.textAlign = 'left';
      font(500, 12); const nw = ctx.measureText(name).width; font(400, 10); const sw = ctx.measureText(sub).width;
      const lx = x + 10, ly = port ? y : y - 12;
      const own = al.filter(a => a.row === r.id), lim = !port ? cw - 8 : r.id === 'ps' ? cw - 96 : own.length ? tickPos(own[0])[0] - 10 : cw - 8;
      const showSub = !port || lx + nw + 8 + sw <= lim;
      const below = !port && lx + nw + 8 + sw > cw - 8; // trop long : la sub passe sous la ligne de vie
      font(500, 12); ctx.fillStyle = r.alias && name === r.alias ? C.acc : C.txt; lab(name, lx, ly);
      if (showSub) { font(400, 10); ctx.fillStyle = C.mut; if (below) lab(sub, lx, y + 13); else lab(sub, lx + nw + 8, ly + 1); }
      ctx.restore();
    });
    // tics d'alerte + anneaux d'allumage
    for (const a of al) {
      const age = T - a.ta; if (age < 0) continue;
      const [x, y] = tickPos(a), col = sevC(a.sev), s = pop(cl(age / .25));
      ctx.save(); ctx.globalAlpha = fadeA * (a.sim ? sim : 1);
      if (age < .7) {
        ctx.globalAlpha *= 1 - age / .7; ctx.strokeStyle = col; ctx.lineWidth = 1.5; if (a.sim) ctx.setLineDash([3, 3]);
        ctx.beginPath(); ctx.arc(x, y, 3 + 25 * eo(age / .7), 0, 7); ctx.stroke(); ctx.globalAlpha = fadeA * (a.sim ? sim : 1);
      }
      if (!a.sim) ctx.drawImage(halo(col), x - 12, y - 12, 24, 24);
      ctx.beginPath(); ctx.arc(x, y, 3.5 * s, 0, 7);
      if (a.sim) { ctx.fillStyle = hatch(col); ctx.fill(); ctx.setLineDash([2, 2]); ctx.strokeStyle = col; ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(x, y, 5.5 * s, 0, 7); ctx.stroke(); }
      else { ctx.fillStyle = col; ctx.fill(); }
      ctx.restore();
    }
  }

  // HTML piloté par T : on ne touche le DOM que sur changement
  function sync() {
    const fading = mode === 'loop' && T >= FADE0, live = liveTo > 0;
    const s = fading ? { n: 0, score: 0, tacs: new Set() } : stateAt(al, T, live), corr = !fading && T >= CORR;
    const k = [s.n, s.score, [...s.tacs].join(), corr, live].join('|'); if (k === key) return; key = k;
    lis.forEach((li, i) => li.classList.toggle('on', i < s.n));
    segs.forEach((g, i) => g.classList.toggle('on', i < s.n));
    tacEls.forEach(li => li.classList.toggle('on', s.tacs.has(li.dataset.tac)));
    fig.classList.toggle('is-corr', corr);
    if (sum) sum.textContent = live ? I.liveSum : I.demoSum;
    if (strips.length) String(s.score).padStart(3, '0').split('').forEach((d, i) => strips[i].style.setProperty('--d', d));
    if (sc) roll(s.score);
  }
  function roll(to) {
    const from = shown ?? to; shown = to;
    if (RM || paused() || from === to) { sc.textContent = to; return; }
    const t0 = performance.now(), step = now => {
      const q = cl((now - t0) / 400); sc.textContent = Math.round(from + (to - from) * eo(q)); if (q < 1 && shown === to) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  const frozen = () => RM || paused() || local;
  const wants = () => visible && document.visibilityState === 'visible' && !frozen() &&
    (mode === 'loop' || T !== target || liveK !== liveTo);
  function render() {
    if ((!cw || Math.min(devicePixelRatio || 1, 2) !== dpr) && !layout()) return;
    draw(); sync(); if (!fig.classList.contains('is-live-canvas')) fig.classList.add('is-live-canvas');
  }
  function frame(now) {
    raf = 0;
    const dt = Math.min((now - last) / 1000, .05); last = now;
    const f0 = performance.now();
    if (mode === 'loop') { T += dt; if (T >= LOOP) T -= LOOP; }
    else if (T !== target) T = T < target ? Math.min(target, T + dt) : target;
    if (liveK !== liveTo) liveK = liveTo > liveK ? Math.min(1, liveK + dt / .4) : Math.max(0, liveK - dt / .4);
    render();
    // dégradation : 30 images lentes d'affilée → plus de champ de points
    if (performance.now() - f0 > 24) { if (++slow >= 30 && dots) { noDots = true; layout(); } } else slow = 0;
    kick();
  }
  function kick() { if (!raf && wants()) { last = performance.now(); raf = requestAnimationFrame(frame); } }
  // Figé (pause, mouvement réduit) : jamais d'image vide ni à moitié effacée.
  function settle() {
    if (raf && frozen()) { cancelAnimationFrame(raf); raf = 0; }
    // pause globale ou mouvement réduit : état final ; pause locale du hero : T figé (sauf image vide)
    if (frozen()) { if (mode === 'loop' && (RM || paused() || T < 1 || T > FADE0)) T = REST; if (mode !== 'loop') T = target; liveK = liveTo; render(); }
    kick();
  }

  fig.classList.add('is-mounted');
  new ResizeObserver(() => { if (layout()) render(); }).observe(wrap);
  new IntersectionObserver(([e]) => { visible = e.isIntersecting; kick(); }).observe(fig);
  document.addEventListener('visibilitychange', kick);
  document.addEventListener('snt-motion', settle);
  if (document.fonts) document.fonts.load(`500 12px ${MONO}`).then(() => { if (layout()) render(); }, () => {});
  if (layout()) render();
  // changement de DPR sans changement de taille (écran Retina, zoom) : le ResizeObserver ne le voit pas
  const onDpr = () => { render(); matchMedia(`(resolution: ${devicePixelRatio}dppx)`).addEventListener('change', onDpr, { once: true }); };
  matchMedia(`(resolution: ${devicePixelRatio}dppx)`).addEventListener('change', onDpr, { once: true });

  return {
    setTarget(s) {
      const tt = targetT(s);
      let cur = -1; for (let i = 0; i <= 7; i++) if (targetT(i) <= T + 1e-6) cur = i;
      if (frozen() || tt < T) T = tt; else if (s - cur > 2) T = targetT(s - 1);
      target = tt; render(); kick();
    },
    setLive(b) { liveTo = b ? 1 : 0; fig.classList.toggle('is-live', b); if (frozen()) liveK = liveTo; render(); kick(); },
    play() { local = false; kick(); },
    pause() { local = true; settle(); },
    destroy() { cancelAnimationFrame(raf); raf = 0; visible = false; },
  };
}
