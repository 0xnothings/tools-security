// techstack.js — dependency CVE lookup by ecosystem query.
// Copyright (c) 2026 0xnothings
// @tool techstack
// @desc Query the OSV.dev API for known vulnerabilities affecting a package+version across ecosystems
// @usage node tools/techstack.js --pkg lodash --eco npm --ver 4.17.20 --json
// @tags security,supplychain,cve
import { readFileSync } from 'node:fs';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`techstack — dependency vulnerability lookup (OSV.dev)

  node tools/techstack.js --pkg <name> [--eco npm] [--ver 1.2.3]
  node tools/techstack.js --manifest package.json|composer.json|requirements.txt
  node tools/techstack.js --list pkgs.txt          (lines: name@version or name version)

  --eco <e>      npm | PyPI | Go | Maven | crates.io | NuGet | Packagist | RubyGems
  --json         machine-readable output
  -h, --help     this text`);
  process.exit(0);
}

const ECO_MAP = { 'package-lock': 'npm', 'package.json': 'npm', 'composer.json': 'Packagist', 'composer.lock': 'Packagist' };

function parseManifest(file) {
  const txt = readFileSync(file, 'utf8');
  const base = file.split(/[\\/]/).pop();
  const pkgs = [];
  if (base === 'package.json' || base === 'composer.json') {
    let j; try { j = JSON.parse(txt); } catch { return pkgs; }
    const eco = ECO_MAP[base];
    const deps = { ...(j.dependencies || {}), ...(j['devDependencies'] || {}), ...(j.require || {}) };
    for (const [name, ver] of Object.entries(deps)) {
      if (typeof ver !== 'string') continue;
      const clean = ver.replace(/^[\^~>=<\s]+/, '').split(' ')[0].split('|')[0];
      if (/^\d/.test(clean)) pkgs.push({ name, eco, ver: clean });
    }
  } else {
    for (const l of txt.split(/\r?\n/)) {
      const m = l.trim().match(/^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([0-9][\w.]*)/);
      if (m) pkgs.push({ name: m[1], eco: 'PyPI', ver: m[2] });
    }
  }
  return pkgs;
}

async function query(pkg) {
  const body = { package: { name: pkg.name, ecosystem: pkg.eco } };
  if (pkg.ver) body.version = pkg.ver;
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 20000);
  try {
    const res = await fetch('https://api.osv.dev/v1/query', { method: 'POST', signal: ctl.signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await res.json();
    return { ...pkg, vulns: (j.vulns || []).map((v) => ({ id: v.id, summary: (v.summary || '').slice(0, 110), severity: (v.database_specific?.severity || v.severity?.[0]?.score || 'unknown'), aliases: (v.aliases || []).slice(0, 3), fixed: (v.affected?.[0]?.ranges?.[0]?.events || []).filter((e) => e.fixed).map((e) => e.fixed)[0] || '-' })) };
  } catch (e) { return { ...pkg, error: String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

let pkgs = [];
if (o.f.manifest) pkgs = parseManifest(String(get(o, 'manifest')));
else if (o.f.pkg) {
  const eco = String(get(o, 'eco', 'npm'));
  pkgs = [{ name: String(get(o, 'pkg')), eco, ver: o.f.ver ? String(get(o, 'ver')) : null }];
} else if (o.f.list) {
  for (const l of await inputLines(String(get(o, 'list')))) {
    const m = l.match(/^(@?[A-Za-z0-9_.\-\/]+)[@\s]+([0-9][\w.\-]*)$/);
    if (m) pkgs.push({ name: m[1], eco: String(get(o, 'eco', 'npm')), ver: m[2] });
    else if (l) pkgs.push({ name: l, eco: String(get(o, 'eco', 'npm')), ver: null });
  }
} else die('need --pkg, --manifest or --list');

if (!pkgs.length) die('no packages parsed');
const conc = num(get(o, 'concurrency'), 6);
const results = [];
let idx = 0;
await Promise.all(Array.from({ length: Math.min(conc, pkgs.length) }, async () => {
  while (idx < pkgs.length) results.push(await query(pkgs[idx++]));
}));
results.sort((a, b) => (b.vulns?.length || 0) - (a.vulns?.length || 0));

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); process.exit(0); }
const rows = [];
for (const r of results) {
  if (r.error) { rows.push({ pkg: r.name, version: r.ver || '', vulns: 'ERR', worst: r.error.slice(0, 30) }); continue; }
  if (!r.vulns.length) continue;
  for (const v of r.vulns) rows.push({ pkg: r.name, version: r.ver || 'any', vulns: v.id, summary: v.summary.slice(0, 60), fixed: v.fixed });
}
console.log(table(rows));
const vulnerable = results.filter((r) => r.vulns?.length).length;
console.log(`\n${results.length} package(s) queried | ${vulnerable} affected | ${rows.length} advisories`);
