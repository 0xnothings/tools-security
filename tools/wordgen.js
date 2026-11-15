// wordgen.js — targeted password/username wordlist generator from profile data.
// Copyright (c) 2026 0xnothings
// @tool wordgen
// @desc Generate context-aware wordlists (names/dates/company/leet/mutations) for authorised recovery testing
// @usage node tools/wordgen.js --name "Budi Santoso" --nick budi --year 1998 --domain acme.id --out words.txt
// @tags security,wordlist,osint
import { writeFileSync } from 'node:fs';
import { args, get, num, flag, die } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`wordgen — context-aware wordlist generator

  node tools/wordgen.js [options]

  --name "Budi Santoso"    full name (spaces split into tokens)
  --nick <list>            nicknames / handles (comma separated)
  --year <list>            years/numbers to append
  --domain <d>             a company/brand/domain word
  --extra <list>           extra words
  --leet                   add l33t variants (a->4 e->3 i->1 o->0 s->5)
  --case                   add Capitalised and UPPER variants
  --suffix <list>          custom suffixes (default: 123,1234,!,@,#,2024,2025,2026,01,007)
  --min <n>, --max <n>     length filter
  --out <file>             write to file (default: stdout)
  --json                   machine-readable summary
  -h, --help               this text`);
  process.exit(0);
}

const tokens = new Set();
const push = (v) => { const s = String(v || '').trim(); if (s && s.length >= 2) tokens.add(s); };
const pushLower = (v) => { const s = String(v || '').trim().toLowerCase(); if (s.length >= 2) tokens.add(s); };

if (o.f.name) {
  const parts = String(get(o, 'name')).split(/[\s._-]+/).filter(Boolean);
  parts.forEach((p) => { push(p); pushLower(p); });
  if (parts.length > 1) {
    pushLower(parts.join(''));
    pushLower(parts.join('.'));
    pushLower(parts.join('_'));
    pushLower(parts.map((p) => p[0]).join(''));
    pushLower(parts[0] + parts[parts.length - 1][0]);
  }
}
for (const k of ['nick', 'domain', 'extra']) if (o.f[k]) String(get(o, k)).split(',').forEach((s) => { push(s); pushLower(s); });
const years = o.f.year ? String(get(o, 'year')).split(',').map((s) => s.trim()) : [];
const suffixes = o.f.suffix ? String(get(o, 'suffix')).split(',').map((s) => s.trim()) : ['123', '1234', '12345', '!', '@', '#', '1', '12', '01', '007', '2024', '2025', '2026'];

const leet = (s) => s.replace(/a/gi, '4').replace(/e/gi, '3').replace(/i/gi, '1').replace(/o/gi, '0').replace(/s/gi, '5').replace(/t/gi, '7');
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

const out = new Set();
for (const t of tokens) {
  const variants = new Set([t, pushLower(t)]);
  variants.add(t.toLowerCase());
  variants.add(cap(t));
  if (flag(o, 'case')) variants.add(t.toUpperCase());
  if (flag(o, 'leet')) { variants.add(leet(t)); variants.add(leet(cap(t))); }
  for (const v of variants) {
    out.add(v);
    for (const s of suffixes) out.add(v + s);
    for (const y of years) { out.add(v + y); out.add(v + y.slice(2)); out.add(v + '@' + y); }
  }
}
for (const y of years) out.add(y);
const min = num(get(o, 'min'), 0), max = num(get(o, 'max'), 0);
const list = [...out].filter((w) => (!min || w.length >= min) && (!max || w.length <= max)).sort();

if (o.f.out) { writeFileSync(String(get(o, 'out')), list.join('\n') + '\n', 'utf8'); console.log(`${list.length} candidates -> ${get(o, 'out')}`); }
else console.log(list.join('\n'));

if (flag(o, 'json')) console.error(JSON.stringify({ tokens: tokens.size, candidates: list.length, avg_len: +(list.reduce((a, w) => a + w.length, 0) / (list.length || 1)).toFixed(2) }));
