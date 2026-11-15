// corscheck.js — CORS misconfiguration scanner.
// Copyright (c) 2026 0xnothings
// @tool corscheck
// @desc Probe endpoints for CORS origin reflection, wildcard + credentials, and null-origin bypass
// @usage node tools/corscheck.js https://api.example.com --paths /,/api/user --json
// @tags security,web,cors
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`corscheck — CORS misconfiguration scanner

  node tools/corscheck.js <url|urls.txt|-> [options]

  --paths <list>      paths to append (default: the url itself)
  --origin <origin>   attacker origin to test (default: https://evil.0xnothings.test)
  --timeout <ms>      request timeout (default: 10000)
  --json              machine-readable output
  -h, --help          this text`);
  process.exit(0);
}

const ATTACKER = get(o, 'origin', 'https://evil.0xnothings.test');
const PROBES = [
  ['reflected', ATTACKER],
  ['null-origin', 'null'],
  ['subdomain-suffix', 'https://evil.' + 'example.com'],
  ['prefix-trick', 'https://' + 'example.com.evil.test'],
];

async function probe(url, origin) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), num(get(o, 'timeout'), 10000));
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { origin, 'user-agent': '0xnothings-cors/1.0' } });
    return {
      acao: res.headers.get('access-control-allow-origin') || '',
      acac: res.headers.get('access-control-allow-credentials') || '',
      acam: res.headers.get('access-control-allow-methods') || '',
      acah: res.headers.get('access-control-allow-headers') || '',
      status: res.status,
    };
  } catch (e) { return { error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

let bases = o._.length ? o._ : ['-'];
let urls = [];
for (const b of bases) {
  if (/-$|\.txt$/.test(b)) urls.push(...(await inputLines(b)));
  else urls.push(b);
}
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u)))];
if (!urls.length) die('no urls given');
const paths = String(get(o, 'paths', '')).split(',').map((s) => s.trim()).filter(Boolean);

const findings = [];
for (const base of urls) {
  const targets = paths.length ? paths.map((p) => base.replace(/\/+$/, '') + (p.startsWith('/') ? p : '/' + p)) : [base];
  for (const url of targets) {
    for (const [label, origin] of PROBES) {
      const r = await probe(url, origin);
      if (r.error) continue;
      const reflected = r.acao === origin || (label === 'null-origin' && r.acao === 'null');
      const wildcard = r.acao === '*';
      const creds = /true/i.test(r.acac);
      let verdict = 'safe';
      if (wildcard && creds) verdict = 'CRITICAL wildcard + credentials';
      else if (reflected && creds) verdict = 'HIGH reflected origin + credentials';
      else if (wildcard) verdict = 'LOW wildcard without credentials';
      else if (reflected) verdict = 'MEDIUM reflected origin without credentials';
      if (verdict === 'safe') continue;
      findings.push({ url, probe: label, origin, acao: r.acao, acac: r.acac || '-', verdict });
    }
  }
}

if (flag(o, 'json')) console.log(JSON.stringify(findings, null, 2));
else if (!findings.length) console.log(`no CORS misconfiguration on ${urls.length} url(s)`);
else { console.log(table(findings)); console.log(`\n${findings.length} finding(s)`); }
