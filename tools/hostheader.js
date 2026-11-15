// hostheader.js — Host header injection tester.
// Copyright (c) 2026 0xnothings
// @tool hostheader
// @desc Test Host / X-Forwarded-Host / X-Forwarded-For handling for cache poisoning and reset-poisoning risk
// @usage node tools/hostheader.js https://example.com/reset --json
// @tags security,web,cachepoisoning
import { args, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`hostheader — Host header injection tester

  node tools/hostheader.js <url|urls.txt|-> [options]

  --canary <host>  attacker host (default: 0xnothings-canary.test)
  --timeout <ms>   request timeout (default: 9000)
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

const CANARY = String(get(o, 'canary', '0xnothings-canary.test'));
const VECTORS = [
  ['Host', CANARY],
  ['Host', `${CANARY}:443`],
  ['X-Forwarded-Host', CANARY],
  ['X-Forwarded-Server', CANARY],
  ['X-Host', CANARY],
  ['X-Original-URL', `https://${CANARY}/`],
  ['X-Rewrite-URL', `https://${CANARY}/`],
  ['Forwarded', `host=${CANARY}`],
  ['X-Forwarded-For', CANARY],
  ['X-Real-IP', CANARY],
  ['X-Client-IP', CANARY],
  ['CF-Connecting-IP', CANARY],
];

async function probe(url, header, value) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), num(get(o, 'timeout'), 9000));
  try {
    const res = await fetch(url, { redirect: 'manual', signal: ctl.signal, headers: { [header]: value, 'user-agent': '0xnothings-host/1.0' } });
    const body = await res.text().catch(() => '');
    return { status: res.status, len: body.length, echo: body.includes(CANARY), ar: res.headers.get('access-control-allow-origin') || '', loc: res.headers.get('location') || '', cache: res.headers.get('x-cache') || res.headers.get('cf-cache-status') || '', body: body.slice(0, 0) };
  } catch (e) { return { error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) urls.push(...(await inputLines(e))); else urls.push(e);
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u)))];
if (!urls.length) die('no url given');

const findings = [];
for (const u of urls) {
  const base = await (async () => { try { const r = await fetch(u, { headers: { 'user-agent': '0xnothings-host/1.0' } }); const b = await r.text(); return { status: r.status, len: b.length }; } catch { return null; } })();
  if (!base) { console.error(`baseline failed for ${u}`); continue; }
  for (const [h, v] of VECTORS) {
    const r = await probe(u, h, v);
    if (r.error) continue;
    const signals = [];
    if (r.echo) signals.push('canary reflected in body');
    if (r.loc.includes(CANARY)) signals.push('canary in Location header');
    if (r.ar.includes(CANARY)) signals.push('canary in ACAO');
    if (base.status !== r.status) signals.push(`status ${base.status}->${r.status}`);
    if (Math.abs(base.len - r.len) > 200) signals.push(`len ${base.len}->${r.len}`);
    if (!signals.length) continue;
    findings.push({ url: u, header: h, value: v, status: r.status, cache: r.cache || '-', signals: signals.join('; ') });
    if (!flag(o, 'json')) console.log(`${u}\n  ${h}: ${v}  -> ${signals.join('; ')}`);
  }
}
if (flag(o, 'json')) console.log(JSON.stringify(findings, null, 2));
else console.log(`\n${findings.length} host-header finding(s) on ${urls.length} url(s)`);
