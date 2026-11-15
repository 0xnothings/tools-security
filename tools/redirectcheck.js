// redirectcheck.js — open redirect scanner.
// Copyright (c) 2026 0xnothings
// @tool redirectcheck
// @desc Test URL parameters for open-redirect behaviour with a payload matrix and 3xx/Location evidence
// @usage node tools/redirectcheck.js "https://site.com/login?next=1" --json
// @tags security,web,redirect
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`redirectcheck — open redirect scanner

  node tools/redirectcheck.js <url-with-params|urls.txt|-> [options]

  --params <list>    params to inject if the url has none (default: next,url,redirect,return,r,dest)
  --params-file <f>  extra params, one per line
  --canary <host>    attacker host (default: evil.0xnothings.test)
  --timeout <ms>     request timeout (default: 8000)
  --json             machine-readable output
  -h, --help         this text`);
  process.exit(0);
}

const CANARY = String(get(o, 'canary', 'evil.0xnothings.test'));
const PAYLOADS = [
  ['plain', `https://${CANARY}/`],
  ['scheme-relative', `//${CANARY}/`],
  ['backslash', `\\\\${CANARY}/`],
  ['encoded-slash', `%2f%2f${CANARY}%2f`],
  ['at-trick', `https://legit.example@${CANARY}/`],
  ['question-trick', `https://example.com?@${CANARY}`],
  ['hash-trick', `https://example.com#@${CANARY}`],
  ['param-suffix', `https://${CANARY}/?x=1`],
  ['double-encoded', `%252f%252f${CANARY}%252f`],
  ['whitespace', `https://${CANARY}//`],
];

function inject(url, param, value) {
  const u = new URL(url);
  u.searchParams.set(param, value);
  return u.toString();
}

async function test(url, param, payload) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), num(get(o, 'timeout'), 8000));
  try {
    const res = await fetch(url, { redirect: 'manual', signal: ctl.signal, headers: { 'user-agent': '0xnothings-redir/1.0' } });
    const loc = res.headers.get('location') || '';
    const refresh = res.headers.get('refresh') || '';
    const landed = loc && (loc.includes(CANARY) || /\/\/[^/]*/.test(loc) && loc.replace(/^https?:\/\//, '').startsWith(CANARY));
    return { status: res.status, loc, refresh, landed: !!landed };
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
  let params = [...new URL(u).searchParams.keys()];
  if (!params.length) params = String(get(o, 'params', 'next,url,redirect,return,r,dest,redir,continue,target,to,out,go,link')).split(',').map((s) => s.trim());
  if (o.f['params-file']) params.push(...(await inputLines(get(o, 'params-file'))));
  params = [...new Set(params)];
  for (const p of params) for (const [label, payload] of PAYLOADS) {
    const full = inject(u, p, payload);
    const r = await test(full, p, payload);
    if (r.error || !r.landed) continue;
    findings.push({ url: u, param: p, payload: label, status: r.status, location: r.loc.slice(0, 100) });
    if (!flag(o, 'json')) console.log(`OPEN REDIRECT  ${u}  param=${p} payload=${label} -> ${r.loc.slice(0, 90)}`);
  }
}
if (flag(o, 'json')) console.log(JSON.stringify(findings, null, 2));
else console.log(`\n${findings.length} open-redirect hit(s) on ${urls.length} url(s)`);
