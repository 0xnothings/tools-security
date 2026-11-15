// statusfuzz.js — HTTP method and auth-boundary matrix builder.
// Copyright (c) 2026 0xnothings
// @tool statusfuzz
// @desc Build a route x method status matrix (no-auth vs bogus-token) to find open endpoints
// @usage node tools/statusfuzz.js https://api.example.com --paths-file routes.txt --json
// @tags security,api,accesscontrol
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`statusfuzz — route/method auth-boundary matrix

  node tools/statusfuzz.js <base-url> [options]

  --paths <list>       comma-separated paths (or --paths-file)
  --paths-file <f>     one path per line
  --methods <list>     default: GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD
  --token <t>          optional bearer token to compare authenticated vs anonymous
  --concurrency <n>    parallel requests (default: 8)
  --timeout <ms>       request timeout (default: 8000)
  --json               machine-readable output
  -h, --help           this text`);
  process.exit(0);
}

const base = o._[0];
if (!base) die('usage: node tools/statusfuzz.js <base-url> --paths /a,/b [--token t]');
const root = base.replace(/\/+$/, '');
let paths = String(get(o, 'paths', '')).split(',').map((s) => s.trim()).filter(Boolean);
if (o.f['paths-file']) paths.push(...(await inputLines(get(o, 'paths-file'))));
if (!paths.length) paths = ['/', '/api', '/api/v1', '/api/v1/users', '/admin', '/login', '/health'];
paths = [...new Set(paths.map((p) => (p.startsWith('/') ? p : '/' + p)))];
const methods = String(get(o, 'methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD')).split(',').map((s) => s.trim());
const conc = num(get(o, 'concurrency'), 8);
const timeout = num(get(o, 'timeout'), 8000);
const token = o.f.token ? String(get(o, 'token')) : null;

async function call(method, url, auth) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  const headers = { 'user-agent': '0xnothings-status/1.0', accept: 'application/json, text/html;q=0.9' };
  if (auth === 'bogus') headers.authorization = 'Bearer 0xnothings-invalid-token';
  if (auth === 'real' && token) headers.authorization = `Bearer ${token}`;
  try {
    const res = await fetch(url, { method, headers, signal: ctl.signal, redirect: 'manual' });
    const body = await res.text().catch(() => '');
    return { status: res.status, len: body.length, allow: res.headers.get('allow') || '', snippet: body.slice(0, 80).replace(/\s+/g, ' ') };
  } catch (e) { return { status: e.name === 'AbortError' ? 'ERR' : 'ERR', len: 0, snippet: e.cause?.code || e.message }; }
  finally { clearTimeout(t); }
}

const modes = token ? ['anon', 'bogus', 'real'] : ['anon', 'bogus'];
const rows = [];
const jobs = [];
for (const p of paths) for (const m of methods) for (const auth of modes) jobs.push({ p, m, auth });

let idx = 0;
await Promise.all(Array.from({ length: Math.min(conc, jobs.length) }, async () => {
  while (idx < jobs.length) {
    const j = jobs[idx++];
    const r = await call(j.m, root + j.p, j.auth);
    rows.push({ path: j.p, method: j.m, auth: j.auth, status: r.status, len: r.len, allow: r.allow, snippet: r.snippet });
  }
}));

const key = (r) => `${r.path}|${r.method}`;
const grouped = new Map();
for (const r of rows) {
  if (!grouped.has(key(r))) grouped.set(key(r), { path: r.path, method: r.method });
  grouped.get(key(r))[r.auth] = r.status;
}
const matrix = [...grouped.values()].map((g) => {
  const open = g.anon && Number(g.anon) < 400 && ![401, 403, 405].includes(Number(g.anon));
  const bypass = g.real && Number(g.real) < 400 && g.bogus && Number(g.bogus) >= 400;
  const skipped = g.bogus && Number(g.bogus) < 400 && g.anon && Number(g.anon) >= 400;
  return { ...g, verdict: open ? 'ANON-OK' : bypass ? 'token-enforced' : skipped ? 'bogus-token-ok' : 'protected' };
});

matrix.sort((a, b) => Number(b.verdict === 'ANON-OK') - Number(a.verdict === 'ANON-OK'));

if (flag(o, 'json')) console.log(JSON.stringify(matrix, null, 2));
else {
  console.log(table(matrix.map((m) => ({ path: m.path, method: m.method, anon: m.anon ?? '', bogus: m.bogus ?? '', real: m.real ?? '', verdict: m.verdict }))));
  const open = matrix.filter((m) => m.verdict === 'ANON-OK');
  console.log(`\n${matrix.length} route/method pairs | ${open.length} reachable without auth`);
  if (open.length) console.log('reachable: ' + open.map((m) => `${m.method} ${m.path}`).join(', '));
}
