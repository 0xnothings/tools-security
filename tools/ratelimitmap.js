// ratelimitmap.js — map rate-limit policy across many endpoints.
// Copyright (c) 2026 0xnothings
// @tool ratelimitmap
// @desc Discover per-path rate-limit thresholds, header conventions and lockout behaviour, then emit a pacing plan
// @usage node tools/ratelimitmap.js https://target --paths /api/login,/api/search --json
// @tags security,web,ratelimit
import { args, get, num, flag, die, readInput, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`ratelimitmap — rate-limit policy mapper

  node tools/ratelimitmap.js <base-url|list.txt|-> [options]

  --paths <list>     comma list of paths, or a file with one path per line (default: a built-in probe set)
  --method <m>       HTTP method (default: GET)
  --burst <n>        max requests per endpoint in the ramp (default: 60)
  --conc <n>         concurrency during the burst (default: 5)
  --gap <ms>         pause between steps of the ramp (default: 400)
  --timeout <ms>     per-request timeout (default: 8000)
  --cookie <c>       Cookie header to include
  --reset-wait <ms>  wait time used to test window reset (default: 15000, 0 to skip)
  --json             machine-readable output
  -h, --help         this text

  Per endpoint: first 429 status index, rate-limit headers (RateLimit-*,
  X-RateLimit-*, Retry-After), lockout escalation, whether the limit is
  per-IP or per-session, and a conservative request pacing plan.`);
  process.exit(0);
}

const exitSoon = (code = 0) => { process.exitCode = code; };
const timeout = num(get(o, 'timeout'), 8000);
const burst = num(get(o, 'burst'), 60);
const conc = num(get(o, 'conc'), 5);
const gap = num(get(o, 'gap'), 400);
const resetWait = num(get(o, 'reset-wait'), 15000);
const method = String(get(o, 'method', 'GET')).toUpperCase();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const DEFAULT_PATHS = [
  '/', '/login', '/api', '/api/login', '/api/search', '/api/users', '/search', '/account',
  '/api/v1/', '/graphql', '/register', '/password/reset',
];

const RL_HEADERS = [
  'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset', 'ratelimit-policy',
  'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
  'x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset',
  'retry-after', 'x-retry-after', 'x-ratelimit-retry-after', 'rate-limit',
  'x-ratelimit-used', 'x-ratelimit-window', 'x-served-by',
];

async function send(url, cookie) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  const started = Date.now();
  try {
    const r = await fetch(url, {
      method,
      headers: { 'user-agent': 'ratelimitmap/1.0', accept: '*/*', ...(cookie ? { cookie } : {}) },
      signal: ctl.signal,
      redirect: 'manual',
    });
    const body = await r.text();
    const hdrs = {};
    let hdrFound = {};
    for (const [k, v] of r.headers) {
      const key = k.toLowerCase();
      if (RL_HEADERS.includes(key)) hdrFound[key] = v;
      hdrs[key] = v;
    }
    return { status: r.status, ms: Date.now() - started, len: body.length, rl: hdrFound, headers: hdrs, retry_after: hdrs['retry-after'] || null, error: null, body_head: body.slice(0, 200) };
  } catch (e) {
    return { status: 0, ms: Date.now() - started, len: 0, rl: {}, headers: {}, error: e.name === 'AbortError' ? 'timeout' : (e.message || 'failed'), body_head: '' };
  } finally { clearTimeout(t); }
}

async function mapEndpoint(url, cookie) {
  const seq = [];
  const firstHit = { at: null, status: null };
  const rlHeadersSeen = new Set();
  let forbidden = false;
  let blockedUntil = null;

  // Sequential ramp — this is the only way the "first 429 index" means anything.
  for (let i = 1; i <= burst; i++) {
    const r = await send(url, cookie);
    for (const k of Object.keys(r.rl)) rlHeadersSeen.add(k);
    seq.push({ n: i, status: r.status, ms: r.ms, retry_after: r.retry_after, rl: r.rl });
    if (r.status === 429 && firstHit.at === null) { firstHit.at = i; firstHit.status = 429; blockedUntil = r.retry_after; }
    if (r.status === 403 && firstHit.at === null && i > 3) { firstHit.at = i; firstHit.status = 403; forbidden = true; }
    if (r.status === 503 && firstHit.at === null) { firstHit.at = i; firstHit.status = 503; }
    // Once limited, keep probing a little to see escalation, then stop.
    if (firstHit.at !== null && i > firstHit.at + 5) break;
    if (r.error) break;
    await sleep(gap);
  }

  // Concurrency probe: does a parallel burst trip the limiter faster than sequential?
  const parStart = Date.now();
  const par = await Promise.all(Array.from({ length: Math.min(conc * 2, burst) }, () => send(url, cookie)));
  const par429 = par.filter((p) => p.status === 429).length;
  const parMs = Date.now() - parStart;

  // Reset window
  let resetProbe = null;
  if (resetWait > 0 && firstHit.at !== null) {
    await sleep(resetWait);
    const after = await send(url, cookie);
    resetProbe = { waited_ms: resetWait, status: after.status, recovered: after.status !== 429 };
  }

  const limitAt = firstHit.at;
  const statuses = seq.map((s) => s.status);
  const errTypes = seq.filter((s) => s.status === 0).length;
  const hint = seq.find((s) => s.rl && (s.rl['ratelimit-limit'] || s.rl['x-ratelimit-limit']));
  const policyHeader = hint ? (hint.rl['ratelimit-policy'] || hint.rl['x-ratelimit-limit'] || hint.rl['ratelimit-limit']) : null;

  const findings = [];
  if (limitAt === null) {
    findings.push({ id: 'no-rate-limit', severity: 'MEDIUM', detail: `no 429/403 within ${seq.length} sequential requests (${statuses.filter((s) => s === 200).length} x 200)`, impact: 'unmetered endpoint — brute force and scraping are unobstructed here' });
  } else if (forbidden) {
    findings.push({ id: 'hard-block', severity: 'INFO', detail: `HTTP 403 at request #${limitAt} — WAF-style block rather than a counter`, impact: 'the block is likely IP/WAF based; rotating source addresses resets it' });
  } else {
    const sev = limitAt > 30 ? 'LOW' : limitAt > 10 ? 'MEDIUM' : 'INFO';
    findings.push({ id: 'limit-detected', severity: sev, detail: `HTTP ${firstHit.status} at request #${limitAt} of a sequential ramp`, impact: limitAt > 30 ? `policy is generous (${limitAt} requests before throttling)` : `tight policy (${limitAt} requests)` });
  }
  if (!rlHeadersSeen.size) findings.push({ id: 'no-ratelimit-headers', severity: 'LOW', detail: 'no RateLimit-*/Retry-After header on any response', impact: 'clients cannot pace themselves; also indicates the limiter is outside the app (proxy/WAF)' });
  if (blockedUntil) findings.push({ id: 'retry-after-present', severity: 'INFO', detail: `Retry-After: ${blockedUntil}`, impact: 'the server states when the window resets — use it to pace' });
  if (par429 > 0 && (limitAt === null || par429 > limitAt)) findings.push({ id: 'concurrency-sensitivity', severity: 'INFO', detail: `${par429}/${par.length} parallel requests were limited vs #${limitAt} sequential`, impact: 'the limiter counts per-connection or per-burst, so concurrency trips it faster than raw volume' });
  if (resetProbe && !resetProbe.recovered) findings.push({ id: 'lockout-persistent', severity: 'MEDIUM', detail: `still HTTP ${resetProbe.status} after waiting ${resetWait}ms`, impact: 'the lockout outlives a naive wait — longer backoff or a different source is required' });
  if (errTypes > 0) findings.push({ id: 'connection-errors', severity: 'INFO', detail: `${errTypes} request(s) failed at the transport layer`, impact: 'possible connection-level limiting or instability under load' });

  const safeRate = limitAt && limitAt > 1 ? Math.max(1, Math.floor(limitAt * 0.5)) : null;
  return {
    url, method,
    requests_sent: seq.length + par.length,
    first_limit_at: limitAt, first_limit_status: firstHit.status,
    limit_headers: [...rlHeadersSeen], policy_header: policyHeader,
    retry_after: blockedUntil,
    parallel: { count: par.length, limited: par429, elapsed_ms: parMs },
    reset_probe: resetProbe,
    sequence: seq.map((s) => ({ n: s.n, status: s.status, ms: s.ms })),
    findings,
    pacing: safeRate
      ? { requests_per_window_before_throttle: limitAt, recommended_requests_per_minute: safeRate * (60000 / Math.max(gap + 100, 500)), recommended_gap_ms: Math.max(gap, Math.ceil(1000 / safeRate) * 1000), note: `half of the observed threshold (${limitAt}) leaves headroom for retries` }
      : { requests_per_window_before_throttle: null, recommended_requests_per_minute: 30, recommended_gap_ms: 2000, note: 'no limit observed; 30 rpm is a conservative default that will not look like abuse' },
  };
}

// ---------- input ----------
const base = o._[0];
if (!base) die('pass a base URL (or a file of base URLs)');
let bases = [];
if (base === '-' || /\.txt$/.test(base)) bases = await inputLines(base);
else bases = [base];
bases = [...new Set(bases.filter(Boolean).map((b) => (/^https?:\/\//.test(b) ? b : `https://${b}`)))];
if (!bases.length) die('no base URL');

let paths = DEFAULT_PATHS;
if (o.f.paths) {
  const p = String(o.f.paths);
  if (/\.txt$/.test(p) || p.includes('/') && !p.startsWith('/api,')) {
    const text = (await readInput(p).catch(() => '')) || p;
    paths = String(text).split(/\r?\n|,/).map((s) => s.trim()).filter(Boolean);
  } else paths = p.split(',').map((s) => s.trim()).filter(Boolean);
}
paths = paths.map((p) => (p.startsWith('/') ? p : `/${p}`));

const cookie = get(o, 'cookie', null);
const results = [];
for (const b of bases) {
  const root = b.replace(/\/+$/, '');
  for (const path of paths) {
    const url = `${root}${path}`;
    const r = await mapEndpoint(url, cookie);
    r.path = path;
    results.push(r);
  }
}

if (flag(o, 'json')) {
  const limited = results.filter((r) => r.first_limit_at !== null);
  console.log(JSON.stringify({
    generated: new Date().toISOString(),
    endpoints: results.length, limited_endpoints: limited.length,
    results,
  }, null, 2));
  exitSoon(0);
}

console.log(table(results.map((r) => ({
  path: r.path.slice(0, 22),
  sent: r.requests_sent,
  limit_at: r.first_limit_at ?? 'none',
  status: r.first_limit_status ?? '',
  retry_after: r.retry_after || '',
  headers: r.limit_headers.length ? r.limit_headers.length : 0,
  par_limited: `${r.parallel.limited}/${r.parallel.count}`,
  reset_ok: r.reset_probe ? (r.reset_probe.recovered ? 'yes' : 'NO') : '-',
  findings: r.findings.filter((f) => f.severity !== 'INFO').length,
}))));

for (const r of results) {
  console.log(`\n# ${r.url}`);
  console.log(`  sent=${r.requests_sent} first_limit=${r.first_limit_at ?? 'none'}${r.policy_header ? ` policy="${r.policy_header}"` : ''}`);
  if (r.limit_headers.length) console.log(`  headers: ${r.limit_headers.join(', ')}`);
  for (const f of r.findings) console.log(`  [${f.severity}] ${f.id}: ${f.detail}\n      -> ${f.impact}`);
}

// Pacing plan for the least-obstructed endpoint on each host.
const plan = [];
const byHost = new Map();
for (const r of results) {
  const host = new URL(r.url).host;
  if (!byHost.has(host)) byHost.set(host, []);
  byHost.get(host).push(r);
}
for (const [host, list] of byHost) {
  const unlimited = list.find((r) => r.first_limit_at === null);
  const tightest = list.filter((r) => r.first_limit_at !== null).sort((a, b) => a.first_limit_at - b.first_limit_at)[0];
  const ref = unlimited || tightest || list[0];
  plan.push({
    host,
    limiting_endpoint: tightest ? `${tightest.path} @ ${tightest.first_limit_at}` : 'none observed',
    recommended_rpm: ref.pacing.recommended_requests_per_minute,
    recommended_gap_ms: ref.pacing.recommended_gap_ms,
    note: ref.pacing.note,
  });
}
console.log('\n--- pacing plan ---');
console.log(table(plan.map((p) => ({ host: p.host, limiting: p.limiting_endpoint, rpm: p.recommended_rpm, gap_ms: p.recommended_gap_ms, note: p.note.slice(0, 50) }))));
const limitedCount = results.filter((r) => r.first_limit_at !== null).length;
console.log(`\n${results.length} endpoint(s), ${limitedCount} rate-limited`);
exitSoon(0);
