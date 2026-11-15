// sessioncheck.js — cookie and session security audit from live responses.
// Copyright (c) 2026 0xnothings
// @tool sessioncheck
// @desc Audit session cookies from live responses: flags, prefixes, entropy estimate, cross-domain scope, __Host- misuse
// @usage node tools/sessioncheck.js https://example.com --json
// @tags security,web,session,auth
import crypto from 'node:crypto';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`sessioncheck — cookie / session security audit

  node tools/sessioncheck.js <url|list.txt|-> [options]

  --timeout <ms>     per-request timeout (default: 10000)
  --conc <n>         parallel requests (default: 5)
  --samples <n>      repeated fetches to sample token entropy (default: 3)
  --cookie <c>       send this Cookie header (for authenticated state)
  --assume-https     treat the URL as https for flag verdicts (default: on)
  --json             machine-readable output
  -h, --help         this text

  Per cookie: Secure / HttpOnly / SameSite, __Host- and __Secure- prefix
  correctness, domain scoping, path scoping, lifetime, session-token
  entropy estimate (bits) and whether the value changes per response.`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };
const timeout = num(get(o, 'timeout'), 10000);
const conc = num(get(o, 'conc'), 5);
const samples = Math.max(1, num(get(o, 'samples'), 3));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseSetCookie(line) {
  const parts = line.split(';').map((s) => s.trim()).filter(Boolean);
  const [nv, ...attrs] = parts;
  const eq = nv.indexOf('=');
  const name = eq >= 0 ? nv.slice(0, eq).trim() : nv.trim();
  const value = eq >= 0 ? nv.slice(eq + 1).trim() : '';
  const c = { name, value, _attrs: attrs, domain: null, path: null, expires: null, max_age: null, secure: false, httponly: false, samesite: null, partitioned: false, priority: null, raw: line };
  for (const a of attrs) {
    const [k, ...v] = a.split('=');
    const key = k.trim().toLowerCase();
    const val = v.join('=').trim();
    if (key === 'secure') c.secure = true;
    else if (key === 'httponly') c.httponly = true;
    else if (key === 'samesite') c.samesite = val || 'unspecified';
    else if (key === 'domain') c.domain = val.replace(/^\./, '');
    else if (key === 'path') c.path = val;
    else if (key === 'expires') c.expires = val;
    else if (key === 'max-age') c.max_age = Number(val);
    else if (key === 'partitioned') c.partitioned = true;
    else if (key === 'priority') c.priority = val;
  }
  return c;
}

function shannonBits(value) {
  if (!value) return { bits: 0, charset: 0, length: 0 };
  const freq = new Map();
  for (const ch of value) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / value.length; h -= p * Math.log2(p); }
  const charset = new Set(value.split('')).size;
  return { bits: +(h * value.length).toFixed(1), charset, length: value.length, entropy_per_char: +h.toFixed(3) };
}

function looksLikeJwt(v) { return /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(v); }

const SESSIONISH = /(sess|sid|auth|token|jwt|login|remember|csrf|xsrf|id)$/i;

function assess(cookie, host, secureCtx) {
  const issues = [];
  const notes = [];
  const isSession = SESSIONISH.test(cookie.name) || looksLikeJwt(cookie.value) || cookie.value.length > 24;
  const prefix = cookie.name.startsWith('__Host-') ? '__Host-' : cookie.name.startsWith('__Secure-') ? '__Secure-' : null;

  if (secureCtx && !cookie.secure) issues.push({ id: 'no-secure', severity: 'HIGH', detail: 'cookie is set without the Secure flag over HTTPS — it will travel over plaintext connections too' });
  if (!cookie.httponly && isSession) issues.push({ id: 'no-httponly', severity: 'HIGH', detail: 'session-ish cookie lacks HttpOnly — readable from JavaScript, so any XSS steals it' });
  if (cookie.samesite === null) issues.push({ id: 'no-samesite', severity: 'MEDIUM', detail: 'SameSite is not specified — modern browsers default to Lax, older ones to None' });
  else if (/^none$/i.test(cookie.samesite) && !cookie.secure) issues.push({ id: 'samesite-none-insecure', severity: 'HIGH', detail: 'SameSite=None without Secure is rejected by browsers and signals a legacy cross-site cookie' });
  else if (/^unspecified$/i.test(cookie.samesite)) issues.push({ id: 'samesite-unspecified', severity: 'LOW', detail: 'SameSite=Unspecified is treated as Lax by Chromium only' });

  if (prefix === '__Host-' && cookie.domain) issues.push({ id: 'host-prefix-domain', severity: 'HIGH', detail: '__Host- cookie also sets Domain — browsers reject this, so the security guarantee is lost' });
  if (prefix === '__Host-' && cookie.path && cookie.path !== '/') issues.push({ id: 'host-prefix-path', severity: 'HIGH', detail: `__Host- cookie has Path=${cookie.path}; it must be exactly /` });
  if (prefix && !cookie.secure) issues.push({ id: 'prefix-without-secure', severity: 'HIGH', detail: `${prefix} cookie missing Secure — browsers will refuse it` });
  if (!prefix && isSession && secureCtx) notes.push({ id: 'no-host-prefix', severity: 'INFO', detail: 'consider __Host- prefix to pin the cookie to this origin with Path=/' });

  if (cookie.domain) {
    const base = host.split('.').slice(-2).join('.');
    if (cookie.domain === base && host !== cookie.domain) issues.push({ id: 'parent-domain-scope', severity: 'MEDIUM', detail: `cookie is scoped to the registrable parent ${cookie.domain} — every sibling subdomain can read and overwrite it` });
    if (/^\./.test(String(cookie.raw).match(/Domain=([^;]+)/)?.[1] || '')) notes.push({ id: 'leading-dot-domain', severity: 'INFO', detail: 'Domain has a leading dot (legacy, ignored by modern browsers)' });
  }
  if (cookie.path && cookie.path !== '/') notes.push({ id: 'path-scoped', severity: 'LOW', detail: `cookie limited to Path=${cookie.path}` });
  if (!cookie.expires && cookie.max_age === null && isSession) notes.push({ id: 'session-cookie', severity: 'INFO', detail: 'no Expires/Max-Age — session cookie, dropped when the browser closes' });
  if (cookie.max_age !== null && cookie.max_age > 60 * 60 * 24 * 30) notes.push({ id: 'long-lifetime', severity: 'LOW', detail: `Max-Age ${cookie.max_age}s (~${Math.round(cookie.max_age / 86400)} days) is long for a session token` });
  if (cookie.expires) {
    const t = Date.parse(cookie.expires);
    if (!isNaN(t) && t - Date.now() > 1000 * 60 * 60 * 24 * 180) notes.push({ id: 'far-future-expiry', severity: 'LOW', detail: `Expires ${cookie.expires} is more than 6 months out` });
  }

  const ent = shannonBits(cookie.value);
  if (isSession && ent.length && ent.bits < 64) issues.push({ id: 'low-entropy', severity: 'HIGH', detail: `session value carries roughly ${ent.bits} bits of entropy across ${ent.length} chars (charset ${ent.charset}) — brute-forceable` });
  else if (isSession && ent.bits < 100) notes.push({ id: 'moderate-entropy', severity: 'LOW', detail: `~${ent.bits} bits of entropy — acceptable, 128+ preferred` });
  if (/^[0-9]+$/.test(cookie.value) && cookie.value.length <= 12) issues.push({ id: 'sequential-value', severity: 'HIGH', detail: 'cookie value is a short pure-numeric string — almost certainly sequential/predictable' });
  if (looksLikeJwt(cookie.value)) {
    const payload = cookie.value.split('.')[1];
    try {
      const json = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
      notes.push({ id: 'jwt-cookie', severity: 'INFO', detail: `cookie value is a JWT with claims: ${Object.keys(json).join(',')}` });
      if (json.alg === 'none') issues.push({ id: 'jwt-none-alg', severity: 'CRITICAL', detail: 'JWT inside the cookie declares alg=none' });
    } catch { notes.push({ id: 'jwt-unparseable', severity: 'LOW', detail: 'value looks like a JWT but the payload did not decode' }); }
  }
  const always = cookie._attrs.filter((a) => /^(secure|httponly|samesite|domain|path|expires|max-age|partitioned)/i.test(a.split('=')[0]));
  return { name: cookie.name, is_session_like: isSession, prefix, entropy_bits: ent.bits, charset: ent.charset, value_length: ent.length, attrs: { secure: cookie.secure, httponly: cookie.httponly, samesite: cookie.samesite, domain: cookie.domain, path: cookie.path, expires: cookie.expires, max_age: cookie.max_age, partitioned: cookie.partitioned }, issues, notes, attr_count: always.length };
}

async function fetchOnce(url, cookieHeader) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(url, { headers: { 'user-agent': 'sessioncheck/1.0', ...(cookieHeader ? { cookie: cookieHeader } : {}) }, signal: ctl.signal, redirect: 'manual' });
    const setCookies = typeof r.headers.getSetCookie === 'function' ? r.headers.getSetCookie() : (r.headers.get('set-cookie') ? [r.headers.get('set-cookie')] : []);
    const body = await r.text();
    const authish = /(set-cookie|log ?out|sign ?out|my account|dashboard)/i.test(body.slice(0, 20000));
    return { status: r.status, setCookies, authish, location: r.headers.get('location'), hsts: r.headers.get('strict-transport-security'), csp: r.headers.get('content-security-policy'), error: null };
  } catch (e) {
    return { status: 0, setCookies: [], error: e.name === 'AbortError' ? 'timeout' : (e.message || 'failed') };
  } finally { clearTimeout(t); }
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) urls.push(...(await inputLines(e)));
  else urls.push(e);
}
urls = [...new Set(urls.filter(Boolean).map((u) => (/^https?:\/\//.test(u) ? u : `https://${u}`)))];
if (!urls.length) die('no URL given');

const cookieHeader = get(o, 'cookie', null);
const results = [];
let cursor = 0;
async function worker() {
  while (cursor < urls.length) {
    const url = urls[cursor++];
    const host = new URL(url).hostname;
    const secureCtx = /^https:/.test(url) || flag(o, 'assume-https');
    const rounds = [];
    for (let i = 0; i < samples; i++) {
      rounds.push(await fetchOnce(url, cookieHeader));
      if (i < samples - 1) await sleep(200);
    }
    const first = rounds[0];
    const cookies = [];
    const seen = new Map();
    for (const r of rounds) {
      for (const sc of r.setCookies) {
        const c = parseSetCookie(sc);
        if (!seen.has(c.name)) { seen.set(c.name, { values: [] }); cookies.push(c); }
        seen.get(c.name).values.push(c.value);
      }
    }
    const assessed = cookies.map((c) => {
      const a = assess(c, host, secureCtx);
      const vals = seen.get(c.name).values;
      a.value_changes = new Set(vals).size > 1;
      a.samples = vals.length;
      if (!a.value_changes && vals.length > 1) a.notes.push({ id: 'static-value', severity: 'LOW', detail: `value identical across ${vals.length} responses — a fixed identifier, not a rotating session token` });
      return a;
    });
    const hostFindings = [];
    if (!first.hsts) hostFindings.push({ id: 'no-hsts', severity: 'MEDIUM', detail: 'no Strict-Transport-Security header — session cookie can be captured on a downgraded connection' });
    else if (!/max-age=\d{5,}/.test(first.hsts)) hostFindings.push({ id: 'weak-hsts', severity: 'LOW', detail: `HSTS max-age is short: ${first.hsts}` });
    results.push({
      url, host, status: first.status, error: first.error, secure_context: secureCtx,
      cookie_count: assessed.length, cookies: assessed, host_findings: hostFindings,
      response_headers: { hsts: first.hsts || null, csp: first.csp ? first.csp.slice(0, 120) : null, location: first.location || null },
    });
  }
}
await Promise.all(Array.from({ length: Math.min(conc, urls.length) }, worker));

if (flag(o, 'json')) {
  const bad = results.some((r) => r.cookies.some((c) => c.issues.length) || r.host_findings.length);
  console.log(JSON.stringify({ generated: new Date().toISOString(), results }, null, 2));
  exitSoon(bad ? 1 : 0);
}

for (const r of results) {
  console.log(`\n### ${r.url}  (HTTP ${r.status}${r.error ? ', ' + r.error : ''}, ${r.cookie_count} cookie(s))`);
  if (!r.cookie_count) { console.log('  no Set-Cookie observed — nothing to audit on this response'); }
  else {
    console.log(table(r.cookies.map((c) => ({
      cookie: c.name.slice(0, 26),
      sess: c.is_session_like ? 'yes' : 'no',
      secure: c.attrs.secure ? 'yes' : 'NO',
      httponly: c.attrs.httponly ? 'yes' : 'NO',
      samesite: c.attrs.samesite || 'MISSING',
      prefix: c.prefix || '-',
      domain: c.attrs.domain || '(host-only)',
      bits: c.entropy_bits || 0,
      issues: c.issues.length,
    }))));
    for (const c of r.cookies) {
      for (const i of c.issues) console.log(`  [${i.severity}] ${c.name}: ${i.detail}`);
      for (const n of c.notes) console.log(`  [${n.severity}] ${c.name}: ${n.detail}`);
    }
  }
  for (const f of r.host_findings) console.log(`  [${f.severity}] host: ${f.detail}`);
}
const totalIssues = results.reduce((n, r) => n + r.cookies.reduce((m, c) => m + c.issues.length, 0) + r.host_findings.length, 0);
console.log(`\n${results.length} endpoint(s), ${totalIssues} issue(s)`);
exitSoon(totalIssues ? 1 : 0);
