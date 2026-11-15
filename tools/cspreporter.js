// cspreporter.js — CSP parser, scorer and policy hardener.
// Copyright (c) 2026 0xnothings
// @tool cspreporter
// @desc Parse a Content-Security-Policy (live or from a file), score it, list weaknesses and emit a tightened policy
// @usage node tools/cspreporter.js https://example.com --json
// @tags security,web,headers
import { existsSync } from 'node:fs';
import { args, get, num, flag, die, readInput, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`cspreporter — CSP parser, scorer and hardener

  node tools/cspreporter.js <url|policy.txt|-> [options]

  Accepts a URL (fetches live headers and any <meta http-equiv> CSP),
  a file containing a raw policy string, or stdin.

  --header <name>   header to read when input is a URL (default: content-security-policy)
  --timeout <ms>    fetch timeout (default: 10000)
  --emit-only       print only the hardened policy
  --json            machine-readable output
  -h, --help        this text

  Scores directives, flags unsafe-inline/unsafe-eval/wildcards/data: URLs,
  missing directives and weak nonce/hash usage, then prints a tightened policy.`);
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

const DIRECTIVES = [
  'default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem',
  'style-src-attr', 'img-src', 'font-src', 'connect-src', 'media-src', 'object-src', 'frame-src',
  'frame-ancestors', 'child-src', 'worker-src', 'manifest-src', 'prefetch-src', 'form-action',
  'base-uri', 'sandbox', 'report-uri', 'report-to', 'upgrade-insecure-requests', 'block-all-mixed-content',
  'require-trusted-types-for', 'trusted-types', 'navigate-to',
];

const IMPORTANT = ['default-src', 'script-src', 'object-src', 'base-uri', 'frame-ancestors', 'form-action'];

function parsePolicy(text) {
  const directives = {};
  const raw = String(text).replace(/\r?\n/g, ' ').trim();
  if (!raw) return { directives, raw: '', empty: true };
  for (const part of raw.split(';')) {
    const t = part.trim();
    if (!t) continue;
    const [name, ...vals] = t.split(/\s+/);
    const key = name.toLowerCase();
    if (!directives[key]) directives[key] = [];
    for (const v of vals) if (!directives[key].includes(v)) directives[key].push(v);
  }
  return { directives, raw, empty: false };
}

function analyse(directives) {
  const findings = [];
  const add = (id, severity, detail, fix) => findings.push({ id, severity, detail, fix });
  const d = directives;

  if (!Object.keys(d).length) {
    add('csp-absent', 'HIGH', 'no Content-Security-Policy at all — any injected script executes', 'deploy a default-src none baseline and relax per directive');
    return findings;
  }
  if (!d['default-src']) add('no-default-src', 'MEDIUM', 'default-src missing — unspecified directives fall back to unrestricted', "add default-src 'none' (or 'self')");
  for (const dir of ['object-src', 'base-uri', 'frame-ancestors', 'form-action']) {
    const covered = d[dir] || ((dir === 'object-src' || dir === 'frame-ancestors') && d['default-src']);
    if (!covered) add(`missing-${dir}`, dir === 'frame-ancestors' ? 'MEDIUM' : 'LOW', `${dir} is not set and not covered by default-src`, `add ${dir} 'none'`);
  }
  for (const [name, vals] of Object.entries(d)) {
    if (vals.includes("'unsafe-inline'")) {
      if (['script-src', 'script-src-elem', 'default-src'].includes(name)) add('unsafe-inline-script', 'HIGH', `${name} allows 'unsafe-inline' — inline <script> executes`, "replace with per-response nonces: script-src 'nonce-<random>' 'strict-dynamic'");
      else if (name.startsWith('style')) add('unsafe-inline-style', 'LOW', `${name} allows 'unsafe-inline'`, 'use style hashes or nonces');
    }
    if (vals.includes("'unsafe-eval'") && (name.startsWith('script') || name === 'default-src')) add('unsafe-eval', 'HIGH', `${name} allows 'unsafe-eval' — string-to-code execution`, 'remove it and refactor dynamic code paths');
    if (vals.includes('*')) add('wildcard-source', 'HIGH', `${name} allows the wildcard * — any host can serve that resource type`, 'enumerate exact origins');
    if (name === 'script-src' && vals.some((v) => /^https?:$/.test(v) || /^https?:\/\/\*/.test(v))) add('scheme-wide-script', 'HIGH', `${name} allows any host over a scheme`, 'list exact script origins');
    if (vals.some((v) => /^data:/i.test(v)) && (name.startsWith('script') || name === 'default-src')) add('data-uri-script', 'HIGH', `${name} allows data: URIs — script can be embedded inline`, 'drop data: from script sources');
    if (vals.some((v) => /^http:/i.test(v))) add('insecure-origin', 'MEDIUM', `${name} allows plain http: origins — MITM script injection`, 'serve and allow https only');
    if (name.includes('script') && vals.some((v) => /(googleapis|gstatic|jquery|cdnjs|jsdelivr|unpkg|bootcdn)/i.test(v)) && !vals.includes("'strict-dynamic'")) add('cdn-script-without-strict-dynamic', 'MEDIUM', `${name} trusts public CDNs without 'strict-dynamic' — JSONP/angular gadget bypasses`, "add 'strict-dynamic' with a nonce so only nonced scripts execute");
    if (vals.some((v) => /^'nonce-/.test(v)) && !vals.includes("'strict-dynamic'")) add('nonce-without-strict-dynamic', 'LOW', `${name} uses a nonce without 'strict-dynamic' — allowlisted hosts still load`, "append 'strict-dynamic'");
    if (vals.some((v) => /unsafe-hashes/.test(v))) add('unsafe-hashes', 'MEDIUM', `${name} uses 'unsafe-hashes'`, 'replace with nonces');
    if (vals.includes("'unsafe-inline'") && vals.some((v) => /^'nonce-/.test(v))) add('nonce-ignored-by-unsafe-inline', 'HIGH', `${name} mixes a nonce with 'unsafe-inline' — browsers ignore the nonce when unsafe-inline is present`, "remove 'unsafe-inline'");
  }
  if (!d['upgrade-insecure-requests'] && !d['block-all-mixed-content']) add('no-upgrade-insecure', 'LOW', 'no upgrade-insecure-requests directive', 'add upgrade-insecure-requests');
  if (!d['report-uri'] && !d['report-to']) add('no-reporting', 'INFO', 'no report-uri/report-to — violations are invisible', 'add report-to with a collection endpoint');
  if (d['frame-ancestors'] && d['frame-ancestors'].includes("'none'") === false && d['frame-ancestors'].some((v) => v === '*')) add('frame-ancestors-wildcard', 'MEDIUM', 'frame-ancestors allows any origin — clickjacking possible', "set frame-ancestors 'none'");
  if (d['sandbox'] && d['sandbox'].some((v) => /allow-scripts/.test(v) && /allow-same-origin/.test(v))) add('sandbox-escape', 'HIGH', 'sandbox allows both allow-scripts and allow-same-origin — sandbox is escapable', 'drop allow-same-origin when allow-scripts is present');
  return findings;
}

function score(findings, directives) {
  let s = 100;
  const weights = { CRITICAL: 40, HIGH: 25, MEDIUM: 12, LOW: 5, INFO: 0 };
  for (const f of findings) s -= weights[f.severity] || 0;
  if (directives["'strict-dynamic'"]) s += 0;
  if (['script-src'].some((k) => (directives[k] || []).includes("'strict-dynamic'"))) s += 10;
  const covered = IMPORTANT.filter((d) => directives[d] || (d !== 'default-src' && directives['default-src'])).length;
  s += covered * 2;
  return Math.max(0, Math.min(100, Math.round(s)));
}

function harden(directives, origin) {
  const self = origin || "'self'";
  const out = {
    'default-src': ["'none'"],
    'script-src': ["'self'", "'nonce-REPLACE_PER_RESPONSE'", "'strict-dynamic'"],
    'style-src': ["'self'", "'nonce-REPLACE_PER_RESPONSE'"],
    'img-src': ["'self'", 'data:', 'https:'],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'media-src': ["'self'"],
    'object-src': ["'none'"],
    'base-uri': ["'none'"],
    'frame-ancestors': ["'none'"],
    'form-action': ["'self'"],
    'worker-src': ["'self'"],
    'manifest-src': ["'self'"],
    'upgrade-insecure-requests': [],
    'block-all-mixed-content': [],
  };
  // Preserve host allowlists that are already safe for the resource type.
  for (const [name, vals] of Object.entries(directives)) {
    if (!out[name]) continue;
    if (name === 'script-src' || name === 'style-src') continue;
    const keep = vals.filter((v) => !/^('unsafe-|'none'|\*$|data:|http:)/i.test(v));
    for (const k of keep) if (!out[name].includes(k)) out[name].push(k);
  }
  if (directives['connect-src']) {
    const keep = directives['connect-src'].filter((v) => !/^('unsafe-|\*$|data:|http:)/i.test(v));
    for (const k of keep) if (!out['connect-src'].includes(k)) out['connect-src'].push(k);
  }
  if (directives['report-to']) out['report-to'] = directives['report-to'];
  else if (directives['report-uri']) out['report-uri'] = directives['report-uri'];
  return Object.entries(out).map(([k, v]) => (v.length ? `${k} ${v.join(' ')}` : k)).join('; ');
}

// ---- input resolution -------------------------------------------------------
let policyText = '';
let source = '';
let origin = '';
const input = o._[0];

if (input && /^https?:\/\//i.test(input)) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(input, { headers: { 'user-agent': 'cspreporter/1.0' }, signal: ctl.signal, redirect: 'follow' });
    const html = await r.text();
    source = `live fetch of ${input}`;
    origin = new URL(input).origin;
    policyText = r.headers.get(String(get(o, 'header', 'content-security-policy')).toLowerCase()) || '';
    if (!policyText) {
      const metas = [...html.matchAll(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi)].map((m) => m[0]);
      const cm = metas.map((m) => (m.match(/content=["']([^"']+)["']/i) || [])[1]).filter(Boolean);
      if (cm.length) { policyText = cm.join('; '); source += ' (meta tag)'; }
    }
  } catch (e) {
    die(`fetch failed: ${e.name === 'AbortError' ? 'timeout' : e.message}`);
  } finally { clearTimeout(t); }
} else {
  const looksLikePolicy = input && /(^|;\s*)(default-src|script-src|style-src|img-src|object-src|connect-src)\b/.test(input);
  const exists = input && input !== '-' && existsSync(input);
  if (looksLikePolicy && !exists) {
    policyText = input;
    source = 'inline policy argument';
  } else {
    policyText = input ? await readInput(input) : await readInput(null);
    source = input && input !== '-' ? `file ${input}` : 'stdin';
  }
  try { origin = new URL(policyText.trim().match(/^https?:\/\/\S+/)?.[0] || '').origin; } catch { origin = ''; }
}

const { directives, raw, empty } = parsePolicy(policyText);
const findings = analyse(directives);
const sc = score(findings, directives);
const hardened = harden(directives, origin);

if (flag(o, 'json')) {
  console.log(JSON.stringify({
    source, policy: raw, empty, score: sc, grade: sc >= 85 ? 'A' : sc >= 70 ? 'B' : sc >= 55 ? 'C' : sc >= 35 ? 'D' : 'F',
    directives, directive_count: Object.keys(directives).length,
    findings, hardened_policy: hardened,
  }, null, 2));
  exitSoon(0);
}

if (flag(o, 'emit-only')) { console.log(hardened); exitSoon(0); }

console.log(`source : ${source}`);
console.log(`policy : ${raw ? raw.slice(0, 300) + (raw.length > 300 ? ' ...' : '') : '(absent)'}`);
console.log(`score  : ${sc}/100  grade ${sc >= 85 ? 'A' : sc >= 70 ? 'B' : sc >= 55 ? 'C' : sc >= 35 ? 'D' : 'F'}  (${Object.keys(directives).length} directives)`);

if (Object.keys(directives).length) {
  console.log('\n' + table(Object.entries(directives).map(([k, v]) => ({ directive: k, value: v.join(' ').slice(0, 70) }))));
}

if (findings.length) {
  console.log('\n' + table(findings.map((f) => ({ severity: f.severity, id: f.id, detail: f.detail.slice(0, 60), fix: f.fix.slice(0, 44) }))));
  console.log('\nDetail:');
  for (const f of findings) console.log(`  [${f.severity}] ${f.id}: ${f.detail}\n      fix: ${f.fix}`);
} else {
  console.log('\nno weaknesses detected in the parsed policy');
}

console.log('\n--- hardened policy ---');
console.log(hardened);
exitSoon(0);
