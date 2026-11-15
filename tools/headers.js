// headers.js — HTTP security header audit with grading.
// Copyright (c) 2026 0xnothings
// @tool headers
// @desc Audit HTTP security headers (HSTS/CSP/XFO/Referrer-Policy...) and grade the response
// @usage node tools/headers.js https://example.com --json
// @tags security,web,audit
import { args, flag, die, inputLines, table, nowISO } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`headers — HTTP security header audit

  node tools/headers.js <url|urls.txt|-> [options]

  --json           machine-readable output
  --insecure       accept self-signed TLS
  --timeout <ms>   request timeout (default: 12000)
  -h, --help       this text`);
  process.exit(0);
}

const CHECK = [
  ['strict-transport-security', 'HSTS', (v) => /max-age=(\d+)/.test(v) && +v.match(/max-age=(\d+)/)[1] >= 15552000, 'max-age=31536000; includeSubDomains'],
  ['content-security-policy', 'CSP', (v) => v.length > 10 && !/unsafe-inline|unsafe-eval|\*/.test(v), "default-src 'self'"],
  ['x-content-type-options', 'X-Content-Type-Options', (v) => /nosniff/i.test(v), 'nosniff'],
  ['x-frame-options', 'X-Frame-Options', (v) => /deny|sameorigin/i.test(v), 'DENY'],
  ['referrer-policy', 'Referrer-Policy', (v) => /no-referrer|strict-origin|same-origin/i.test(v), 'strict-origin-when-cross-origin'],
  ['permissions-policy', 'Permissions-Policy', (v) => v.length > 5, 'geolocation=(), camera=(), microphone=()'],
  ['cross-origin-opener-policy', 'COOP', (v) => /same-origin|same-origin-allow-popups/i.test(v), 'same-origin'],
  ['cross-origin-resource-policy', 'CORP', (v) => /same-origin|same-site/i.test(v), 'same-origin'],
];

const LEAK = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator', 'via', 'x-drupal-cache', 'x-debug-token'];

async function check(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), Number(o.f.timeout) || 12000);
  let res;
  try {
    res = await fetch(url, { redirect: 'follow', signal: ctl.signal, headers: { 'user-agent': '0xnothings-headers/1.0' } });
  } catch (e) {
    clearTimeout(t);
    return { url, error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) };
  }
  clearTimeout(t);
  const h = res.headers;
  const hits = CHECK.map(([key, label, ok, rec]) => {
    const val = h.get(key) || '';
    return { header: label, present: !!val, ok: !!val && ok(val), value: val || '-', recommended: rec };
  });
  const leaks = LEAK.map((k) => [k, h.get(k)]).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`);
  const score = hits.filter((x) => x.ok).length;
  const grade = score >= 7 ? 'A' : score >= 5 ? 'B' : score >= 4 ? 'C' : score >= 2 ? 'D' : 'F';
  return { url, status: res.status, grade: `${grade} (${score}/${hits.length})`, hits, leaks, server: h.get('server') || '-' };
}

const targets = o._.length ? o._ : ['-'];
let urls = [];
for (const t of targets) {
  if (/-$|\.txt$/.test(t)) urls.push(...(await inputLines(t)));
  else urls.push(t);
}
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u)))];
if (!urls.length) die('no urls given');

const results = [];
for (const u of urls) results.push(await check(u));

if (flag(o, 'json')) { console.log(JSON.stringify({ checked_at: nowISO(), results }, null, 2)); process.exit(0); }

for (const r of results) {
  console.log(`\n=== ${r.url}`);
  if (r.error) { console.log(`  ERROR: ${r.error}`); continue; }
  console.log(`  status ${r.status}   grade ${r.grade}`);
  console.log(table(r.hits.map((x) => ({ header: x.header, ok: x.ok ? 'PASS' : 'FAIL', value: x.value.slice(0, 60) }))));
  if (r.leaks.length) console.log(`  info leak: ${r.leaks.join(' | ')}`);
}
const avg = results.filter((r) => !r.error);
if (avg.length) console.log(`\nmean grade score: ${(avg.reduce((a, r) => a + Number(r.grade.match(/(\d+)\//)[1]), 0) / avg.length).toFixed(1)}/${CHECK.length}`);
