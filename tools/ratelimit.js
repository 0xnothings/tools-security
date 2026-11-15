#!/usr/bin/env node
// ratelimit.js — auth rate-limit and lockout behaviour tester.
// Copyright (c) 2026 0xnothings
// @tool ratelimit
// @desc Sequentially probe a login/OTP endpoint to measure throttling, lockout and Retry-After behaviour
// @usage node tools/ratelimit.js https://site.com/api/login --field email --value you@x.com --attempts 15
// @tags security,auth,ratelimit
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`ratelimit — auth throttling / lockout tester

  node tools/ratelimit.js <login-url> [options]

  --field <name>     the identifier field (default: email)
  --value <v>        identifier value (default: 0xnothings-probe@example.com)
  --passfield <n>    password field name (default: password)
  --attempts <n>     number of attempts, keep low (default: 12)
  --gap <ms>         delay between attempts (default: 250)
  --method <m>       POST (default) or GET
  --json             machine-readable output
  -h, --help         this text

  Use only against systems you own or are engaged to test.
  Defaults intentionally stay under typical lockout thresholds.`);
  process.exit(0);
}

const url = o._[0];
if (!url) die('usage: node tools/ratelimit.js <login-url> --field email --value x@y.z --attempts 12');
const field = String(get(o, 'field', 'email'));
const value = String(get(o, 'value', '0xnothings-probe@example.com'));
const passfield = String(get(o, 'passfield', 'password'));
const attempts = Math.min(num(get(o, 'attempts'), 12), 50);
const gap = num(get(o, 'gap'), 250);
const method = String(get(o, 'method', 'POST')).toUpperCase();

const rows = [];
for (let i = 0; i < attempts; i++) {
  const t0 = Date.now();
  const body = new URLSearchParams({ [field]: value, [passfield]: `wrong-${Math.random().toString(36).slice(2, 10)}` });
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 12000);
  try {
    const res = method === 'GET'
      ? await fetch(`${url}${url.includes('?') ? '&' : '?'}${body}`, { signal: ctl.signal, redirect: 'manual', headers: { 'user-agent': '0xnothings-ratelimit/1.0' } })
      : await fetch(url, { method: 'POST', signal: ctl.signal, redirect: 'manual', body, headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': '0xnothings-ratelimit/1.0' } });
    const text = await res.text().catch(() => '');
    rows.push({ n: i + 1, status: res.status, ms: Date.now() - t0, retryAfter: res.headers.get('retry-after') || '-', xRat: res.headers.get('x-ratelimit-remaining') || '-', snippet: text.slice(0, 60).replace(/\s+/g, ' ') });
  } catch (e) {
    rows.push({ n: i + 1, status: 'ERR', ms: Date.now() - t0, retryAfter: '-', xRat: '-', snippet: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) });
  } finally { clearTimeout(t); }
  if (i < attempts - 1) await new Promise((r) => setTimeout(r, gap));
}

const statuses = [...new Set(rows.map((r) => r.status))];
const throttled = rows.some((r) => r.status === 429 || /too many|rate limit|try again later|locked|blocked/i.test(r.snippet));
const lockout = rows.some((r) => /locked|suspended|disabled|account.*blocked/i.test(r.snippet));
const first429 = rows.find((r) => r.status === 429);
const timeGrowth = rows.length > 3 && rows[rows.length - 1].ms > rows[0].ms * 3;

const verdict = lockout ? 'LOCKOUT observed — account lock behaviour active'
  : throttled ? `THROTTLED at attempt ${first429?.n ?? '?'} (429/limit text)`
  : timeGrowth ? 'no 429 but latency climbing — possible progressive delay'
  : 'NO THROTTLING observed within the test window';

if (flag(o, 'json')) console.log(JSON.stringify({ url, attempts, verdict, statuses, rows }, null, 2));
else {
  console.log(table(rows.map((r) => ({ n: r.n, status: r.status, ms: r.ms, retry_after: r.retryAfter, remain: r.xRat, body: r.snippet.slice(0, 44) }))));
  console.log(`\nverdict: ${verdict}`);
  console.log(`distinct status codes: ${statuses.join(', ')}`);
}
