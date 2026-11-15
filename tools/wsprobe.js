#!/usr/bin/env node
// wsprobe.js — WebSocket handshake and message-layer probe.
// Copyright (c) 2026 0xnothings
// @tool wsprobe
// @desc Test a WebSocket endpoint: unauthenticated upgrade, origin validation bypass, subprotocol injection and message echo
// @usage node tools/wsprobe.js wss://target/socket --json
// @tags security,web,websocket
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`wsprobe — WebSocket handshake probe

  node tools/wsprobe.js <ws://host/path|wss://host/path|list.txt|-> [options]

  --origin <o>       origin value to test (default: evil.example)
  --origins <list>   comma list of origins to try
  --subprotocol <p>  requested subprotocol (default: none)
  --cookie <c>       Cookie header to send
  --bearer <t>       Authorization: Bearer ***
  --msg <text>       message to send after upgrade (echo probe)
  --timeout <ms>     handshake timeout (default: 8000)
  --json             machine-readable output
  -h, --help         this text

  Checks: 101 upgrade without credentials (vs 401/403 baseline), reflected
  or missing Origin validation, X-Forwarded-* spoofing of the Origin,
  subprotocol negotiation, and whether frames are echoed back.`);
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
const msg = get(o, 'msg', 'wsprobe-ping-7391');

function b64(buf) { return Buffer.from(buf).toString('base64'); }

function wsHandshake(host, port, path, useTls, headers, wantMsg, ms) {
  return new Promise((resolve) => {
    const key = b64(crypto.randomBytes(16));
    const reqHeaders = [
      `GET ${path} HTTP/1.1`,
      `Host: ${host}${port === (useTls ? 443 : 80) ? '' : ':' + port}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Key: ${key}`,
      'Sec-WebSocket-Version: 13',
      'User-Agent: wsprobe/1.0',
      ...Object.entries(headers || {}).map(([k, v]) => `${k}: ${v}`),
      '', '',
    ].join('\r\n');

    let done = false;
    const chunks = [];
    const fin = (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch { /* ignore */ }
      const text = Buffer.concat(chunks).toString('latin1');
      const headEnd = text.indexOf('\r\n\r\n');
      const head = headEnd >= 0 ? text.slice(0, headEnd) : text;
      const bodyRaw = headEnd >= 0 ? text.slice(headEnd + 4) : '';
      const status = Number((head.match(/^HTTP\/1\.1 (\d{3})/) || [])[1] || 0);
      const hdrs = {};
      for (const line of head.split('\r\n').slice(1)) {
        const i = line.indexOf(':');
        if (i > 0) hdrs[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      // Decode any websocket frames the server sent back.
      const frames = [];
      let buf = Buffer.from(bodyRaw, 'latin1');
      while (buf.length >= 2) {
        const opcode = buf[0] & 0x0f;
        let len = buf[1] & 0x7f;
        let off = 2;
        if (len === 126) { if (buf.length < 4) break; len = buf.readUInt16BE(2); off = 4; }
        else if (len === 127) { if (buf.length < 10) break; len = Number(buf.readBigUInt64BE(2)); off = 10; }
        if (buf.length < off + len) break;
        frames.push({ opcode, payload: buf.slice(off, off + len).toString('utf8').slice(0, 300) });
        buf = buf.slice(off + len);
      }
      resolve({ status, headers: hdrs, frames, error: err || null, accept: hdrs['sec-websocket-accept'] || null, expected_accept: b64(crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest()) });
    };

    let sock;
    const onConnect = () => {
      sock.write(reqHeaders);
      if (wantMsg && done === false) {
        setTimeout(() => {
          if (done) return;
          const payload = Buffer.from(wantMsg, 'utf8');
          const mask = crypto.randomBytes(4);
          const masked = Buffer.from(payload.map((b, i) => b ^ mask[i % 4]));
          const header = Buffer.from([0x81, 0x80 | payload.length]);
          try { sock.write(Buffer.concat([header, mask, masked])); } catch { /* ignore */ }
        }, 250);
      }
    };
    if (useTls) sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: ms }, onConnect);
    else sock = net.connect({ host, port }, onConnect);
    const timer = setTimeout(() => fin('timeout'), ms);
    sock.on('data', (c) => { chunks.push(c); if (Buffer.concat(chunks).length > 32768) fin(null); });
    sock.on('error', (e) => fin(e.code || e.message));
    sock.on('close', () => fin(null));
  });
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) urls.push(...(await inputLines(e)));
  else urls.push(e);
}
urls = [...new Set(urls.filter(Boolean))];
if (!urls.length) die('no ws URL given');

const originList = String(get(o, 'origins', get(o, 'origin', 'evil.example'))).split(',').map((s) => s.trim()).filter(Boolean);
const results = [];

for (const raw of urls) {
  const m = raw.match(/^(wss?|https?):\/\/([^\/]+)(\/.*)?$/);
  if (!m) { die(`cannot parse "${raw}" — expected ws://host/path or wss://host/path`); }
  const scheme = m[1];
  const useTls = scheme === 'wss' || scheme === 'https';
  const [host, portStr] = m[2].split(':');
  const port = Number(portStr) || (useTls ? 443 : 80);
  const path = m[3] || '/';

  const baseHeaders = {};
  if (o.f.cookie) baseHeaders.cookie = String(o.f.cookie);
  if (o.f.bearer) baseHeaders.authorization = `Bearer ${String(o.f.bearer)}`;
  if (o.f.subprotocol) baseHeaders['sec-websocket-protocol'] = String(o.f.subprotocol);

  const tests = [];
  const baseline = await wsHandshake(host, port, path, useTls, baseHeaders, null, timeout);
  tests.push({
    id: 'baseline-no-origin', vector: 'plain upgrade (no Origin, no credentials)',
    status: baseline.status, accept_valid: baseline.accept === baseline.expected_accept,
    verdict: baseline.status === 101 && !o.f.cookie && !o.f.bearer ? 'MEDIUM' : null,
    evidence: [baseline.status === 101
      ? (o.f.cookie || o.f.bearer ? 'upgraded with supplied credentials' : 'upgraded without any credentials (unauthenticated socket)')
      : `server refused: HTTP ${baseline.status}`],
    headers: baseline.headers,
  });

  for (const origin of originList) {
    const r = await wsHandshake(host, port, path, useTls, { ...baseHeaders, origin: `https://${origin}` }, null, timeout);
    const accepted = r.status === 101;
    const sameAsBaseline = r.status === baseline.status;
    const ev = [];
    let verdict = null;
    if (accepted && baseline.status === 101) { ev.push(`foreign Origin https://${origin} accepted (no origin check)`); verdict = 'HIGH'; }
    else if (accepted && baseline.status !== 101) { ev.push(`Origin https://${origin} allowed upgrade while the plain request was ${baseline.status} — origin-based auth bypass`); verdict = 'CRITICAL'; }
    else if (!accepted && !sameAsBaseline) { ev.push(`Origin https://${origin} -> HTTP ${r.status} (differs from baseline ${baseline.status})`); verdict = 'LOW'; }
    else ev.push(`Origin rejected/treated as baseline (HTTP ${r.status})`);
    tests.push({ id: `origin:${origin}`, vector: 'Origin validation', status: r.status, accept_valid: r.accept === r.expected_accept, verdict, evidence: ev, headers: r.headers });
  }

  // Header-spoofed origins: proxies frequently trust these instead of Origin.
  for (const h of ['x-forwarded-host', 'x-forwarded-for', 'x-real-ip', 'x-origin']) {
    const r = await wsHandshake(host, port, path, useTls, { ...baseHeaders, [h]: `https://${originList[0]}` }, null, timeout);
    const accepted = r.status === 101;
    tests.push({
      id: `spoof:${h}`, vector: `${h} spoofing`,
      status: r.status, accept_valid: r.accept === r.expected_accept,
      verdict: accepted && baseline.status === 101 ? 'MEDIUM' : null,
      evidence: [accepted ? `${h} spoof accepted; if the backend trusts it, origin checks are bypassable` : `rejected (HTTP ${r.status})`],
      headers: r.headers,
    });
    await new Promise((s) => setTimeout(s, 80));
  }

  // Subprotocol negotiation abuse.
  for (const sp of ['admin', 'graphql-ws', 'json', 'bearer-token,'.slice(0, -1), 'x'.repeat(200)]) {
    const r = await wsHandshake(host, port, path, useTls, { ...baseHeaders, 'sec-websocket-protocol': sp }, null, timeout);
    const negotiated = r.headers['sec-websocket-protocol'];
    tests.push({
      id: `subprotocol:${sp.slice(0, 12)}`, vector: 'subprotocol negotiation',
      status: r.status, accept_valid: r.accept === r.expected_accept,
      verdict: negotiated && negotiated !== sp ? 'LOW' : null,
      evidence: [negotiated ? `server selected subprotocol "${negotiated}" (requested "${sp.slice(0, 20)}")` : `no subprotocol negotiated (HTTP ${r.status})`],
      headers: r.headers,
    });
  }

  // Message-layer echo probe.
  const echo = await wsHandshake(host, port, path, useTls, baseHeaders, msg, timeout);
  const echoed = echo.frames.filter((f) => f.payload.includes(msg));
  tests.push({
    id: 'message-echo', vector: 'post-upgrade message',
    status: echo.status, accept_valid: echo.accept === echo.expected_accept,
    verdict: echoed.length ? 'LOW' : null,
    evidence: [echo.frames.length
      ? `received ${echo.frames.length} frame(s): ${echo.frames.map((f) => `op=0x${f.opcode.toString(16)} "${f.payload.slice(0, 60)}"`).join(' | ')}`
      : 'no frames returned within the timeout'],
    frames: echo.frames, headers: echo.headers,
  });

  const findings = tests.filter((t) => t.verdict && t.verdict !== 'LOW');
  results.push({ url: raw, host, port, path, tls: useTls, findings_count: findings.length, tests, findings });
}

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); exitSoon(results.some((r) => r.findings.length) ? 1 : 0); }

for (const r of results) {
  console.log(`\n### ${r.url}  (${r.tls ? 'tls' : 'plain'} ${r.host}:${r.port}${r.path})`);
  console.log(table(r.tests.map((t) => ({
    probe: t.id.slice(0, 24), vector: t.vector.slice(0, 22), status: t.status,
    accept_ok: t.accept_valid === undefined ? '' : (t.accept_valid ? 'yes' : 'no'),
    verdict: t.verdict || '-', evidence: (t.evidence[0] || '').slice(0, 50),
  }))));
  if (r.findings.length) {
    console.log(`FINDINGS (${r.findings.length}):`);
    for (const f of r.findings) console.log(`  [${f.verdict}] ${f.id}: ${f.evidence.join('; ')}`);
  } else console.log('no handshake weaknesses detected');
}
exitSoon(results.some((r) => r.findings.length) ? 1 : 0);
