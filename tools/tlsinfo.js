#!/usr/bin/env node
// tlsinfo.js — TLS certificate and protocol inspector.
// Copyright (c) 2026 0xnothings
// @tool tlsinfo
// @desc Inspect a host's TLS certificate: subject, SANs, issuer, expiry countdown, protocol version
// @usage node tools/tlsinfo.js example.com:443 --json
// @tags security,tls,recon
import tls from 'node:tls';
import { args, num, flag, die, inputLines, table, get } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`tlsinfo — TLS certificate inspector

  node tools/tlsinfo.js <host[:port]|hosts.txt|-> [options]

  --port <n>       default port (default: 443)
  --timeout <ms>   handshake timeout (default: 8000)
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

function inspect(host, port, timeout) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout }, () => {
      const c = sock.getPeerCertificate();
      const p = sock.getProtocol();
      const expiry = c.valid_to ? new Date(c.valid_to) : null;
      const days = expiry ? Math.floor((expiry - Date.now()) / 86400000) : null;
      resolve({
        host, port, protocol: p, cipher: sock.getCipher()?.name,
        subject: c.subject?.CN || '-', issuer: (c.issuer?.O || c.issuer?.CN || '-'),
        valid_from: c.valid_from, valid_to: c.valid_to, days_left: days,
        expired: days !== null && days < 0,
        self_signed: JSON.stringify(c.subject) === JSON.stringify(c.issuer),
        sans: (c.subjectaltname || '').split(',').map((s) => s.replace(/^DNS:/, '').trim()).filter(Boolean),
        serial: c.serialNumber, fingerprint256: c.fingerprint256,
      });
      sock.end();
    });
    sock.once('timeout', () => { sock.destroy(); resolve({ host, port, error: 'timeout' }); });
    sock.once('error', (e) => resolve({ host, port, error: e.code || e.message }));
  });
}

let entries = o._.length ? o._ : ['-'];
let hosts = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) hosts.push(...(await inputLines(e))); else hosts.push(e);
hosts = [...new Set(hosts.filter(Boolean))];
if (!hosts.length) die('no hosts given');

const defPort = num(o.f.port, 443);
const timeout = num(get(o, 'timeout'), 8000);
const results = [];
for (const h of hosts) {
  const [host, port] = h.includes(':') ? h.split(':') : [h, defPort];
  results.push(await inspect(host.trim(), Number(port) || defPort, timeout));
}

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); process.exit(0); }

console.log(table(results.map((r) => ({
  host: r.host, port: r.port, error: r.error || '',
  protocol: r.protocol || '', subject: r.subject || '', issuer: r.issuer || '',
  days_left: r.days_left ?? '', expiry: (r.valid_to || '').slice(0, 11), flags: [r.expired && 'EXPIRED', r.self_signed && 'SELF-SIGNED'].filter(Boolean).join(' '),
}))));

for (const r of results.filter((x) => !x.error)) {
  console.log(`\n${r.host}:${r.port}  ${r.days_left} days left${r.sans.length ? '  SANs: ' + r.sans.slice(0, 8).join(', ') + (r.sans.length > 8 ? ` (+${r.sans.length - 8})` : '') : ''}`);
  if (r.days_left !== null && r.days_left < 14) console.log(`  [!] certificate expires in ${r.days_left} days`);
}
