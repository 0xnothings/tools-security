// svcfinger.js — banner-grab and fingerprint services on open TCP ports.
// Copyright (c) 2026 0xnothings
// @tool svcfinger
// @desc Banner-grab open TCP ports and fingerprint the service behind them (HTTP/TLS/SMTP/FTP/SSH with correct verbs)
// @usage node tools/svcfinger.js 10.0.0.1 --ports 22,80,443 --json
// @tags security,recon,network
import net from 'node:net';
import tls from 'node:tls';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`svcfinger — TCP banner grabber and service fingerprinter

  node tools/svcfinger.js <host|hosts.txt|-> [options]

  --ports <list>     comma list or ranges, e.g. 22,80,443,8000-8100
  --top              use the built-in 40-port common list (default)
  --timeout <ms>     per-probe wait (default: 4000)
  --conc <n>         parallel sockets (default: 32)
  --json             machine-readable output
  -h, --help         this text

  Protocols are probed with real verbs: HEAD / for HTTP, EHLO for SMTP,
  USER anonymous for FTP, TLS handshake for 443/993/465/8443, raw banner else.`);
  process.exit(0);
}

const COMMON = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 636,
  993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5985,
  6379, 8000, 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017, 50000,
];

const TLS_PORTS = new Set([443, 465, 636, 993, 995, 990, 8443, 8834, 9443, 5986]);

function parsePorts(spec) {
  const out = new Set();
  for (const part of String(spec).split(',')) {
    const p = part.trim();
    if (!p) continue;
    const m = p.match(/^(\d+)\s*-\s*(\d+)$/);
    if (m) {
      const a = Number(m[1]), b = Number(m[2]);
      if (b < a) continue;
      if (b - a > 5000) die('port range too large (max 5000)');
      for (let i = a; i <= b; i++) out.add(i);
    } else if (/^\d+$/.test(p)) out.add(Number(p));
  }
  return [...out].filter((p) => p > 0 && p < 65536).sort((a, b) => a - b);
}

function payloadFor(port, host) {
  if ([80, 8080, 8000, 8888, 8081, 3000, 5000, 9000].includes(port))
    return `HEAD / HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: svcfinger/1.0\r\nAccept: */*\r\n\r\n`;
  if (port === 25 || port === 587) return `EHLO svcfinger.local\r\n`;
  if (port === 21) return `USER anonymous\r\n`;
  if (port === 110) return `USER test\r\n`;
  if (port === 143) return `a1 CAPABILITY\r\n`;
  if (port === 3306) return null;
  return null;
}

function tcpProbe(host, port, waitMs) {
  return new Promise((resolve) => {
    const chunks = [];
    let settled = false;
    let idle = null;
    const sock = net.connect({ host, port });
    const finish = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(hard);
      if (idle) clearTimeout(idle);
      try { sock.destroy(); } catch { /* already gone */ }
      resolve({ raw: Buffer.concat(chunks).toString('latin1'), bytes: Buffer.concat(chunks).length, error: err || null });
    };
    const hard = setTimeout(() => finish(null), waitMs);
    sock.on('connect', () => {
      const p = payloadFor(port, host);
      if (p) sock.write(p);
    });
    sock.on('data', (c) => {
      chunks.push(c);
      if (idle) clearTimeout(idle);
      idle = setTimeout(() => finish(null), 400);
      const total = chunks.reduce((n, b) => n + b.length, 0);
      if (total > 16384) finish(null);
    });
    sock.on('error', (e) => finish(e.code || e.message || 'error'));
    sock.on('close', () => finish(null));
  });
}

function tlsProbe(host, port, waitMs) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: waitMs }, () => {
      const c = sock.getPeerCertificate() || {};
      const bits = c.bits;
      done({
        tls: sock.getProtocol() || null,
        cipher: sock.getCipher()?.name || null,
        cert_cn: c.subject?.CN || null,
        cert_issuer: (c.issuer?.O || c.issuer?.CN || null),
        cert_bits: bits || null,
        cert_expires: c.valid_to || null,
        alpn: sock.alpnProtocol || null,
      });
      try { sock.end(); } catch { /* ignore */ }
    });
    sock.setTimeout(waitMs, () => { try { sock.destroy(); } catch { /* ignore */ } done({}); });
    sock.once('error', () => done({}));
  });
}

function fingerprint(raw, port) {
  const s = raw;
  const low = s.toLowerCase();
  const hits = [];
  const push = (v, ver) => { hits.push({ svc: v, ver: ver || '' }); };

  if (/^ssh-/i.test(s)) push('ssh', (s.match(/^SSH-[\d.]+-([^\s\r\n]+)/) || [])[1] || '');
  if (/^\s*220[\s-]/.test(s) && /smtp|esmtp|postfix|exim|sendmail|microsoft/i.test(low)) push('smtp', (s.match(/\b(Postfix|Exim|Sendmail|Microsoft ESMTP[^\r\n]*)/i) || [])[1] || '');
  else if (/^\s*220[\s-]/.test(s) && port === 21) push('ftp', (s.match(/\b(vsftpd|proftpd|pure-ftpd|FileZilla|Microsoft FTP)[^\r\n]*/i) || [])[1] || '');
  else if (/^\s*220[\s-]/.test(s)) push('ftp-or-smtp', (s.split(/\r?\n/)[0] || '').slice(0, 60));
  if (/^\* OK/i.test(s) || /CAPABILITY/i.test(low) && /imap/i.test(low)) push('imap', (s.match(/(Dovecot|Cyrus|Exchange)/i) || [])[1] || '');
  if (/^\+OK/i.test(s)) push('pop3', (s.match(/(Dovecot|Courier|qpopper)/i) || [])[1] || '');
  if (/^HTTP\/[\d.]+\s+\d{3}/i.test(s)) push('http', '');
  const srv = s.match(/^Server:\s*(.+)$/im);
  if (srv) push('http-server', srv[1].trim());
  const pw = s.match(/^X-Powered-By:\s*(.+)$/im);
  if (pw) push('powered-by', pw[1].trim());
  const aspnet = s.match(/^X-AspNet-Version:\s*(.+)$/im);
  if (aspnet) push('aspnet', aspnet[1].trim());
  if (/^-ERR|^\+PONG|redis_version/i.test(s)) push('redis', (s.match(/redis_version:([\d.]+)/) || [])[1] || '');
  if (/mongodb|ismaster|helloOk/i.test(s)) push('mongodb', '');
  if (/mysql_native_password|MariaDB/i.test(s)) push('mysql', (s.match(/(\d+\.\d+\.\d+[^\s-]*)/) || [])[1] || '');
  if (/SSH-2\.0-OpenSSH/i.test(s)) push('openssh', (s.match(/OpenSSH[_-]([\d.p]+)/) || [])[1] || '');
  if (/VMware|ESXi/i.test(s)) push('vmware', '');
  if (/RFB \d{3}/.test(s)) push('vnc', (s.match(/RFB (\d{3}\.\d{3})/) || [])[1] || '');
  if (/^SMTP|PJL|@PJL/i.test(s)) push('jetdirect', '');
  if (/^\x00\x00/ && port === 445) push('smb', '');
  if (/AIRPLAY|AirTunes/i.test(s)) push('airplay', '');
  if (/^\*\* +\*+/.test(s) && port === 6379) push('redis-inline', '');
  if (/http\/1\.1 400|Bad Request/i.test(s) && /gnutls|cloudflare/i.test(low)) push('tls-plaintext', '');
  if (!hits.length && s.length) push('unknown', '');
  return hits;
}

const timeout = num(get(o, 'timeout'), 4000);
const conc = num(get(o, 'conc'), 32);
const jsonOut = flag(o, 'json');

let targets = o._.length ? o._ : ['-'];
let hosts = [];
for (const t of targets) {
  if (t === '-' || /\.txt$/.test(t)) hosts.push(...(await inputLines(t)));
  else hosts.push(t.replace(/^https?:\/\//, '').split('/')[0]);
}
hosts = [...new Set(hosts.filter(Boolean))];
if (!hosts.length) die('no hosts given');

const ports = parsePorts(get(o, 'ports', flag(o, 'top') ? COMMON.join(',') : COMMON.join(',')));

const jobs = [];
for (const h of hosts) for (const p of ports) jobs.push([h, p]);

const results = [];
let cursor = 0;
async function worker() {
  while (cursor < jobs.length) {
    const [host, port] = jobs[cursor++];
    let rec = { host, port, state: 'open', service: '', version: '', tls: null, banner: '' };
    const r = await tcpProbe(host, port, timeout);
    if (r.error && !r.bytes) {
      rec.state = 'closed';
      rec.error = r.error;
      results.push(rec);
      continue;
    }
    rec.banner = r.raw.replace(/\r/g, '').split('\n').filter(Boolean).slice(0, 3).join(' | ').slice(0, 160);
    const fp = fingerprint(r.raw, port);
    if (fp.length) { rec.service = fp.map((x) => x.svc).join('/'); rec.version = fp.map((x) => x.ver).filter(Boolean).join(' '); }
    if (TLS_PORTS.has(port) || (r.raw === '' && TLS_PORTS.has(port))) {
      const t = await tlsProbe(host, port, timeout);
      if (t.tls) {
        rec.tls = t.tls;
        rec.cipher = t.cipher;
        rec.cert_cn = t.cert_cn;
        rec.cert_issuer = t.cert_issuer;
        rec.cert_bits = t.cert_bits;
        if (!rec.service) { rec.service = 'https'; rec.version = `(${t.tls})`; }
      }
    }
    results.push(rec);
  }
}
await Promise.all(Array.from({ length: Math.min(conc, jobs.length || 1) }, worker));

const open = results.filter((r) => r.state === 'open');
if (jsonOut) {
  console.log(JSON.stringify({ host_count: hosts.length, ports_scanned: ports.length, open: open.length, results: open }, null, 2));
  process.exit(0);
}

console.log(table(open.map((r) => ({
  host: r.host, port: r.port, service: r.service || '?', version: r.version || '',
  tls: r.tls || '', cert: r.cert_cn || '', banner: r.banner.slice(0, 48),
}))));
console.log(`\n${hosts.length} host(s) x ${ports.length} port(s) -> ${open.length} open`);
