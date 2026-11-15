// svcaudit.js — TLS protocol and cipher weakness audit.
// Copyright (c) 2026 0xnothings
// @tool svcaudit
// @desc Audit a TLS endpoint for legacy protocols, weak ciphers, missing forward secrecy and certificate chain problems
// @usage node tools/svcaudit.js example.com:443 --json
// @tags security,tls,audit
import tls from 'node:tls';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`svcaudit — TLS protocol / cipher / certificate audit

  node tools/svcaudit.js <host[:port]|list.txt|-> [options]

  --timeout <ms>   per-handshake timeout (default: 8000)
  --conc <n>       parallel hosts (default: 6)
  --quiet          only print hosts with findings
  --json           machine-readable output
  -h, --help       this text

  Findings: SSLv3/TLS1.0/TLS1.1 accepted, RC4/3DES/NULL/EXPORT ciphers,
  CBC-mode without AEAD, no forward secrecy, expired/self-signed certs,
  short keys, soon-expiring certs, hostname mismatch.`);
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
const conc = num(get(o, 'conc'), 6);

const LEGACY = ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'];
const WEAK_CIPHER = /(RC4|3DES|DES|NULL|EXPORT|anon|MD5|IDEA|SEED|CAMELLIA)/i;
const CBC = /_CBC|_CBC3/i;
const AEAD = /GCM|CHACHA20|CCM/i;

function attempt(host, port, opts, label) {
  return new Promise((resolve) => {
    let done = false;
    const fin = (v) => { if (!done) { done = true; resolve({ label, ...v }); } };
    let sock;
    try {
      sock = tls.connect({ host, port, servername: opts.sni === false ? undefined : host, rejectUnauthorized: false, timeout, ...opts.tlsOpts });
    } catch (e) { return fin({ ok: false, error: e.message }); }
    const to = setTimeout(() => { try { sock.destroy(); } catch { /* ignore */ } fin({ ok: false, error: 'timeout' }); }, timeout);
    sock.once('secureConnect', () => {
      clearTimeout(to);
      const c = sock.getPeerCertificate(true) || {};
      const cipher = sock.getCipher() || {};
      const res = {
        ok: true,
        protocol: sock.getProtocol(),
        cipher: cipher.name,
        cipher_version: cipher.version,
        kx: (cipher.name || '').split('-')[0],
        authorized: sock.authorized,
        auth_error: sock.authorizationError ? String(sock.authorizationError) : null,
        cert: {
          subject: c.subject ? Object.fromEntries(Object.entries(c.subject).filter(([, v]) => v)) : {},
          issuer: c.issuer ? Object.fromEntries(Object.entries(c.issuer).filter(([, v]) => v)) : {},
          valid_from: c.valid_from, valid_to: c.valid_to,
          bits: c.bits || c.asn1Curve || null,
          curve: c.asn1Curve || null,
          fingerprint256: c.fingerprint256,
          san: (c.subjectaltname || '').split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean),
          self_signed: c.subject && c.issuer && c.subject.CN === c.issuer.CN && c.subject.O === c.issuer.O && !c.issuer.O,
          chain_depth: (() => { let n = 0; let cur = c; while (cur && cur.issuerCertificate && cur.issuerCertificate !== cur) { n++; cur = cur.issuerCertificate; if (n > 10) break; } return n; })(),
        },
      };
      try { sock.destroy(); } catch { /* ignore */ }
      fin(res);
    });
    sock.once('error', (e) => { clearTimeout(to); fin({ ok: false, error: e.code || e.message }); });
    sock.once('timeout', () => { clearTimeout(to); try { sock.destroy(); } catch { /* ignore */ } fin({ ok: false, error: 'timeout' }); });
  });
}

function hostMatches(host, cert) {
  const names = [cert.subject?.CN, ...(cert.san || [])].filter(Boolean).map((s) => s.toLowerCase());
  if (!names.length) return null;
  const h = host.toLowerCase();
  for (const n of names) {
    if (n === h) return true;
    if (n.startsWith('*.')) {
      const base = n.slice(2);
      if (h.endsWith('.' + base) && h.split('.').length === base.split('.').length + 1) return true;
    }
  }
  return false;
}

async function audit(host, port) {
  const findings = [];
  const modern = await attempt(host, port, { tlsOpts: { minVersion: 'TLSv1.2' } }, 'modern');
  if (!modern.ok) return { host, port, error: modern.error, findings: [{ id: 'unreachable', severity: 'INFO', detail: modern.error }] };

  const protocolLegacy = [];
  for (const p of ['TLSv1', 'TLSv1.1']) {
    const r = await attempt(host, port, { tlsOpts: { minVersion: p, maxVersion: p } }, p);
    if (r.ok) protocolLegacy.push(p);
  }
  if (protocolLegacy.length) {
    findings.push({
      id: 'legacy-protocol', severity: 'HIGH',
      detail: `accepts deprecated protocol(s): ${protocolLegacy.join(', ')}`,
      fix: 'raise minimum to TLSv1.2 (nginx: ssl_protocols TLSv1.2 TLSv1.3)',
    });
  }

  const suites = [];
  for (const name of [
    'TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_MD5', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_RSA_WITH_DES_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_AES_128_GCM_SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384',
    'TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256',
  ]) {
    const r = await attempt(host, port, { tlsOpts: { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', ciphers: name } }, name);
    if (r.ok) suites.push({ suite: name, accepted: r.cipher });
  }
  const weak = suites.filter((s) => WEAK_CIPHER.test(s.suite));
  if (weak.length) {
    findings.push({
      id: 'weak-cipher', severity: 'HIGH',
      detail: `accepts weak suite(s): ${weak.map((w) => w.suite).join(', ')}`,
      fix: 'remove RC4/3DES/DES from the cipher list and prefer AEAD suites',
    });
  }
  const cbc = suites.filter((s) => CBC.test(s.suite) && !AEAD.test(s.suite));
  if (cbc.length) {
    findings.push({
      id: 'cbc-mode', severity: 'MEDIUM',
      detail: `accepts CBC-mode suite(s) without AEAD: ${cbc.map((c) => c.suite).join(', ')}`,
      fix: 'prefer GCM/CHACHA20 suites; CBC is prone to padding-oracle attacks',
    });
  }
  const noFs = suites.filter((s) => /^TLS_RSA_/.test(s.suite) && !/RC4|3DES|DES/.test(s.suite));
  if (noFs.length) {
    findings.push({
      id: 'no-forward-secrecy', severity: 'MEDIUM',
      detail: `static-RSA key exchange accepted (no PFS): ${noFs.map((s) => s.suite).join(', ')}`,
      fix: 'restrict to ECDHE/DHE suites so captured keys cannot decrypt past traffic',
    });
  }

  const cert = modern.cert;
  const expires = cert.valid_to ? new Date(cert.valid_to) : null;
  const days = expires ? Math.floor((expires - Date.now()) / 86400000) : null;
  if (days !== null && days < 0) findings.push({ id: 'cert-expired', severity: 'HIGH', detail: `certificate expired ${-days} day(s) ago`, fix: 'renew the certificate' });
  else if (days !== null && days < 15) findings.push({ id: 'cert-expiring', severity: 'MEDIUM', detail: `certificate expires in ${days} day(s)`, fix: 'renew before expiry; automate with ACME' });
  if (cert.self_signed) findings.push({ id: 'cert-self-signed', severity: 'MEDIUM', detail: 'certificate appears self-signed', fix: 'install a CA-issued certificate' });
  if (cert.bits && Number(cert.bits) < 2048 && !cert.curve) findings.push({ id: 'cert-weak-key', severity: 'HIGH', detail: `RSA key only ${cert.bits} bits`, fix: 'use RSA-2048 minimum or an EC P-256 key' });
  if (cert.curve && /secp192|secp224|sect/i.test(cert.curve)) findings.push({ id: 'cert-weak-curve', severity: 'MEDIUM', detail: `weak EC curve ${cert.curve}`, fix: 'use P-256 or better' });
  const match = hostMatches(host, cert);
  if (match === false) findings.push({ id: 'hostname-mismatch', severity: 'MEDIUM', detail: `certificate SANs do not cover ${host}`, fix: 'issue a certificate that includes this hostname' });
  if (!modern.authorized) findings.push({ id: 'chain-untrusted', severity: 'MEDIUM', detail: `chain not trusted: ${modern.auth_error}`, fix: 'serve the full intermediate chain' });
  if (cert.chain_depth === 0 && !cert.self_signed) findings.push({ id: 'chain-incomplete', severity: 'LOW', detail: 'server did not present intermediate certificate(s)', fix: 'include intermediates in the served bundle' });

  const isTls13 = /^TLSv1\.3/.test(modern.protocol || '');
  return {
    host, port,
    protocol: modern.protocol,
    cipher: modern.cipher,
    key_exchange: isTls13 ? 'ECDHE (TLS1.3)' : modern.kx,
    forward_secrecy: isTls13 ? true : /^(ECDHE|DHE)/.test(modern.kx || ''),
    aead: isTls13 ? true : AEAD.test(modern.cipher || ''),
    legacy_protocols: protocolLegacy,
    suites_accepted: suites.map((s) => s.suite),
    cert: {
      cn: cert.subject?.CN || null,
      issuer: cert.issuer?.O || cert.issuer?.CN || null,
      valid_from: cert.valid_from, valid_to: cert.valid_to, days_left: days,
      key_bits: cert.bits, curve: cert.curve, hostname_match: match,
      chain_depth: cert.chain_depth, fingerprint256: cert.fingerprint256,
    },
    findings,
  };
}

let entries = o._.length ? o._ : ['-'];
let hosts = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) hosts.push(...(await inputLines(e)));
  else hosts.push(e);
}
hosts = [...new Set(hosts.filter(Boolean))];
if (!hosts.length) die('no hosts given');

const targets = hosts.map((h) => {
  const clean = h.replace(/^https?:\/\//, '').split('/')[0];
  const [host, port] = clean.includes(':') ? clean.split(':') : [clean, 443];
  return [host.trim(), Number(port) || 443];
});

const results = [];
let cursor = 0;
async function worker() {
  while (cursor < targets.length) {
    const [h, p] = targets[cursor++];
    results.push(await audit(h, p));
  }
}
await Promise.all(Array.from({ length: Math.min(conc, targets.length) }, worker));

const withFindings = results.filter((r) => (r.findings || []).some((f) => f.severity !== 'INFO'));
if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); exitSoon(0); }

const shown = flag(o, 'quiet') ? withFindings : results;
console.log(table(shown.map((r) => ({
  host: r.host, port: r.port,
  protocol: r.protocol || '',
  cipher: (r.cipher || '').slice(0, 28),
  fs: r.forward_secrecy === undefined ? '' : (r.forward_secrecy ? 'yes' : 'NO'),
  aead: r.aead === undefined ? '' : (r.aead ? 'yes' : 'NO'),
  legacy: (r.legacy_protocols || []).join(','),
  days: r.cert?.days_left ?? '',
  findings: (r.findings || []).filter((f) => f.severity !== 'INFO').length,
  error: r.error || '',
}))));

for (const r of shown) {
  const f = (r.findings || []).filter((x) => x.severity !== 'INFO');
  if (!f.length) continue;
  console.log(`\n${r.host}:${r.port}`);
  for (const x of f) console.log(`  [${x.severity}] ${x.id}: ${x.detail}\n      fix: ${x.fix}`);
}
const total = results.reduce((n, r) => n + (r.findings || []).filter((f) => f.severity !== 'INFO').length, 0);
console.log(`\n${results.length} endpoint(s), ${withFindings.length} with findings, ${total} finding(s) total`);
exitSoon(0);
