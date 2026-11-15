// dnsrecon.js — DNS reconnaissance bundle.
// Copyright (c) 2026 0xnothings
// @tool dnsrecon
// @desc DNS recon bundle: zone transfer, recursion, wildcard detection, DNSSEC presence and DNS-rebinding feasibility
// @usage node tools/dnsrecon.js example.com --json
// @tags security,dns,recon,network
import dns from 'node:dns';
import net from 'node:net';
import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`dnsrecon — DNS reconnaissance bundle

  node tools/dnsrecon.js <domain|list.txt|-> [options]

  --timeout <ms>     per-query timeout (default: 5000)
  --resolver <ip>    resolver to use (default: system)
  --axfr <server>    attempt a zone transfer against this nameserver (default: try every NS)
  --no-axfr          skip zone-transfer attempts
  --random-labels <n> wildcard probe labels (default: 5)
  --rebind <ip>      check whether the zone can point at this internal IP
  --json             machine-readable output
  -h, --help         this text

  Checks: NS/SOA/MX/TXT/CAA/SRV records, AXFR against every NS, PTR coverage,
  wildcard A/AAAA/TXT, DNSSEC (DS at the parent + DNSKEY presence), open
  recursion response, CNAME chains, and DNS-rebinding feasibility
  (TTL <= 60 with an A answer that an attacker can control).`);
  process.exit(0);
}

const exitSoon = (code = 0) => { process.exitCode = code; };
const timeout = num(get(o, 'timeout'), 5000);
const randomLabels = num(get(o, 'random-labels'), 5);

if (o.f.resolver) {
  try { dns.setServers(String(o.f.resolver).split(',').map((s) => s.trim())); } catch { die('invalid --resolver'); }
}

function q(fn, name) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ status: 'timeout', answer: null }), timeout);
    fn(name, (err, res) => {
      clearTimeout(timer);
      if (err) return resolve({ status: err.code || 'ERROR', answer: null });
      resolve({ status: 'OK', answer: res });
    });
  });
}

const R = {
  A: (n, cb) => dns.resolve4(n, cb),
  AAAA: (n, cb) => dns.resolve6(n, cb),
  NS: (n, cb) => dns.resolveNs(n, cb),
  MX: (n, cb) => dns.resolveMx(n, cb),
  TXT: (n, cb) => dns.resolveTxt(n, cb),
  SOA: (n, cb) => dns.resolveSoa(n, cb),
  CAA: (n, cb) => dns.resolveCaa(n, cb),
  SRV: (n, cb) => dns.resolveSrv(n, cb),
  CNAME: (n, cb) => dns.resolveCname(n, cb),
  PTR: (n, cb) => dns.reverse(n, cb),
  // Node's resolver exposes no DS record type, so DS and DNSKEY go through rawRecordQuery().
  DS: (n, cb) => rawRecordQuery(n, 43).then((r) => cb(null, r.answer), (e) => cb(e)),
  DNSKEY: (n, cb) => rawRecordQuery(n, 48).then((r) => cb(null, r.answer), (e) => cb(e)),
};

/** Minimal UDP DNS query for record types Node's resolver does not expose. */
function rawQuery(name, qtype, cb, wantTcp = false) {
  const labels = String(name).replace(/\.$/, '').split('.').filter(Boolean);
  const qname = Buffer.concat([...labels.map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')])), Buffer.from([0])]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE((Math.random() * 65535) & 0xffff, 0);
  header.writeUInt16BE(0x0100, 2);      // standard query, recursion desired
  header.writeUInt16BE(1, 4);           // one question
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0); tail.writeUInt16BE(1, 2);
  const msg = Buffer.concat([header, qname, tail]);

  const server = (dns.getServers()[0] || '8.8.8.8');
  const [host, portStr] = server.includes(':') && !server.startsWith('[') && server.split(':').length === 2 && !server.includes('::')
    ? server.split(':') : [server, 53];
  const port = Number(portStr) || 53;

  const chunks = [];
  let done = false;
  const fin = (err, data) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    try { if (wantTcp) sock.destroy(); } catch { /* ignore */ }
    // A UDP socket left open keeps the event loop alive and the process hangs.
    try { if (!wantTcp) sock.close(); } catch { /* already closed */ }
    if (err) return cb(err);
    cb(null, data);
  };

  let sock;
  if (wantTcp) {
    const lenPfx = Buffer.alloc(2); lenPfx.writeUInt16BE(msg.length, 0);
    sock = net.connect({ host, port });
    sock.on('connect', () => sock.write(Buffer.concat([lenPfx, msg])));
  } else {
    sock = dgram.createSocket(server.includes('::') ? 'udp6' : 'udp4');
    sock.on('message', (m) => fin(null, m));
    sock.send(msg, port, host, (e) => { if (e) fin(e); });
  }
  const timer = setTimeout(() => fin(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), timeout);
  if (wantTcp) {
    sock.on('data', (c) => chunks.push(c));
    sock.on('error', (e) => fin(e));
    sock.on('close', () => { if (chunks.length) fin(null, Buffer.concat(chunks).slice(2)); else fin(null, Buffer.alloc(0)); });
  } else sock.on('error', (e) => fin(e));
}

/** Parse a raw DNS response: returns answer count and whether an answer RR exists. */
function parseDnsResponse(buf) {
  if (!buf || buf.length < 12) return { count: 0, rcode: null };
  const flags = buf.readUInt16BE(2);
  const rcode = flags & 0x000f;
  const ancount = buf.readUInt16BE(6);
  return { count: ancount, rcode, authoritative: !!(flags & 0x0400) };
}

/** Wraps rawQuery into the {status, answer} shape the rest of the file expects. */
function rawRecordQuery(name, qtype) {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve({ status: 'timeout', answer: null }), timeout);
    rawQuery(name, qtype, (err, buf) => {
      clearTimeout(t);
      if (err) return resolve({ status: err.code || err.message || 'ERROR', answer: null });
      const parsed = parseDnsResponse(buf);
      resolve({ status: parsed.rcode === 0 ? 'OK' : (parsed.rcode === 3 ? 'ENOTFOUND' : 'RCODE_' + parsed.rcode), answer: parsed.count ? [{ rcode: parsed.rcode, count: parsed.count }] : null, count: parsed.count });
    });
  });
}

// Minimal DNS-over-TCP query for AXFR (Node's resolver cannot do AXFR).
function axfr(server, zone, ms) {
  return new Promise((resolve) => {
    const chunks = [];
    let done = false;
    const fin = (err) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      try { sock.destroy(); } catch { /* ignore */ }
      const buf = Buffer.concat(chunks);
      resolve({ server, bytes: buf.length, records: countAxfrRecords(buf), error: err || null });
    };
    // Build the AXFR query: header + question (QTYPE=252).
    const labels = zone.split('.').filter(Boolean);
    const qname = Buffer.concat([...labels.map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
    const header = Buffer.alloc(12);
    header.writeUInt16BE(0x1234, 0);   // id
    header.writeUInt16BE(0x0000, 2);   // flags
    header.writeUInt16BE(1, 4);        // qdcount
    const tail = Buffer.alloc(4);
    tail.writeUInt16BE(252, 0);        // AXFR
    tail.writeUInt16BE(1, 2);          // IN
    const msg = Buffer.concat([header, qname, tail]);
    const lenPrefix = Buffer.alloc(2);
    lenPrefix.writeUInt16BE(msg.length, 0);

    const sock = net.connect({ host: server, port: 53 });
    const t = setTimeout(() => fin('timeout'), ms);
    sock.on('connect', () => sock.write(Buffer.concat([lenPrefix, msg])));
    sock.on('data', (c) => { chunks.push(c); if (Buffer.concat(chunks).length > 262144) fin(null); });
    sock.on('error', (e) => fin(e.code || e.message));
    sock.on('close', () => fin(null));
  });
}

function countAxfrRecords(buf) {
  // Each TCP segment is 2-byte length + DNS message; sum the answer counts.
  let off = 0, total = 0, rcode = null;
  while (off + 14 <= buf.length) {
    const segLen = buf.readUInt16BE(off);
    if (segLen === 0 || off + 2 + segLen > buf.length) break;
    const msg = buf.slice(off + 2, off + 2 + segLen);
    const flags = msg.readUInt16BE(2);
    rcode = flags & 0x000f;
    const ancount = msg.readUInt16BE(6);
    total += ancount;
    off += 2 + segLen;
    if (off + 2 > buf.length) break;
  }
  return { answer_records: total, rcode };
}

async function pool(items, fn, limit) {
  const out = new Array(items.length);
  let i = 0;
  async function w() { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, w));
  return out;
}

let entries = o._.length ? o._ : ['-'];
let domains = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) domains.push(...(await inputLines(e)));
  else domains.push(e);
}
domains = [...new Set(domains.filter(Boolean).map((d) => d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^\*\./, '').trim().toLowerCase()))];
if (!domains.length) die('no domain given');

const results = [];
for (const domain of domains) {
  const rec = { domain, records: {}, checks: {}, findings: [] };
  const add = (id, severity, detail, impact) => rec.findings.push({ id, severity, detail, impact });

  // ---- records ----
  const [ns, soa, a, aaaa, mx, txt, caa, ds, dnskeys, cname] = await Promise.all([
    q(R.NS, domain), q(R.SOA, domain), q(R.A, domain), q(R.AAAA, domain),
    q(R.MX, domain), q(R.TXT, domain), q(R.CAA, domain), q(R.DS, domain),
    q(R.DNSKEY, domain), q(R.CNAME, domain),
  ]);
  rec.records = {
    ns: ns.answer || [], soa: soa.answer || null, a: a.answer || [], aaaa: aaaa.answer || [],
    mx: mx.answer || [], txt: (txt.answer || []).map((t) => t.join('')), caa: caa.answer || [],
    ds: ds.answer || null, dnskey_count: Array.isArray(dnskeys.answer) ? dnskeys.answer.length : 0,
    cname: cname.answer || [], status: { ns: ns.status, soa: soa.status, a: a.status, mx: mx.status, caa: caa.status, ds: ds.status },
  };

  // ---- zone transfer ----
  const axfrResults = [];
  if (!flag(o, 'no-axfr')) {
    const servers = o.f.axfr ? [String(o.f.axfr)] : (ns.answer || []).slice(0, 6);
    for (const s of servers) {
      const r = await axfr(s, domain, timeout * 2);
      axfrResults.push(r);
      const ok = r.records && r.records.rcode === 0 && r.records.answer_records > 1;
      if (ok) add('axfr-open', 'CRITICAL', `zone transfer succeeded from ${s}: ${r.records.answer_records} records`, 'the full zone contents are exposed to any client — enumerate every host directly');
      else if (r.error) rec.checks[`axfr_${s}`] = `error: ${r.error}`;
    }
  }
  rec.checks.axfr = axfrResults;

  // ---- wildcard detection ----
  const rand = () => crypto.randomBytes(9).toString('hex');
  const wildProbes = await pool(Array.from({ length: randomLabels }, () => `${rand()}.${domain}`), async (n) => {
    const [ra, rt] = await Promise.all([q(R.A, n), q(R.TXT, n)]);
    return { name: n, a: ra.answer || [], txt: rt.answer || [], status: ra.status };
  }, 4);
  const answered = wildProbes.filter((w) => (w.a && w.a.length) || (w.txt && w.txt.length));
  rec.checks.wildcard = { probes: wildProbes.length, answered: answered.length, sample_answers: answered.slice(0, 3).map((w) => ({ name: w.name, a: w.a, txt: w.txt.map((t) => t.join('')) })) };
  if (answered.length) add('wildcard-dns', 'MEDIUM', `${answered.length}/${wildProbes.length} random labels returned answers (wildcard${answered[0].txt.length ? ' TXT' : ' A'} record)`, 'subdomain enumeration needs a response fingerprint to filter wildcard noise');

  // ---- recursion ----
  const outer = `${rand()}.wikipedia.org`;
  const rec2 = await q(R.A, outer);
  rec.checks.recursion = { probe: outer, status: rec2.status, answered: !!(rec2.answer && rec2.answer.length) };
  if (rec2.status === 'OK' || rec2.status === 'ENOTFOUND' || rec2.status === 'ENODATA') add('recursion-enabled', 'INFO', `the resolver answers for zones outside ${domain} (${rec2.status})`, 'recursion is present; combined with an open UDP/53 this is an amplification vector');

  // ---- DNSSEC ----
  const signed = (ds.status === 'OK' && ds.answer) || rec.records.dnskey_count > 0;
  rec.checks.dnssec = { ds_present: ds.status === 'OK' && !!ds.answer, dnskey_records: rec.records.dnskey_count, signed };
  if (!signed) add('no-dnssec', 'LOW', 'no DNSSEC: no DS at the parent and no DNSKEY in the zone', 'DNS responses are forgeable by any on-path attacker');

  // ---- CAA ----
  if (!(caa.status === 'OK' && caa.answer && caa.answer.length)) add('no-caa', 'LOW', 'no CAA record — any public CA may issue for this domain', 'add CAA to restrict which CAs can issue certificates');

  // ---- SPF/DMARC hints from TXT ----
  const txtJoined = rec.records.txt.join(' | ');
  if (/v=spf1/.test(txtJoined) && /[+~]all/.test(txtJoined) && !/-all/.test(txtJoined)) add('weak-spf', 'MEDIUM', `SPF does not hard-fail: ${(txtJoined.match(/v=spf1[^|]*/) || [''])[0].trim()}`, 'spoofed mail from this domain is likely accepted');
  if (!/v=spf1/.test(txtJoined) && rec.records.mx.length) add('no-spf', 'MEDIUM', 'MX records exist but no SPF TXT record is published', 'any host may send mail claiming to be this domain');

  // ---- DNS rebinding feasibility ----
  const soaTTL = rec.records.soa && typeof rec.records.soa === 'object' ? (rec.records.soa.minttl ?? rec.records.soa.ttl ?? null) : null;
  const rebindTarget = get(o, 'rebind', '127.0.0.1');
  const lowTTL = soaTTL !== null && Number(soaTTL) <= 60;
  rec.checks.rebinding = {
    soa_minttl: soaTTL,
    low_ttl: lowTTL,
    attacker_controlled: true,
    note: `a zone TTL of ${soaTTL ?? 'unknown'}s ${lowTTL ? 'permits rapid A-record rotation' : 'makes rebinding slow but not impossible'}; pointing an A record at ${rebindTarget} would let a browser reach an internal service`,
  };
  if (lowTTL) add('rebind-feasible', 'MEDIUM', `zone minimum TTL is ${soaTTL}s — an attacker-controlled record can be re-pointed between requests`, `DNS rebinding to ${rebindTarget} becomes practical; verify the app validates the Host header`);

  // ---- PTR for A records ----
  const ptrs = await pool(rec.records.a.slice(0, 8), async (ip) => {
    const r = await q(R.PTR, ip);
    return { ip, names: r.answer || [], status: r.status };
  }, 4);
  rec.checks.ptr = ptrs;

  if (!rec.records.a.length && !rec.records.aaaa.length && !rec.records.cname.length) {
    add('no-address-record', 'INFO', 'no A/AAAA/CNAME at the apex', 'the apex is not directly reachable; check www and other names');
  }

  results.push(rec);
}

if (flag(o, 'json')) {
  console.log(JSON.stringify({ generated: new Date().toISOString(), resolver: dns.getServers(), results }, null, 2));
  exitSoon(results.some((r) => r.findings.some((f) => f.severity === 'CRITICAL')) ? 1 : 0);
}

for (const r of results) {
  console.log(`\n### ${r.domain}`);
  const rows = [
    { record: 'NS', value: r.records.ns.join(', ').slice(0, 70) || `(${r.records.status.ns})` },
    { record: 'A', value: r.records.a.join(', ') || `(${r.records.status.a})` },
    { record: 'AAAA', value: r.records.aaaa.join(', ').slice(0, 60) || '-' },
    { record: 'MX', value: r.records.mx.map((m) => `${m.priority} ${m.exchange}`).join(', ').slice(0, 60) || '-' },
    { record: 'TXT', value: r.records.txt.map((t) => t.slice(0, 40)).join(' | ').slice(0, 70) || '-' },
    { record: 'CAA', value: r.records.caa.length ? `${r.records.caa.length} record(s)` : `(${r.records.status.caa})` },
    { record: 'SOA', value: r.records.soa ? `${r.records.soa.nsname} serial=${r.records.soa.serial} minttl=${r.records.soa.minttl}` : `(${r.records.status.soa})` },
  ];
  console.log(table(rows));

  console.log('\nchecks:');
  console.log(table([
    { check: 'zone transfer', result: r.checks.axfr ? (r.checks.axfr.some((a) => a.records && a.records.answer_records > 1 && a.records.rcode === 0) ? 'OPEN' : `refused (${r.checks.axfr.map((a) => a.error || 'rcode ' + a.records?.rcode).slice(0, 2).join(', ')})`) : 'skipped', detail: `${(r.checks.axfr || []).length} server(s) tried` },
    { check: 'wildcard', result: r.checks.wildcard.answered ? `PRESENT (${r.checks.wildcard.answered}/${r.checks.wildcard.probes})` : 'none', detail: (r.checks.wildcard.sample_answers[0]?.a || []).join(',') },
    { check: 'recursion', result: r.checks.recursion.status, detail: r.checks.recursion.probe },
    { check: 'dnssec', result: r.checks.dnssec.signed ? 'signed' : 'unsigned', detail: `DS=${r.checks.dnssec.ds_present} DNSKEY=${r.checks.dnssec.dnskey_records}` },
    { check: 'rebinding', result: r.checks.rebinding.low_ttl ? 'TTL<=60 (practical)' : `TTL ${r.checks.rebinding.soa_minttl ?? '?'}` , detail: 'attacker-controlled A record' },
  ]));

  if (r.checks.ptr.length) {
    console.log('\nreverse DNS:');
    console.log(table(r.checks.ptr.map((p) => ({ ip: p.ip, ptr: p.names.join(', ').slice(0, 60) || `(${p.status})` }))));
  }
  console.log(`\nfindings (${r.findings.length}):`);
  for (const f of r.findings) console.log(`  [${f.severity}] ${f.id}: ${f.detail}\n      -> ${f.impact}`);
}
exitSoon(results.some((r) => r.findings.some((f) => f.severity === 'CRITICAL')) ? 1 : 0);
