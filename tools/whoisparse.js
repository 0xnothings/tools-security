#!/usr/bin/env node
// whoisparse.js — structured WHOIS/RDAP parser.
// Copyright (c) 2026 0xnothings
// @tool whoisparse
// @desc Parse WHOIS (port 43) and RDAP into structured JSON: registrar, dates, status, nameservers, contacts
// @usage node tools/whoisparse.js example.com --json
// @tags security,recon,osint,domains
import net from 'node:net';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`whoisparse — structured WHOIS / RDAP parser

  node tools/whoisparse.js <domain|ip|list.txt|-> [options]

  --server <host>  force a WHOIS server (default: auto-discovered)
  --rdap           use RDAP instead of port-43 WHOIS
  --timeout <ms>   whois server timeout (default: 10000)
  --raw            include the raw WHOIS/RDAP payload
  --json           machine-readable output (default for this tool is table)
  -h, --help       this text

  Example: node tools/whoisparse.js example.com`);
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

function whoisQuery(server, query, ms) {
  return new Promise((resolve) => {
    const chunks = [];
    let done = false;
    const sock = net.connect({ host: server, port: 43 });
    const fin = (err) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      try { sock.destroy(); } catch { /* ignore */ }
      resolve({ server, text: Buffer.concat(chunks).toString('utf8'), error: err || null });
    };
    const t = setTimeout(() => fin('timeout'), ms);
    sock.on('connect', () => sock.write(query + '\r\n'));
    sock.on('data', (c) => chunks.push(c));
    sock.on('error', (e) => fin(e.code || e.message));
    sock.on('close', () => fin(null));
  });
}

const TLD_SERVERS = {
  com: 'whois.verisign-grs.com', net: 'whois.verisign-grs.com', org: 'whois.pir.org',
  io: 'whois.nic.io', co: 'whois.nic.co', dev: 'whois.nic.google', app: 'whois.nic.google',
  xyz: 'whois.nic.xyz', info: 'whois.afilias.net', me: 'whois.nic.me', ai: 'whois.nic.ai',
  id: 'whois.id', my: 'whois.mynic.my', us: 'whois.nic.us', uk: 'whois.nic.uk', de: 'whois.denic.de',
  nl: 'whois.domain-registry.nl', fr: 'whois.nic.fr', ru: 'whois.tcinet.ru', br: 'whois.registro.br',
  to: 'whois.tonic.to', sh: 'whois.nic.sh', cc: 'ccwhois.verisign-grs.com',
};

const DATE_KEYS = [
  'creation date', 'created', 'registered on', 'registration time', 'domain registration date',
  'created date', 'registered', 'activation date', 'registry expiry date', 'expiry date',
  'expiration date', 'registrar registration expiration date', 'expires', 'paid-till',
  'updated date', 'last updated', 'last modified', 'changed', 'modified',
];
const REG_KEYS = ['registrar', 'sponsoring registrar', 'registrar name', 'registrar organization'];
const STATUS_KEYS = ['domain status', 'status', 'registration status'];
const NS_KEYS = ['name server', 'nserver', 'nameserver', 'nameservers'];
const CONTACT_KEYS = ['registrant name', 'registrant organization', 'registrant email', 'registrant country',
  'admin name', 'admin email', 'admin organization', 'tech name', 'tech email', 'org', 'e-mail'];

function parseWhoisText(text, server) {
  const out = {
    server,
    registrar: null, status: [], nameservers: [],
    created: null, updated: null, expires: null,
    registrant: {}, admin: {}, tech: {}, dnssec: null, contacts: [],
    raw_keys: {},
  };
  const kv = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+$/, '');
    if (!line || line.startsWith('%') || line.startsWith('#') || line.startsWith('>>>')) continue;
    const m = line.match(/^([^:]{2,60}):\s*(.+)$/);
    if (m) kv.push([m[1].trim().toLowerCase(), m[2].trim()]);
    if (/dnssec/i.test(line) && out.dnssec === null) out.dnssec = /signed|yes/i.test(line);
  }
  for (const [k, v] of kv) {
    if (REG_KEYS.includes(k) && !out.registrar) out.registrar = v;
    else if (STATUS_KEYS.includes(k)) { const s = v.split(/\s+/)[0]; if (!out.status.includes(s)) out.status.push(s); }
    else if (NS_KEYS.includes(k)) { const n = v.split(/\s+/)[0].toLowerCase().replace(/\.$/, ''); if (n && !out.nameservers.includes(n)) out.nameservers.push(n); }
    else if (DATE_KEYS.includes(k)) {
      const d = normalizeDate(v);
      if (k.includes('expir') || k.includes('paid-till')) { if (!out.expires) out.expires = d; }
      else if (k.includes('updat') || k.includes('modif') || k.includes('chang')) { if (!out.updated) out.updated = d; }
      else if (!out.created) out.created = d;
    } else if (CONTACT_KEYS.includes(k)) {
      const bucket = k.startsWith('admin') ? out.admin : k.startsWith('tech') ? out.tech : out.registrant;
      const prop = k.replace(/^(admin|tech|registrant)\s*/, '').replace(/\s+/g, '_');
      if (!bucket[prop]) bucket[prop] = v;
    }
  }
  return out;
}

function normalizeDate(v) {
  const s = String(v).trim();
  const t = Date.parse(s);
  if (!isNaN(t)) return new Date(t).toISOString();
  const m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}T${m[4] || '00'}:${m[5] || '00'}:${m[6] || '00'}Z`;
  return s || null;
}

async function rdapLookup(target) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(target);
    const url = `https://rdap.org/${isIp ? 'ip' : 'domain'}/${encodeURIComponent(target)}`;
    const r = await fetch(url, { headers: { accept: 'application/rdap+json, application/json', 'user-agent': 'whoisparse/1.0' }, signal: ctl.signal });
    if (!r.ok) return { error: `HTTP ${r.status}` };
    const d = await r.json();
    const out = {
      source: 'rdap',
      handle: d.handle, ldhName: d.ldhName,
      status: d.status || [],
      nameservers: (d.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
      events: (d.events || []).map((e) => ({ action: e.eventAction, date: e.eventDate })),
      registrar: null, entities: [],
      startAddress: d.startAddress, endAddress: d.endAddress, ipVersion: d.ipVersion,
      country: d.country, asn: d.asn,
      dnssec: d.secureDNS ? !!(d.secureDNS.delegationSigned) : null,
      notices: (d.notices || []).map((n) => ({ title: n.title, description: (n.description || []).join(' ') })),
    };
    for (const e of d.entities || []) {
      const v = {};
      for (const item of e.vcardArray?.[1] || []) { if (item[0] === 'fn') v.fn = item[3]; if (item[0] === 'email') v.email = item[3]; if (item[0] === 'org') v.org = item[3]; }
      out.entities.push({ roles: e.roles || [], handle: e.handle, ...v });
      if (!out.registrar && (e.roles || []).includes('registrar')) out.registrar = v.fn || e.handle;
    }
    for (const ev of out.events) {
      if (ev.action === 'registration') out.created = ev.date;
      if (ev.action === 'last changed') out.updated = ev.date;
      if (ev.action === 'expiration') out.expires = ev.date;
    }
    return out;
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'timeout' : (e.message || 'rdap failed') };
  } finally { clearTimeout(t); }
}

let targets = o._.length ? o._ : ['-'];
let items = [];
for (const t of targets) {
  if (t === '-' || /\.txt$/.test(t)) items.push(...(await inputLines(t)));
  else items.push(t.trim());
}
items = [...new Set(items.filter(Boolean))];
if (!items.length) die('no domain or IP given');

const results = [];
for (const target of items) {
  let rec;
  if (flag(o, 'rdap')) {
    rec = { query: target, ...(await rdapLookup(target)) };
  } else {
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(target);
    let server = get(o, 'server', null);
    if (!server) {
      if (isIp) {
        server = 'whois.arin.net';
      } else {
        const tld = target.split('.').pop().toLowerCase();
        server = TLD_SERVERS[tld] || 'whois.iana.org';
      }
    }
    let r = await whoisQuery(server, isIp ? `n + ${target}` : target, timeout);
    let parsed = parseWhoisText(r.text, server);
    // Referral chase: registry servers point at the registrar's whois for full registrant detail.
    const ref = (r.text.match(/^\s*(?:Whois Server|ReferralServer|whois):\s*(\S+)/im) || [])[1];
    if (ref && ref !== server && /\./.test(ref) && parsed.registrant && Object.keys(parsed.registrant).length === 0) {
      const refClean = ref.replace(/^whois:\/\//, '').split('/')[0];
      const r2 = await whoisQuery(refClean, target, timeout);
      const p2 = parseWhoisText(r2.text, refClean);
      if (p2.registrar && !parsed.registrar) parsed.registrar = p2.registrar;
      for (const n of p2.nameservers) if (!parsed.nameservers.includes(n)) parsed.nameservers.push(n);
      if (p2.created && !parsed.created) parsed.created = p2.created;
      if (p2.expires && !parsed.expires) parsed.expires = p2.expires;
      if (Object.keys(p2.registrant).length) parsed.registrant = p2.registrant;
      if (p2.status.length > parsed.status.length) parsed.status = p2.status;
      parsed.referral = refClean;
    }
    rec = { query: target, source: 'whois', error: r.error, ...parsed };
  }
  if (rec.created && rec.expires) {
    rec.age_days = Math.floor((Date.now() - Date.parse(rec.created)) / 86400000);
    rec.days_to_expiry = Math.floor((Date.parse(rec.expires) - Date.now()) / 86400000);
  }
  results.push(rec);
}

if (flag(o, 'json')) {
  const clean = results.map((r) => (flag(o, 'raw') ? r : Object.fromEntries(Object.entries(r).filter(([, v]) => v !== null && !(Array.isArray(v) && !v.length) && !(typeof v === 'object' && v && !Array.isArray(v) && !Object.keys(v).length)))));
  console.log(JSON.stringify(clean, null, 2));
  exitSoon(0);
} else {
  console.log(table(results.map((r) => ({
    query: r.query,
    source: r.source || 'whois',
    registrar: (r.registrar || r.error || '').slice(0, 34),
    created: (r.created || '').slice(0, 10),
    expires: (r.expires || '').slice(0, 10),
    age_d: r.age_days ?? '',
    exp_d: r.days_to_expiry ?? '',
    status: (r.status || []).slice(0, 2).join(','),
    ns: (r.nameservers || []).slice(0, 2).join(',').slice(0, 40),
  }))));
  for (const r of results) {
    const reg = r.registrant || {};
    console.log(`\n${r.query} -> ${r.source || 'whois'}${r.error ? ' (' + r.error + ')' : ''}`);
    if (r.registrar) console.log(`  registrar : ${r.registrar}`);
    if (Object.keys(reg).length) console.log(`  registrant: ${JSON.stringify(reg)}`);
    if ((r.status || []).length) console.log(`  status    : ${r.status.join(', ')}`);
    if ((r.nameservers || []).length) console.log(`  ns        : ${r.nameservers.join(', ')}`);
    if (r.days_to_expiry !== undefined) console.log(`  expiry    : ${r.days_to_expiry} day(s) (age ${r.age_days} d)`);
    if (r.dnssec !== null && r.dnssec !== undefined) console.log(`  dnssec    : ${r.dnssec ? 'signed' : 'unsigned'}`);
  }
  exitSoon(0);
}
