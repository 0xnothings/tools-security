#!/usr/bin/env node
// dnshistory.js — passive DNS history from multiple keyless sources.
// Copyright (c) 2026 0xnothings
// @tool dnshistory
// @desc Passive DNS history: merge historical name->IP records from keyless sources, dedup by (name, ip, first_seen)
// @usage node tools/dnshistory.js example.com --json
// @tags security,recon,dns,osint
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`dnshistory — passive DNS history aggregator

  node tools/dnshistory.js <domain|list.txt|-> [options]

  --source <s>     hackertarget | crtsh | wayback | all (default: all)
  --timeout <ms>   per-request timeout (default: 20000)
  --limit <n>      max rows printed per domain (default: 200)
  --json           machine-readable output
  -h, --help       this text

  Sources are keyless: HackerTarget hostsearch, crt.sh CT names, Wayback CDX host list.
  Records are merged and deduplicated on (name, ip, first_seen).`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };
const timeout = num(get(o, 'timeout'), 20000);
const limit = num(get(o, 'limit'), 200);
const pick = String(get(o, 'source', 'all')).toLowerCase();

async function getText(u, accept) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(u, { headers: { accept: accept || 'text/plain', 'user-agent': 'dnshistory/1.0' }, signal: ctl.signal, redirect: 'follow' });
    return { status: r.status, text: await r.text() };
  } catch (e) {
    return { status: 0, text: e.name === 'AbortError' ? 'timeout' : (e.message || 'failed') };
  } finally { clearTimeout(t); }
}

const isIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

async function srcHackertarget(domain) {
  const out = [];
  const r = await getText(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`);
  if (r.status !== 200 || /error|API count exceeded|no records/i.test(r.text)) return { name: 'hackertarget', records: out, error: r.text.slice(0, 80) };
  for (const line of r.text.split(/\r?\n/)) {
    const m = line.match(/^([^,]+),(\S+)/);
    if (m) out.push({ name: m[1].toLowerCase(), ip: m[2], first_seen: null, last_seen: null, source: 'hackertarget' });
  }
  return { name: 'hackertarget', records: out };
}

async function srcCrtsh(domain) {
  const out = [];
  const r = await getText(`https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`, 'application/json');
  if (r.status !== 200) return { name: 'crtsh', records: out, error: `HTTP ${r.status}` };
  let data;
  try { data = JSON.parse(r.text); } catch { return { name: 'crtsh', records: out, error: 'non-json' }; }
  if (!Array.isArray(data)) return { name: 'crtsh', records: out, error: 'unexpected shape' };
  const seen = new Set();
  for (const row of data) {
    const entry = (row.entry_timestamp || row.not_before || '').slice(0, 19);
    for (const n of String(row.name_value || '').split('\n')) {
      const clean = n.replace(/^\*\./, '').trim().toLowerCase();
      if (!clean || !clean.endsWith(domain)) continue;
      if (seen.has(clean)) continue;
      seen.add(clean);
      out.push({ name: clean, ip: null, first_seen: entry || null, last_seen: null, source: 'crtsh', issuer: (row.issuer_name || '').slice(0, 60) });
    }
  }
  return { name: 'crtsh', records: out };
}

async function srcWayback(domain) {
  const out = [];
  const r = await getText(`http://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original,timestamp&collapse=urlkey&limit=800`, 'application/json');
  if (r.status !== 200) return { name: 'wayback', records: out, error: `HTTP ${r.status}` };
  let data;
  try { data = JSON.parse(r.text); } catch { return { name: 'wayback', records: out, error: 'non-json' }; }
  if (!Array.isArray(data) || data.length < 2) return { name: 'wayback', records: out };
  const seen = new Set();
  for (const row of data.slice(1)) {
    const url = row[0];
    const ts = row[1];
    const host = (url.match(/^https?:\/\/([^\/:]+)/) || [])[1];
    if (!host || !host.toLowerCase().endsWith(domain)) continue;
    const h = host.toLowerCase();
    if (seen.has(h)) continue;
    seen.add(h);
    const iso = ts && /^\d{14}$/.test(ts) ? `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}` : null;
    out.push({ name: h, ip: null, first_seen: iso, last_seen: null, source: 'wayback' });
  }
  return { name: 'wayback', records: out };
}

const SOURCES = { hackertarget: srcHackertarget, crtsh: srcCrtsh, wayback: srcWayback };

let targets = o._.length ? o._ : ['-'];
let domains = [];
for (const t of targets) {
  if (t === '-' || /\.txt$/.test(t)) domains.push(...(await inputLines(t)));
  else domains.push(t.trim());
}
domains = [...new Set(domains.map((d) => d.replace(/^\*\./, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase()).filter(Boolean))];
if (!domains.length) die('no domains given');

const report = [];
for (const domain of domains) {
  const used = pick === 'all' ? Object.keys(SOURCES) : [pick];
  const perSource = [];
  let merged = [];
  for (const s of used) {
    const fn = SOURCES[s];
    if (!fn) { perSource.push({ source: s, error: 'unknown source' }); continue; }
    const res = await fn(domain);
    perSource.push({ source: res.name, count: res.records.length, error: res.error || null });
    merged = merged.concat(res.records);
  }

  const keyed = new Map();
  for (const r of merged) {
    const k = `${r.name}|${r.ip || ''}|${(r.first_seen || '').slice(0, 10)}`;
    if (!keyed.has(k)) keyed.set(k, { ...r });
    else {
      const ex = keyed.get(k);
      if (!ex.source.split('+').includes(r.source)) ex.source = ex.source + '+' + r.source;
      if (r.issuer && !ex.issuer) ex.issuer = r.issuer;
    }
  }
  const rows = [...keyed.values()].sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const ips = [...new Set(rows.map((r) => r.ip).filter((x) => x && isIp(x)))];
  report.push({ domain, sources: perSource, unique_names: new Set(rows.map((r) => r.name)).size, unique_ips: ips.length, rows, ips });
}

if (flag(o, 'json')) {
  console.log(JSON.stringify({
    generated: new Date().toISOString(),
    domains: report.map((r) => ({
      domain: r.domain, unique_names: r.unique_names, unique_ips: r.unique_ips,
      sources: r.sources,
      records: r.rows.slice(0, limit).map((x) => ({ name: x.name, ip: x.ip, first_seen: x.first_seen, source: x.source })),
    })),
  }, null, 2));
  exitSoon(0);
} else {
  for (const r of report) {
    console.log(`\n### ${r.domain}  (${r.unique_names} names / ${r.unique_ips} ips)`);
    console.log(table(r.sources.map((s) => ({ source: s.source, records: s.count ?? '', error: s.error || '' }))));
    const rows = r.rows.slice(0, limit).map((x) => ({ name: x.name, ip: x.ip || '', first_seen: (x.first_seen || '').slice(0, 10), source: x.source }));
    if (rows.length) console.log(table(rows));
    if (r.rows.length > limit) console.log(`... ${r.rows.length - limit} more record(s)`);
  }
  console.log(`\n${report.length} domain(s), ${report.reduce((n, r) => n + r.unique_names, 0)} unique name(s)`);
  exitSoon(0);
}
