#!/usr/bin/env node
// massparse.js — normalize masscan/nmap/naabu output into one schema.
// Copyright (c) 2026 0xnothings
// @tool massparse
// @desc Parse masscan/nmap/naabu output (XML, JSON, greppable, plain) into one normalized scan schema
// @usage node tools/massparse.js scan.xml --json
// @tags security,recon,network,parsing
import { readFileSync, existsSync } from 'node:fs';
import { args, get, num, flag, die, readInput, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`massparse — scanner output normalizer

  node tools/massparse.js <scan file|-> [options]

  node tools/massparse.js scan.xml
  node tools/massparse.js naabu.jsonl
  node tools/massparse.js masscan.grep
  node tools/massparse.js nmap.txt --format nmap-text

  --format <f>     auto | nmap-xml | nmap-grep | nmap-text | masscan-list | masscan-grep | naabu-json | naabu-text | json (default: auto)
  --state <s>      only keep this port state (open|closed|filtered, default: all)
  --port <list>    only keep these ports (comma list or a-b range)
  --limit <n>      max records printed (default: 500)
  --json           machine-readable output
  -h, --help       this text

  Output schema: {host, ip, port, proto, state, service, product, version, banner, cpe, hostnames, script}  `);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };
const limit = num(get(o, 'limit'), 500);

function norm(rec) {
  const out = {
    host: rec.host || rec.ip || '',
    ip: rec.ip || rec.host || '',
    port: Number(rec.port) || 0,
    proto: (rec.proto || 'tcp').toLowerCase(),
    state: (rec.state || 'open').toLowerCase(),
    service: rec.service || '',
    product: rec.product || '',
    version: rec.version || '',
    banner: rec.banner || '',
    cpe: rec.cpe || '',
    hostnames: rec.hostnames || [],
    script: rec.script || '',
  };
  if (!out.ip) out.ip = out.host;
  if (!out.host) out.host = out.ip;
  return out;
}

// ---------- nmap XML ----------
function parseNmapXml(text) {
  const hosts = [];
  const hostBlocks = text.split(/<host\b/).slice(1);
  for (const block of hostBlocks) {
    const end = block.indexOf('</host>');
    const h = end >= 0 ? block.slice(0, end) : block;
    const status = (h.match(/<status\s+state="([^"]+)"/) || [])[1] || 'unknown';
    const addr = (h.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv[46]"/) || [])[1] || '';
    const hostnames = [...h.matchAll(/<hostname\s+name="([^"]+)"/g)].map((m) => m[1]);
    const ports = [...h.matchAll(/<port\s+([^>]*)>([\s\S]*?)<\/port>/g)];
    if (!ports.length) {
      hosts.push(norm({ ip: addr, host: hostnames[0] || addr, port: 0, state: status, service: '', hostnames, script: 'host-status-only' }));
      continue;
    }
    for (const [, attrs, inner] of ports) {
      const port = (attrs.match(/portid="(\d+)"/) || [])[1];
      const proto = (attrs.match(/protocol="([^"]+)"/) || [])[1] || 'tcp';
      const state = (inner.match(/<state\s+state="([^"]+)"/) || [])[1] || 'filtered';
      const svcTag = (inner.match(/<service\s+([^>]*)\/?>/) || [])[1] || '';
      const svc = (svcTag.match(/name="([^"]+)"/) || [])[1] || '';
      const product = (svcTag.match(/product="([^"]+)"/) || [])[1] || '';
      const version = (svcTag.match(/version="([^"]+)"/) || [])[1] || '';
      const extra = (svcTag.match(/extrainfo="([^"]+)"/) || [])[1] || '';
      const cpe = (inner.match(/<cpe>([^<]+)<\/cpe>/) || [])[1] || '';
      const scripts = [...inner.matchAll(/<script\s+id="([^"]+)"\s+output="([^"]*)"/g)].map((m) => `${m[1]}=${m[2].slice(0, 60)}`).join('; ');
      hosts.push(norm({
        ip: addr, host: hostnames[0] || addr, port, proto, state, service: svc,
        product, version: [version, extra].filter(Boolean).join(' '), cpe, hostnames, script: scripts,
      }));
    }
  }
  return { format: 'nmap-xml', records: hosts };
}

// ---------- nmap greppable ----------
function parseNmapGrep(text) {
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^Host:\s*(\S+)\s*\(([^)]*)\)\s*(.*)$/);
    if (!m) continue;
    const [, ip, hostname, rest] = m;
    const ports = [...rest.matchAll(/(\d+)\/(\w+)\s+(\w+)\s+([^\s/]*)\s*([^\t\/]*)/g)];
    for (const p of ports) {
      records.push(norm({ ip, host: hostname || ip, port: p[1], proto: p[2], state: p[3], service: p[4], version: (p[5] || '').trim(), hostnames: hostname ? [hostname] : [] }));
    }
    if (!ports.length && /Status:/.test(rest)) records.push(norm({ ip, host: hostname || ip, state: 'up', hostnames: hostname ? [hostname] : [] }));
  }
  return { format: 'nmap-grep', records };
}

// ---------- nmap normal text ----------
function parseNmapText(text) {
  const records = [];
  let curIp = '';
  let curHost = '';
  for (const line of text.split(/\r?\n/)) {
    const hm = line.match(/^Nmap scan report for\s+(?:(\S+)\s*\()?([\d.a-fA-F:]+)\)?/);
    if (hm) { curHost = hm[1] || hm[2]; curIp = hm[2]; continue; }
    const pm = line.match(/^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)$/);
    if (pm) records.push(norm({ ip: curIp, host: curHost, port: pm[1], proto: pm[2], state: pm[3], service: pm[4], version: (pm[5] || '').trim() }));
  }
  return { format: 'nmap-text', records };
}

// ---------- masscan -oL ----------
function parseMasscanList(text) {
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^(open|closed|filtered)\s+(tcp|udp)\s+(\d+)\s+(\S+)/);
    if (m) records.push(norm({ state: m[1], proto: m[2], port: m[3], ip: m[4] }));
  }
  return { format: 'masscan-list', records };
}

// ---------- masscan -oG ----------
function parseMasscanGrep(text) {
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    if (!/^Host:/.test(line)) continue;
    const ip = (line.match(/Host:\s*(\S+)/) || [])[1];
    for (const m of line.matchAll(/Ports:\s*([^]*?)(?:Ignored|Seq|$)/g)) {
      for (const p of m[1].matchAll(/(\d+)\/(\w+)\/(\w+)\/([^/]*)\/([^/\s]*)\/?([^,\s]*)/g)) {
        records.push(norm({ ip, host: ip, port: p[1], proto: p[2], state: p[3], service: p[4], version: p[6] || '', banner: '' }));
      }
    }
  }
  return { format: 'masscan-grep', records };
}

// ---------- naabu ----------
function parseNaabuJson(text) {
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    let d;
    try { d = JSON.parse(t); } catch { continue; }
    if (Array.isArray(d)) {
      for (const item of d) records.push(norm({ ip: item.ip || item.host, host: item.host || item.ip, port: item.port, proto: item.protocol || 'tcp', service: item.tls ? 'tls' : '' }));
      continue;
    }
    if (d.ports && Array.isArray(d.ports)) {
      for (const p of d.ports) records.push(norm({ ip: d.ip || d.host, host: d.host || d.ip, port: p.port, proto: p.protocol || 'tcp' }));
    } else {
      records.push(norm({ ip: d.ip || d.host, host: d.host || d.ip, port: d.port, proto: d.protocol || 'tcp', service: d.tls ? 'tls' : '' }));
    }
  }
  return { format: 'naabu-json', records };
}

function parseNaabuText(text) {
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith('[')) continue;
    const m = t.match(/^(\[[^\]]+\]\s*)?(.+?):(\d+)$/);
    if (m) records.push(norm({ host: m[2], ip: m[2], port: m[3] }));
  }
  return { format: 'naabu-text', records };
}

function parseJsonGeneric(text) {
  let d;
  try { d = JSON.parse(text); } catch { return { format: 'json', records: [] }; }
  const arr = Array.isArray(d) ? d : (d.results || d.hosts || d.ports || []);
  const records = [];
  for (const item of arr) {
    if (!item || typeof item !== 'object') continue;
    if (Array.isArray(item.ports)) {
      for (const p of item.ports) records.push(norm({ ip: item.ip || item.host, host: item.host || item.ip, port: p.port || p, proto: p.protocol, state: p.state, service: p.service, product: p.product, version: p.version, banner: p.banner, hostnames: item.hostnames }));
    } else records.push(norm(item));
  }
  return { format: 'json', records };
}

function detect(text) {
  const t = text.trim();
  if (!t) return 'empty';
  if (t.startsWith('<?xml') || t.includes('<nmaprun')) return 'nmap-xml';
  if (t.startsWith('{') || t.startsWith('[')) {
    if (/"ip"\s*:\s*"[^"]+"\s*,\s*"port"/.test(t) || t.split('\n').filter((l) => /^\{.*"port"/.test(l.trim())).length > 1) return 'naabu-json';
    return 'json';
  }
  if (/^# Nmap .*scan initiated/m.test(t) || /^Host: .*\(\S*\)/m.test(t)) return /Ports:/.test(t) ? 'nmap-grep' : 'nmap-grep';
  if (/^(open|closed|filtered)\s+(tcp|udp)\s+\d+/m.test(t)) return 'masscan-list';
  if (/^Host: \S+\s*\(/m.test(t) && /Ports:/.test(t)) return 'nmap-grep';
  if (/^# masscan/m.test(t) && /Ports:/.test(t)) return 'masscan-grep';
  if (/^\d+\/(tcp|udp)\s+(open|closed|filtered)/m.test(t)) return 'nmap-text';
  if (/^[^\s:]+:\d+$/m.test(t) && !t.includes('/')) return 'naabu-text';
  return 'unknown';
}

const PARSERS = {
  'nmap-xml': parseNmapXml,
  'nmap-grep': parseNmapGrep,
  'nmap-text': parseNmapText,
  'masscan-list': parseMasscanList,
  'masscan-grep': parseMasscanGrep,
  'naabu-json': parseNaabuJson,
  'naabu-text': parseNaabuText,
  json: parseJsonGeneric,
};

const inputPath = o._[0];
if (!inputPath) die('no input file given (pass a path or - for stdin)');
const text = inputPath === '-' ? await readInput(null) : readFileSync(inputPath, 'utf8');

const wantFormat = String(get(o, 'format', 'auto')).toLowerCase();
const detected = detect(text);
const format = wantFormat === 'auto' ? detected : wantFormat;
const parser = PARSERS[format];
if (!parser) die(`cannot parse format "${format}" (detected "${detected}") — supported: ${Object.keys(PARSERS).join(', ')}`);

const parsed = parser(text);
let records = parsed.records.map(norm);
const beforeFilter = records.length;

// Filters
const stateFilter = get(o, 'state', null);
if (stateFilter) records = records.filter((r) => r.state === String(stateFilter).toLowerCase());
if (o.f.port) {
  const wanted = new Set();
  for (const part of String(o.f.port).split(',')) {
    const m = part.trim().match(/^(\d+)-(\d+)$/);
    if (m) { for (let i = Number(m[1]); i <= Number(m[2]); i++) wanted.add(i); }
    else if (/^\d+$/.test(part.trim())) wanted.add(Number(part.trim()));
  }
  records = records.filter((r) => wanted.has(r.port));
}

// De-duplicate on host/port/proto and sort
const keyed = new Map();
for (const r of records) {
  const k = `${r.ip}|${r.port}|${r.proto}`;
  const ex = keyed.get(k);
  if (!ex) keyed.set(k, r);
  else {
    for (const f of ['service', 'product', 'version', 'banner', 'cpe', 'script']) if (!ex[f] && r[f]) ex[f] = r[f];
    for (const h of r.hostnames) if (!ex.hostnames.includes(h)) ex.hostnames.push(h);
    if (ex.state !== 'open' && r.state === 'open') ex.state = r.state;
  }
}
const finalRecords = [...keyed.values()].sort((a, b) => (a.ip === b.ip ? a.port - b.port : a.ip.localeCompare(b.ip)));

const summary = {
  source: inputPath,
  format_detected: detected,
  format_used: format,
  records_before_filter: beforeFilter,
  records: finalRecords.length,
  unique_hosts: new Set(finalRecords.map((r) => r.ip)).size,
  unique_ports: new Set(finalRecords.map((r) => r.port)).size,
  states: finalRecords.reduce((acc, r) => { acc[r.state] = (acc[r.state] || 0) + 1; return acc; }, {}),
  services: finalRecords.reduce((acc, r) => { if (r.service) acc[r.service] = (acc[r.service] || 0) + 1; return acc; }, {}),
  top_ports: Object.entries(finalRecords.reduce((acc, r) => { acc[r.port] = (acc[r.port] || 0) + 1; return acc; }, {})).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([p, n]) => ({ port: Number(p), count: n })),
};

if (flag(o, 'json')) {
  console.log(JSON.stringify({ summary, results: finalRecords.slice(0, limit) }, null, 2));
  exitSoon(0);
}

console.log(`source : ${summary.source}`);
console.log(`format : ${summary.format_detected}${summary.format_used !== summary.format_detected ? ' (forced ' + summary.format_used + ')' : ''}`);
console.log(`records: ${summary.records_before_filter} parsed -> ${summary.records} after filters/dedup`);
console.log(`hosts  : ${summary.unique_hosts}, ports: ${summary.unique_ports}`);
console.log(`states : ${JSON.stringify(summary.states)}`);
console.log(`top ports: ${summary.top_ports.map((t) => `${t.port}(x${t.count})`).join(' ')}`);
console.log('\n' + table(finalRecords.slice(0, limit).map((r) => ({
  ip: r.ip, port: r.port, proto: r.proto, state: r.state,
  service: r.service, version: (r.product + ' ' + r.version).trim().slice(0, 30),
  hostnames: r.hostnames.join(',').slice(0, 24), cpe: r.cpe ? 'yes' : '',
}))));
if (finalRecords.length > limit) console.log(`... ${finalRecords.length - limit} more (raise --limit)`);
exitSoon(0);
