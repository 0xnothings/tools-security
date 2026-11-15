// internetdb.js — Shodan InternetDB keyless host lookup.
// Copyright (c) 2026 0xnothings
// @tool internetdb
// @desc Keyless Shodan InternetDB lookup by IP: open ports, hostnames, CPEs, tags and known CVEs
// @usage node tools/internetdb.js 8.8.8.8 --json
// @tags security,recon,osint
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`internetdb — Shodan InternetDB lookup (no API key)

  node tools/internetdb.js <ip|cidr|ips.txt|-> [options]

  --timeout <ms>   per-request timeout (default: 10000)
  --conc <n>       parallel lookups for CIDR input (default: 4)
  --vulns-only     print only hosts with known CVEs
  --json           machine-readable output
  -h, --help       this text

  Example: node tools/internetdb.js 8.8.8.8`);
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
const conc = num(get(o, 'conc'), 4);

async function lookup(ip) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
      headers: { accept: 'application/json', 'user-agent': 'internetdb/1.0' },
      signal: ctl.signal,
    });
    if (r.status === 404) return { ip, found: false, ports: [], hostnames: [], tags: [], cpes: [], vulns: [] };
    const text = await r.text();
    if (!r.ok) return { ip, found: false, error: `HTTP ${r.status}: ${text.slice(0, 120)}` };
    const d = JSON.parse(text);
    return {
      ip, found: true,
      ports: (d.ports || []).slice().sort((a, b) => a - b),
      hostnames: d.hostnames || [],
      tags: d.tags || [],
      cpes: d.cpes || [],
      vulns: d.vulns || [],
    };
  } catch (e) {
    return { ip, found: false, error: e.name === 'AbortError' ? 'timeout' : (e.message || 'fetch failed') };
  } finally { clearTimeout(t); }
}

function expandCidr(spec) {
  const m = String(spec).match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/);
  if (!m) return null;
  const base = (Number(m[1]) << 24 >>> 0) + (Number(m[2]) << 16) + (Number(m[3]) << 8) + Number(m[4]);
  const bits = Number(m[5]);
  if (bits < 16) return { error: 'refusing CIDR wider than /16' };
  const size = 2 ** (32 - bits);
  const out = [];
  for (let i = 0; i < size; i++) {
    const n = (base + i) >>> 0;
    out.push([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'));
  }
  return { ips: out };
}

let targets = o._.length ? o._ : ['-'];
let ips = [];
for (const t of targets) {
  if (t === '-' || /\.txt$/.test(t)) { ips.push(...(await inputLines(t))); continue; }
  const c = expandCidr(t);
  if (c && c.ips) ips = ips.concat(c.ips);
  else if (c && c.error) die(c.error);
  else ips.push(t.trim());
}
ips = [...new Set(ips.filter(Boolean))];
if (!ips.length) die('no IPs given');

const results = [];
let cursor = 0;
async function worker() {
  while (cursor < ips.length) {
    const ip = ips[cursor++];
    results.push(await lookup(ip));
  }
}
await Promise.all(Array.from({ length: Math.min(conc, ips.length) }, worker));

if (flag(o, 'vulns-only')) {
  const v = results.filter((r) => r.vulns.length);
  if (flag(o, 'json')) { console.log(JSON.stringify(v, null, 2)); exitSoon(0); }
  console.log(table(v.map((r) => ({ ip: r.ip, vulns: r.vulns.length, ports: r.ports.join(','), hostnames: r.hostnames.slice(0, 3).join(',') }))));
  exitSoon(0);
}

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); exitSoon(0); }

console.log(table(results.map((r) => ({
  ip: r.ip,
  found: r.found ? 'yes' : 'no',
  ports: r.ports.join(',').slice(0, 40),
  vulns: r.vulns.length,
  tags: r.tags.join(','),
  hostnames: r.hostnames.slice(0, 3).join(',').slice(0, 40),
  error: r.error || '',
}))));

const withVulns = results.filter((r) => r.vulns.length);
if (withVulns.length) {
  console.log('\nKnown CVEs:');
  for (const r of withVulns) console.log(`  ${r.ip}  ${r.vulns.join(' ')}`);
}
console.log(`\n${results.length} host(s) queried, ${results.filter((r) => r.found).length} with data, ${withVulns.length} with CVEs`);
