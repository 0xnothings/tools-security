#!/usr/bin/env node
// ipintel.js — IP geolocation, ASN and reverse DNS with provider fallback.
// Copyright (c) 2026 0xnothings
// @tool ipintel
// @desc IP geolocation, ASN, org and reverse DNS across multiple keyless providers with automatic fallback
// @usage node tools/ipintel.js 8.8.8.8 --json
// @tags security,recon,osint,network
import dns from 'node:dns';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`ipintel — IP geolocation + ASN + rDNS (multi-provider fallback)

  node tools/ipintel.js <ip|cidr|ips.txt|-> [options]

  --provider <p>   ipwho | ipapi | ipinfo | freeipapi | auto (default: auto)
  --no-rdns        skip reverse DNS lookup
  --timeout <ms>   per-request timeout (default: 8000)
  --conc <n>       parallel lookups (default: 4)
  --json           machine-readable output
  -h, --help       this text

  Example: node tools/ipintel.js 8.8.8.8`);
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
const conc = num(get(o, 'conc'), 4);
const provider = String(get(o, 'provider', 'auto')).toLowerCase();

const PROVIDERS = [
  {
    key: 'ipwho',
    url: (ip) => `https://ipwho.is/${encodeURIComponent(ip)}`,
    parse: (d) => (d.success === false ? null : {
      country: d.country, country_code: d.country_code, region: d.region, city: d.city,
      lat: d.latitude, lon: d.longitude, tz: d.timezone?.id,
      isp: d.connection?.isp, org: d.connection?.org, asn: d.connection?.asn ? `AS${d.connection.asn}` : null,
      as_name: d.connection?.domain || null,
    }),
  },
  {
    key: 'ipapi',
    url: (ip) => `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,proxy,hosting`,
    parse: (d) => (d.status === 'fail' ? null : {
      country: d.country, country_code: d.countryCode, region: d.regionName, city: d.city,
      lat: d.lat, lon: d.lon, tz: d.timezone,
      isp: d.isp, org: d.org, asn: (d.as || '').split(' ')[0] || null, as_name: d.asname || null,
      is_proxy: d.proxy, is_hosting: d.hosting,
    }),
  },
  {
    key: 'ipinfo',
    url: (ip) => `https://ipinfo.io/${encodeURIComponent(ip)}/json`,
    parse: (d) => (d.bogon || d.error ? null : {
      country: d.country, country_code: d.country, region: d.region, city: d.city,
      lat: (d.loc || ',').split(',')[0], lon: (d.loc || ',').split(',')[1], tz: d.timezone,
      isp: null, org: d.org, asn: (d.org || '').split(' ')[0] || null, as_name: (d.org || '').split(' ').slice(1).join(' ') || null,
      hostname: d.hostname,
    }),
  },
  {
    key: 'freeipapi',
    url: (ip) => `https://freeipapi.com/api/json/${encodeURIComponent(ip)}`,
    parse: (d) => (d.ipVersion === undefined ? null : {
      country: d.countryName, country_code: d.countryCode, region: d.regionName, city: d.cityName,
      lat: d.latitude, lon: d.longitude, tz: d.timeZone,
      isp: null, org: null, asn: null, as_name: null,
    }),
  },
];

const chain = provider === 'auto' ? PROVIDERS : PROVIDERS.filter((p) => p.key === provider);
if (!chain.length) die(`unknown provider "${provider}" (auto|ipwho|ipapi|ipinfo|freeipapi)`);

async function fetchProvider(p, ip) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(p.url(ip), { headers: { accept: 'application/json', 'user-agent': 'ipintel/1.0' }, signal: ctl.signal });
    if (!r.ok) return null;
    const d = await r.json();
    const parsed = p.parse(d);
    if (!parsed) return null;
    return { ...parsed, provider: p.key };
  } catch { return null; } finally { clearTimeout(t); }
}

async function lookup(ip) {
  const rec = { ip };
  const errs = [];
  for (const p of chain) {
    const out = await fetchProvider(p, ip);
    if (out) return { ...rec, ...out, errors: errs };
    errs.push(p.key);
  }
  return { ...rec, error: `all providers failed (${errs.join(', ')})` };
}

function rdns(ip) {
  return new Promise((resolve) => {
    dns.reverse(ip, (err, names) => resolve(err ? [] : (names || [])));
  });
}

function expandCidr(spec) {
  const m = String(spec).match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/);
  if (!m) return null;
  const bits = Number(m[5]);
  const base = (Number(m[1]) << 24 >>> 0) + (Number(m[2]) << 16) + (Number(m[3]) << 8) + Number(m[4]);
  if (bits < 24) return { error: 'refusing CIDR wider than /24' };
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
    const r = await lookup(ip);
    if (!flag(o, 'no-rdns')) {
      const names = await rdns(ip);
      r.rdns = names;
    } else r.rdns = [];
    results.push(r);
  }
}
await Promise.all(Array.from({ length: Math.min(conc, ips.length) }, worker));

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); exitSoon(0); }

console.log(table(results.map((r) => ({
  ip: r.ip,
  error: r.error || '',
  country: r.country_code || '',
  city: (r.city || '').slice(0, 16),
  asn: r.asn || '',
  org: (r.as_name || r.org || r.isp || '').slice(0, 28),
  provider: r.provider || '',
  rdns: (r.rdns || []).join(',').slice(0, 30),
}))));

for (const r of results.filter((x) => x.is_proxy || x.is_hosting)) {
  console.log(`\n${r.ip} flagged: ${[r.is_proxy && 'proxy/VPN', r.is_hosting && 'hosting/datacenter'].filter(Boolean).join(', ')}`);
}
console.log(`\n${results.length} IP(s) resolved, ${results.filter((r) => !r.error).length} with geo data`);
