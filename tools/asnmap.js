#!/usr/bin/env node
// asnmap.js — ASN to announced CIDR ranges and IP to ASN resolution.
// Copyright (c) 2026 0xnothings
// @tool asnmap
// @desc Map ASNs to their announced CIDR ranges (RIPEstat/BGPView) and resolve which ASN owns an IP
// @usage node tools/asnmap.js AS15169 --json
// @tags security,recon,network,osint
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`asnmap — ASN <-> CIDR range mapper

  node tools/asnmap.js <AS1234 | AS15169,... | 8.8.8.8 | file.txt | -> [options]

  --limit <n>      max prefixes to print per ASN (default: 500)
  --timeout <ms>   per-request timeout (default: 15000)
  --count-only     print only prefix counts
  --json           machine-readable output
  -h, --help       this text

  Examples:
    node tools/asnmap.js AS15169
    node tools/asnmap.js 8.8.8.8
    node tools/asnmap.js AS15169,AS13335 --count-only`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };

const timeout = num(get(o, 'timeout'), 15000);
const limit = num(get(o, 'limit'), 500);

async function getJson(u) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(u, { headers: { accept: 'application/json', 'user-agent': 'asnmap/1.0' }, signal: ctl.signal });
    if (!r.ok) return { error: `HTTP ${r.status}` };
    return { data: await r.json() };
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'timeout' : (e.message || 'fetch failed') };
  } finally { clearTimeout(t); }
}

const isIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

async function prefixesFor(asn) {
  const n = String(asn).replace(/^AS/i, '');
  const out = [];
  const a = await getJson(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${n}`);
  if (!a.error && a.data?.data?.prefixes) {
    for (const p of a.data.data.prefixes) out.push({ prefix: p.prefix, source: 'ripestat' });
  }
  if (!out.length) {
    const b = await getJson(`https://api.bgpview.io/asn/${n}/prefixes`);
    if (!b.error && b.data?.data?.ipv4_prefixes) {
      for (const p of b.data.data.ipv4_prefixes) out.push({ prefix: p.prefix, source: 'bgpview' });
    }
    for (const p of (b.data?.data?.ipv6_prefixes || [])) out.push({ prefix: p.prefix, source: 'bgpview', v6: true });
  }
  if (!out.length) return { asn: `AS${n}`, error: a.error || 'no prefixes returned', prefixes: [] };

  let info = { asn: `AS${n}` };
  const meta = await getJson(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${n}`);
  if (!meta.error && meta.data?.data) {
    info.holder = meta.data.data.holder;
    info.announced = meta.data.data.announced;
  }
  const v4 = out.filter((p) => !p.v6).map((p) => p.prefix).sort((x, y) => ipToInt(x.split('/')[0]) - ipToInt(y.split('/')[0]));
  const v6 = out.filter((p) => p.v6).map((p) => p.prefix);
  return { ...info, prefixes: v4, ipv6_prefixes: v6, total: v4.length + v6.length };
}

async function asnForIp(ip) {
  const a = await getJson(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`);
  if (!a.error && a.data?.data?.asns?.length) {
    const first = a.data.data.asns[0];
    return {
      ip,
      asn: `AS${first.asn}`,
      holder: first.holder || null,
      prefix: a.data.data.resource || null,
      announced: a.data.data.announced,
      source: 'ripestat',
    };
  }
  const b = await getJson(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,as,asname,isp,org`);
  if (!b.error && b.data?.status === 'success') {
    return { ip, asn: b.data.as || null, holder: b.data.asname || b.data.org || null, isp: b.data.isp, source: 'ip-api' };
  }
  return { ip, error: a.error || 'lookup failed' };
}

let targets = o._.length ? o._ : ['-'];
let items = [];
for (const t of targets) {
  if (t === '-' || /\.txt$/.test(t)) items.push(...(await inputLines(t)));
  else items = items.concat(String(t).split(','));
}
items = [...new Set(items.map((s) => s.trim()).filter(Boolean))];
if (!items.length) die('no ASN or IP given');

const report = { asns: [], ips: [] };
for (const it of items) {
  if (/^AS\d+$/i.test(it)) {
    report.asns.push(await prefixesFor(it));
  } else if (isIp(it)) {
    const r = await asnForIp(it);
    report.ips.push(r);
    if (r.asn && /^AS\d+$/.test(r.asn)) {
      report.asns.push(await prefixesFor(r.asn));
    }
  } else {
    die(`"${it}" is neither an ASN (AS1234) nor an IPv4 address`);
  }
}

if (flag(o, 'json')) {
  console.log(JSON.stringify(report, null, 2));
  exitSoon(0);
}

if (report.ips.length) {
  console.log('--- IP -> ASN ---');
  console.log(table(report.ips.map((r) => ({ ip: r.ip, asn: r.asn || '', holder: (r.holder || '').slice(0, 40), prefix: r.prefix || '', src: r.source || r.error || '' }))));
}

console.log('\n--- ASN -> prefixes ---');
console.log(table(report.asns.map((a) => ({
  asn: a.asn,
  holder: (a.holder || '').slice(0, 36),
  ipv4: a.prefixes ? a.prefixes.length : 0,
  ipv6: a.ipv6_prefixes ? a.ipv6_prefixes.length : 0,
  error: a.error || '',
}))));

if (!flag(o, 'count-only')) {
  for (const a of report.asns) {
    console.log(`\n### ${a.asn} ${a.holder || ''}`);
    const list = (a.prefixes || []).slice(0, limit);
    for (const p of list) console.log(`  ${p}`);
    if ((a.prefixes || []).length > limit) console.log(`  ... ${a.prefixes.length - limit} more (raise --limit)`);
  }
}
