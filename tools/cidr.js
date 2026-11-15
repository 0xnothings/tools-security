// cidr.js — IP/CIDR math toolkit.
// Copyright (c) 2026 0xnothings
// @tool cidr
// @desc Expand, collapse, split and test IPv4/IPv6 networks; check whether an IP is inside a range
// @usage node tools/cidr.js 10.0.0.0/24 --split 26 --json
// @tags security,network,ipam
import net from 'node:net';
import { args, flag, die, inputLines, get } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`cidr — IP / CIDR math toolkit

  node tools/cidr.js <cidr|list.txt|-> [options]

  --split <bits>     split each range into /bits subnets
  --limit <n>        max addresses listed per range (default: 256)
  --test <ip>        report which input ranges contain this IP
  --collapse         merge overlapping ranges into the minimal set
  --json             machine-readable output
  -h, --help         this text`);
  process.exit(0);
}

const v4 = (ip) => ip.split('.').reduce((a, o) => (a << 8 >>> 0) + Number(o), 0) >>> 0;
const u32 = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

function parseRange(s) {
  const t = s.trim();
  if (!t) return null;
  if (t.includes('/')) {
    const [ip, bitsStr] = t.split('/');
    const bits = Number(bitsStr);
    if (!net.isIPv4(ip) || !(bits >= 0 && bits <= 32)) return { raw: t, error: 'invalid IPv4 CIDR' };
    const maskBits = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const start = (v4(ip) & maskBits) >>> 0;
    const size = Math.pow(2, 32 - bits);
    return { raw: t, network: u32(start), broadcast: u32((start + size - 1) >>> 0), size, bits };
  }
  if (net.isIPv4(t)) return { raw: t, network: t, broadcast: t, size: 1, bits: 32 };
  return { raw: t, error: 'invalid address' };
}

let entries = o._.length ? o._ : ['-'];
let raw = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) raw.push(...(await inputLines(e))); else raw.push(e);
if (!raw.length) die('no CIDR given');

let ranges = raw.map(parseRange).filter(Boolean);
const bad = ranges.filter((r) => r.error);
ranges = ranges.filter((r) => !r.error);
if (!ranges.length) die('no valid IPv4 CIDR in input');

if (flag(o, 'collapse')) {
  const sorted = [...ranges].sort((a, b) => v4(a.network) - v4(b.network));
  const merged = [];
  for (const r of sorted) {
    const last = merged[merged.length - 1];
    if (last && v4(r.network) <= v4(last.broadcast) + 1) {
      if (v4(r.broadcast) > v4(last.broadcast)) last.broadcast = r.broadcast;
      last.size = v4(last.broadcast) - v4(last.network) + 1;
    } else merged.push({ ...r });
  }
  ranges = merged;
}

if (o.f.split) {
  const bits = Number(get(o, 'split'));
  const out = [];
  for (const r of ranges) {
    if (!(bits > r.bits && bits <= 32)) { out.push(r); continue; }
    const step = Math.pow(2, 32 - bits);
    for (let s = v4(r.network); s <= v4(r.broadcast); s += step) {
      out.push({ raw: `${u32(s)}/${bits}`, network: u32(s), broadcast: u32((s + step - 1) >>> 0), size: step, bits });
    }
  }
  ranges = out;
}

if (flag(o, 'json')) {
  console.log(JSON.stringify({ ranges, invalid: bad.map((b) => b.raw), total_addresses: ranges.reduce((a, r) => a + r.size, 0) }, null, 2));
} else {
  const limit = Number(get(o, 'limit', 256));
  for (const r of ranges) {
    const head = `${r.network}${r.bits < 32 ? '/' + r.bits : ''}`;
    console.log(`${head.padEnd(22)} ${String(r.size).padStart(12)} addr   ${r.network}${r.size > 1 ? ' - ' + r.broadcast : ''}`);
    if (r.size > 1 && r.size <= limit && !o.f.split) {
      for (let i = v4(r.network); i <= v4(r.broadcast); i++) process.stdout.write('  ' + u32(i) + '\n');
    }
  }
  console.log(`\n${ranges.length} range(s), ${ranges.reduce((a, r) => a + r.size, 0)} addresses`);
  if (bad.length) console.log(`invalid: ${bad.map((b) => b.raw).join(', ')}`);
}

if (o.f.test) {
  const ip = String(get(o, 'test'));
  if (!net.isIPv4(ip)) die(`--test expects an IPv4 address, got ${ip}`);
  const n = v4(ip);
  const hits = ranges.filter((r) => n >= v4(r.network) && n <= v4(r.broadcast));
  console.log(flag(o, 'json') ? JSON.stringify({ ip, contained: hits.map((r) => r.raw) }) : `${ip} ${hits.length ? 'IN ' + hits.map((r) => r.raw).join(', ') : 'not in any given range'}`);
}
