// hackertarget.js — keyless HackerTarget API queries.
// Copyright (c) 2026 0xnothings
// @tool hackertarget
// @desc Query the keyless HackerTarget API: hostsearch, reverseiplookup, dnslookup, geoip, pagelinks and more
// @usage node tools/hackertarget.js hostsearch example.com --json
// @tags security,recon,osint,dns
import { args, get, num, flag, die, readStdin, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`hackertarget — keyless HackerTarget API client

  node tools/hackertarget.js <query> [target] [options]

  Queries: hostsearch, reverseiplookup, dnslookup, nslookup, geoip, pagelinks,
           httpheaders, shareddns, mtr, aslookup, reverse-dns, whois

  node tools/hackertarget.js hostsearch example.com
  node tools/hackertarget.js reverseiplookup 8.8.8.8
  node tools/hackertarget.js dnslookup example.com --type MX
  node tools/hackertarget.js hostsearch example.com --json

  --type <t>       DNS record type for dnslookup/nslookup (default: A)
  --list           list available queries
  --timeout <ms>   per-request timeout (default: 20000)
  --raw            print the raw text response
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };

const QUERIES = {
  hostsearch: { path: 'hostsearch', arg: 'q', needs: 'domain', desc: 'subdomains and A records' },
  reverseiplookup: { path: 'reverseiplookup', arg: 'q', needs: 'ip', desc: 'domains hosted on an IP' },
  dnslookup: { path: 'dnslookup', arg: 'q', needs: 'domain', extra: 'type', desc: 'DNS records by type' },
  nslookup: { path: 'nslookup', arg: 'q', needs: 'domain', desc: 'A records' },
  geoip: { path: 'geoip', arg: 'q', needs: 'ip', desc: 'IP geolocation' },
  pagelinks: { path: 'pagelinks', arg: 'q', needs: 'domain', desc: 'links found on the page' },
  httpheaders: { path: 'httpheaders', arg: 'q', needs: 'domain', desc: 'HTTP response headers' },
  shareddns: { path: 'shareddns', arg: 'q', needs: 'domain', desc: 'shared DNS servers' },
  mtr: { path: 'mtr', arg: 'q', needs: 'host', desc: 'traceroute' },
  aslookup: { path: 'aslookup', arg: 'q', needs: 'ip', desc: 'ASN lookup' },
  'reverse-dns': { path: 'reverseiplookup', arg: 'q', needs: 'ip', desc: 'alias of reverseiplookup' },
  whois: { path: 'whois', arg: 'q', needs: 'domain', desc: 'whois summary' },
};

const timeout = num(get(o, 'timeout'), 20000);

if (flag(o, 'list') || !o._.length) {
  console.log(table(Object.entries(QUERIES).map(([k, v]) => ({ query: k, needs: v.needs, description: v.desc }))));
  console.log('\nusage: node tools/hackertarget.js <query> <target>');
  exitSoon(0);
}

const q = String(o._[0]).toLowerCase();
const tgt = o._[1];
const spec = QUERIES[q];
if (!spec) die(`unknown query "${q}" — run with --list`);
if (!tgt) die(`query "${q}" needs a ${spec.needs} argument`);

async function hit(u) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(u, { headers: { 'user-agent': 'hackertarget-cli/1.0' }, signal: ctl.signal });
    const text = await r.text();
    return { status: r.status, text };
  } catch (e) {
    return { status: 0, text: e.name === 'AbortError' ? 'request timeout' : (e.message || 'request failed') };
  } finally { clearTimeout(t); }
}

let url = `https://api.hackertarget.com/${spec.path}/?${spec.arg}=${encodeURIComponent(tgt)}`;
if (spec.extra) url += `&type=${encodeURIComponent(String(get(o, 'type', 'A')))}`;

let res = await hit(url);
if (res.status === 0 || res.status >= 500) res = await hit(url.replace('https://', 'http://'));

const text = res.text;
const isError = /^\s*(error|API count exceeded|no records found|blocked)/i.test(text) || res.status !== 200;
const rows = text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).map((line) => ({ line }));

if (flag(o, 'json')) {
  console.log(JSON.stringify({
    query: q, target: tgt, url, status: res.status, ok: !isError,
    count: isError ? 0 : rows.length,
    records: isError ? [] : text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean),
    raw: isError ? text.slice(0, 500) : undefined,
  }, null, 2));
  exitSoon(isError ? 2 : 0);
}

if (flag(o, 'raw') || isError) {
  console.log(text.trim());
  if (isError) console.log(`\n(# HackerTarget returned an error or empty result for ${q} ${tgt})`);
  exitSoon(isError ? 2 : 0);
} else {
  console.log(table(rows));
  console.log(`\n${rows.length} record(s) for ${q} ${tgt} (${url})`);
}
