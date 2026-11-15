// robtex.js — passive DNS and WHOIS correlation without API keys.
// Copyright (c) 2026 0xnothings
// @tool robtex
// @desc Pull RDAP registration data plus reverse-IP co-hosted domains for infrastructure mapping
// @usage node tools/robtex.js example.com --json
// @tags security,osint,passivedns
import dns from 'node:dns';
import { args, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`robtex — RDAP + reverse-IP infrastructure mapping

  node tools/robtex.js <domain|domain.txt|-> [options]

  --no-reverse    skip reverse-IP co-host lookup
  --max-hosts <n> limit reverse lookups (default: 6)
  --json          machine-readable output
  -h, --help      this text`);
  process.exit(0);
}

async function get(url, timeout = 20000) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { accept: 'application/rdap+json, application/json', 'user-agent': '0xnothings-robtex/1.0' } });
    if (!res.ok) return { error: `HTTP ${res.status}` };
    return await res.json();
  } catch (e) { return { error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

function rdapSummary(j) {
  if (j.error) return { error: j.error };
  const events = Object.fromEntries((j.events || []).map((e) => [e.eventAction, e.eventDate]));
  const entities = (j.entities || []).map((e) => ({
    role: (e.roles || []).join('/'), handle: e.handle,
    name: e.vcardArray?.[1]?.find((x) => x[0] === 'fn')?.[3] || null,
    email: e.vcardArray?.[1]?.find((x) => x[0] === 'email')?.[3] || null,
  })).filter((e) => e.role);
  return {
    handle: j.handle, ldhName: j.ldhName, status: (j.status || []).join(', '),
    registered: (events.registration || '').slice(0, 10), expires: (events.expiration || '').slice(0, 10),
    updated: (events['last changed'] || '').slice(0, 10), registrar: entities.find((e) => /registrar/i.test(e.role))?.name || '-',
    registrant: entities.find((e) => /registrant/i.test(e.role))?.name || '(redacted)',
    nameservers: (j.nameservers || []).map((n) => n.ldhName?.toLowerCase()).filter(Boolean),
    entities: entities.slice(0, 8),
    dnssec: j.secureDNS?.delegationSigned ?? false,
  };
}

async function reverseIp(ip) {
  const j = await get(`https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`, 20000);
  if (typeof j === 'string') return j.split('\n').map((s) => s.trim()).filter((s) => s && !/error|API count/i.test(s)).slice(0, 60);
  return [];
}

let entries = o._.length ? o._ : ['-'];
let domains = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) domains.push(...(await inputLines(e))); else domains.push(e);
domains = [...new Set(domains.map((d) => d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase()).filter(Boolean))];
if (!domains.length) die('no domain given');

const out = [];
for (const d of domains) {
  const rdap = rdapSummary(await get(`https://rdap.org/domain/${encodeURIComponent(d)}`));
  let ips = [];
  try { ips = await dns.promises.resolve4(d); } catch {}
  const entry = { domain: d, rdap, ips, reverse: [] };
  if (!flag(o, 'no-reverse')) {
    for (const ip of ips.slice(0, Number(get(o, 'max-hosts', 6)))) {
      const hosts = await reverseIp(ip);
      if (hosts.length) entry.reverse.push({ ip, hosts });
    }
  }
  out.push(entry);
}

if (flag(o, 'json')) { console.log(JSON.stringify(out, null, 2)); process.exit(0); }
for (const e of out) {
  console.log(`\n######## ${e.domain}`);
  const r = e.rdap;
  if (r.error) console.log('  RDAP ' + r.error);
  else {
    console.log(`  registrar  ${r.registrar}`);
    console.log(`  registrant ${r.registrant}`);
    console.log(`  created ${r.registered || '?'}   expires ${r.expires || '?'}   updated ${r.updated || '?'}`);
    console.log(`  status     ${r.status || '-'}`);
    console.log(`  NS         ${r.nameservers.join(', ') || '-'}`);
    console.log(`  dnssec     ${r.dnssec}`);
  }
  if (e.ips.length) console.log(`  A          ${e.ips.join(', ')}`);
  for (const rev of e.reverse) console.log(`  reverse ${rev.ip} (${rev.hosts.length}): ${rev.hosts.slice(0, 12).join(', ')}${rev.hosts.length > 12 ? ' ...' : ''}`);
}
