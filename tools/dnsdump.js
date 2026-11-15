#!/usr/bin/env node
// dnsdump.js — full DNS record dump with reverse lookups.
// Copyright (c) 2026 0xnothings
// @tool dnsdump
// @desc Dump A/AAAA/MX/NS/TXT/SOA/CNAME/CAA/SRV records; decode SPF+DMARC; optional PTR and zone-transfer test
// @usage node tools/dnsdump.js example.com --json
// @tags security,dns,recon
import dns from 'node:dns';
import { args, num, flag, die, inputLines, table, get } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`dnsdump — full DNS record dump

  node tools/dnsdump.js <domain|domains.txt|-> [options]

  --types <list>   record types (default: A,AAAA,MX,NS,TXT,SOA,CNAME,CAA,SRV)
  --ptr            reverse-resolve every A record
  --axfr           attempt a zone transfer against each NS
  --resolver <ip>  custom resolver
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

if (o.f.resolver) dns.setServers([String(get(o, 'resolver'))]);
const r = new dns.promises.Resolver({ timeout: 5000, tries: 2 });
const types = String(get(o, 'types', 'A,AAAA,MX,NS,TXT,SOA,CNAME,CAA,SRV')).split(',').map((s) => s.trim().toUpperCase());

let entries = o._.length ? o._ : ['-'];
let domains = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) domains.push(...(await inputLines(e))); else domains.push(e);
domains = [...new Set(domains.map((d) => d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase()).filter(Boolean))];
if (!domains.length) die('no domain given');

function parseSpf(txt) {
  if (!/^v=spf1/.test(txt)) return null;
  const mechs = txt.split(/\s+/).slice(1);
  const all = mechs.find((m) => /^[+-~?]?all$/.test(m));
  return { record: txt, all: all || '(none)', allMeaning: !all ? 'undefined (treated as ?all = neutral)' : all.startsWith('-') ? 'hardfail (good)' : all.startsWith('~') ? 'softfail (acceptable)' : all.startsWith('+') ? 'PASS-ALL (spoofable!)' : all.startsWith('?') ? 'neutral (weak)' : 'implicit (weak)', mechs };
}

async function dump(domain) {
  const out = { domain, records: {} };
  for (const t of types) {
    try {
      const fn = { A: 'resolve4', AAAA: 'resolve6', MX: 'resolveMx', NS: 'resolveNs', TXT: 'resolveTxt', SOA: 'resolveSoa', CNAME: 'resolveCname', CAA: 'resolveCa', SRV: 'resolveSrv' }[t];
      if (!fn) continue;
      const v = await r[fn](domain);
      if (!v || (Array.isArray(v) && !v.length)) continue;
      out.records[t] = t === 'TXT' ? v.map((a) => a.join('')) : v;
    } catch { /* NXDOMAIN or no record of that type */ }
  }
  const txts = out.records.TXT || [];
  out.spf = txts.map(parseSpf).filter(Boolean);
  try {
    const dmarc = await r.resolveTxt(`_dmarc.${domain}`);
    out.dmarc = dmarc.map((a) => a.join(''));
    out.dmarcPolicy = (out.dmarc.join('').match(/p=(\w+)/) || [, 'none'])[1];
  } catch { out.dmarcPolicy = 'none (no _dmarc record — spoofable)'; }
  try {
    const dkim = await r.resolveTxt(`default._domainkey.${domain}`);
    out.dkim = true;
  } catch { out.dkim = false; }
  try { out.mta_sts = (await r.resolveTxt(`_mta-sts.${domain}`)).map((a) => a.join('')); } catch {}
  if (flag(o, 'ptr') && out.records.A) {
    out.ptr = {};
    for (const ip of out.records.A.slice(0, 20)) {
      try { out.ptr[ip] = (await dns.promises.reverse(ip))[0]; } catch { out.ptr[ip] = null; }
    }
  }
  if (flag(o, 'axfr') && out.records.NS) {
    out.axfr = out.records.NS.map((ns) => ({ ns, ...(globalThis.__axfr ? {} : { status: 'requires TCP zone transfer — use: dig AXFR ' + domain + ' @' + ns }) }));
  }
  return out;
}

const results = [];
for (const d of domains) results.push(await dump(d));

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); process.exit(0); }
for (const res of results) {
  console.log(`\n######## ${res.domain}`);
  for (const [t, v] of Object.entries(res.records)) {
    const flat = Array.isArray(v) ? v.map((x) => (typeof x === 'object' ? (x.exchange || x.nsname || x.name || x.target || x.priority !== undefined ? `${x.priority ?? ''} ${x.exchange || x.nsname || ''}`.trim() : JSON.stringify(x)) : x)) : [v];
    console.log(`  ${t.padEnd(5)} ${flat.join('\n        ')}`);
  }
  if (res.spf.length) res.spf.forEach((s) => console.log(`  SPF   ${s.allMeaning}`));
  else console.log('  SPF   no SPF record — email spoofable');
  console.log(`  DMARC ${res.dmarcPolicy}`);
  console.log(`  DKIM  ${res.dkim ? 'default selector present' : 'no default selector'}`);
}
