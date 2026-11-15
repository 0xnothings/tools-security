#!/usr/bin/env node
// subdomain.js — DNS subdomain brute-forcer with wildcard detection.
// Copyright (c) 2026 0xnothings
// @tool subdomain
// @desc Concurrent DNS subdomain brute-forcer with wildcard detection and JSON output
// @usage node tools/subdomain.js example.com --wordlist words.txt --concurrency 100
// @tags security,recon,dns
import dns from 'node:dns';
import { args, get, num, flag, die, inputLines, nowISO } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`subdomain — DNS subdomain brute-forcer

  node tools/subdomain.js <domain> [options]

  --wordlist <file>   prefixes, one per line (default: built-in 60)
  --resolvers <file>  custom resolvers, one per line
  --concurrency <n>   parallel queries        (default: 100)
  --timeout <ms>      per-query timeout       (default: 4000)
  --wildcard-skip     abort entries caught by the wildcard IP
  --json              machine-readable output
  -h, --help          this text`);
  process.exit(0);
}

const BUILTIN = ['www','mail','api','dev','test','staging','stage','admin','portal','app','apps','blog','shop','store','cdn','static','assets','media','img','images','files','download','downloads','ftp','sftp','ns1','ns2','ns3','mx','mx1','mx2','smtp','pop','pop3','imap','webmail','vpn','remote','gw','gateway','proxy','internal','intranet','extranet','db','mysql','postgres','redis','mongo','elastic','kibana','grafana','prometheus','jenkins','ci','cd','git','gitlab','github','bitbucket','jira','confluence','wiki','docs','support','help','status','monitor','nagios','zabbix','backup','old','new','beta','demo','sandbox','qa','uat','preprod','prod','edge','origin','lb','vpn2','auth','sso','id','login','pay','payment','checkout','ws','socket','grpc','mq','kafka','rabbit'];

const domain = o._[0];
if (!domain) die('usage: node tools/subdomain.js <domain> [--wordlist file] [--json]');

if (o.f.resolvers) {
  const rs = await inputLines(get(o, 'resolvers'));
  if (rs.length) dns.setServers(rs);
}

const words = o.f.wordlist ? await inputLines(get(o, 'wordlist')) : BUILTIN;
const conc = num(get(o, 'concurrency'), 100);
const timeout = num(get(o, 'timeout'), 4000);
const resolver = new dns.promises.Resolver({ timeout, tries: 2 });

async function lookup(name) {
  const out = { name };
  try {
    const a = await resolver.resolve4(name);
    if (a?.length) out.a = a;
  } catch {}
  if (!out.a) {
    try {
      const c = await resolver.resolveCname(name);
      if (c?.length) out.cname = c;
    } catch {}
  }
  return out.a || out.cname ? out : null;
}

// wildcard detection
let wildcard = [];
for (const probe of [`0xnothings-wildcard-${Math.random().toString(36).slice(2, 10)}.${domain}`]) {
  const r = await lookup(probe);
  if (r) wildcard = r.a || r.cname || [];
}
if (wildcard.length) console.error(`[!] wildcard DNS detected: ${wildcard.join(', ')}`);

const found = [];
let idx = 0;
await Promise.all(Array.from({ length: Math.min(conc, words.length) }, async () => {
  while (idx < words.length) {
    const w = words[idx++];
    const name = `${w}.${domain}`;
    const r = await lookup(name);
    if (!r) continue;
    const ips = r.a || r.cname || [];
    if (wildcard.length && ips.every((ip) => wildcard.includes(ip)) && flag(o, 'wildcard-skip')) continue;
    r.wildcard = wildcard.length ? ips.every((ip) => wildcard.includes(ip)) : false;
    found.push(r);
    if (!flag(o, 'json')) console.log(`${(r.a || r.cname).join(', ').padEnd(30)} ${r.name}${r.wildcard ? '  [wildcard]' : ''}`);
  }
}));

if (flag(o, 'json')) console.log(JSON.stringify({ domain, scouted_at: nowISO(), wildcard, count: found.length, results: found }, null, 2));
else console.log(`\n${found.length} subdomains of ${domain} (${words.length} probed)`);
