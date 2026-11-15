#!/usr/bin/env node
// paramfuzz.js — parameter discovery and reflection tester.
// Copyright (c) 2026 0xnothings
// @tool paramfuzz
// @desc Probe a URL with candidate parameters to find hidden/reflected/reachable ones
// @usage node tools/paramfuzz.js https://example.com/search --wordlist params.txt --reflect
// @tags security,web,fuzzing
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`paramfuzz — parameter discovery

  node tools/paramfuzz.js <url> [options]

  --wordlist <file>   parameter names (default: built-in 60)
  --reflect           check whether the value is reflected in the response
  --marker <str>      canary value (default: 0xnothings1337)
  --concurrency <n>   parallel requests (default: 15)
  --timeout <ms>      request timeout (default: 8000)
  --json              machine-readable output
  -h, --help          this text`);
  process.exit(0);
}

const BUILTIN = ['id','uid','user','userid','user_id','username','name','q','query','search','s','keyword','page','p','offset','limit','count','size','start','end','from','to','date','sort','order','dir','orderby','filter','type','format','mode','action','cmd','do','view','file','path','dir','url','uri','redirect','next','return','returnurl','callback','ref','reference','debug','test','admin','token','key','apikey','api_key','auth','session','sid','lang','locale','country','currency','category','cat','tag','item','product','price','amount','total','email','phone','title','body','message','msg','content','data','json','xml','html','output','type','include','require','load','template','theme','skin','style','css','js','src','host','domain','site','ip','port','proxy','target','dest','destination','file','filename','download','upload','list','all','show','hide','enable','disable','status','state','step','version','v','t','timestamp','nonce','csrf','signature','sig','hash','checksum'];

const base = o._[0];
if (!base) die('usage: node tools/paramfuzz.js <url> [--reflect] [--wordlist file]');
const wordlist = o.f.wordlist ? await inputLines(get(o, 'wordlist')) : BUILTIN;
const marker = String(get(o, 'marker', '0xnothings1337'));
const conc = num(get(o, 'concurrency'), 15);
const timeout = num(get(o, 'timeout'), 8000);
const reflect = flag(o, 'reflect');

const baseline = await (async () => {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), timeout);
  try { const r = await fetch(base, { signal: c.signal, redirect: 'manual' }); const b = await r.text().catch(() => ''); return { status: r.status, len: b.length }; }
  catch { return null; } finally { clearTimeout(t); }
})();
if (!baseline) die('baseline request failed — check the URL');
console.error(`[i] baseline: ${baseline.status}, ${baseline.len} bytes`);

const url0 = new URL(base);
const results = [];
let idx = 0;
await Promise.all(Array.from({ length: Math.min(conc, wordlist.length) }, async () => {
  while (idx < wordlist.length) {
    const p = wordlist[idx++];
    if (url0.searchParams.has(p)) continue;
    const u = new URL(base); u.searchParams.set(p, marker);
    const c = new AbortController(); const t = setTimeout(() => c.abort(), timeout);
    try {
      const r = await fetch(u, { signal: c.signal, redirect: 'manual' });
      const body = await r.text().catch(() => '');
      const lenDiff = body.length - baseline.len;
      const statusDiff = r.status !== baseline.status;
      const isReflected = reflect && body.includes(marker);
      const interesting = statusDiff || Math.abs(lenDiff) > 24 || isReflected;
      if (interesting) {
        results.push({ param: p, status: r.status, lenDiff, reflected: isReflected, reason: [statusDiff && `status ${baseline.status}->${r.status}`, Math.abs(lenDiff) > 24 && `len ${lenDiff > 0 ? '+' : ''}${lenDiff}`, isReflected && 'value reflected'].filter(Boolean).join('; ') });
        if (!flag(o, 'json')) console.log(`${p.padEnd(18)} status=${r.status} len=${lenDiff > 0 ? '+' : ''}${lenDiff}${isReflected ? ' REFLECTED' : ''}`);
      }
    } catch { /* timeout/conn reset — not interesting */ } finally { clearTimeout(t); }
  }
}));

if (flag(o, 'json')) console.log(JSON.stringify({ url: base, baseline, tested: wordlist.length, found: results.length, results }, null, 2));
else console.log(`\n${results.length} interesting params of ${wordlist.length} tested on ${base}`);
