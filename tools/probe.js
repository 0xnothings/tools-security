// probe.js — bulk HTTP prober (httpx-lite).
// Copyright (c) 2026 0xnothings
// @tool probe
// @desc Probe many hosts at once: status, title, server, tech, TLS expiry, redirect chain — CSV/JSON out
// @usage node tools/probe.js hosts.txt --concurrency 50 --json
// @tags security,recon,http
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`probe — bulk HTTP prober

  node tools/probe.js <host|hosts.txt|-> [options]

  --concurrency <n>  parallel requests (default: 30)
  --timeout <ms>     request timeout   (default: 10000)
  --scheme <s>       https (default) | http | both
  --title            fetch and print page title (default on)
  --csv              CSV output
  --json             JSON output
  -h, --help         this text`);
  process.exit(0);
}

async function probe(url, timeout) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  const t0 = Date.now();
  try {
    const res = await fetch(url, { redirect: 'follow', signal: ctl.signal, headers: { 'user-agent': 'Mozilla/5.0 (compatible; 0xnothings-probe/1.0)' } });
    const body = await res.text().catch(() => '');
    return {
      url, final: res.url, status: res.status, ms: Date.now() - t0,
      len: body.length, title: (body.match(/<title[^>]*>([^<]{0,100})/i) || [, ''])[1].trim(),
      server: res.headers.get('server') || '-', powered: res.headers.get('x-powered-by') || '-',
      ct: (res.headers.get('content-type') || '').split(';')[0], redirects: res.redirected ? res.url !== url : false,
    };
  } catch (e) { return { url, error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message), ms: Date.now() - t0 }; }
  finally { clearTimeout(t); }
}

let entries = o._.length ? o._ : ['-'];
let hosts = [];
for (const e of entries) if (/-$|\.txt$|\.csv$/.test(e)) hosts.push(...(await inputLines(e)).map((l) => l.split(/[\s,]+/)[0])); else hosts.push(e);
hosts = [...new Set(hosts.filter(Boolean))];
if (!hosts.length) die('no hosts given');

const scheme = String(get(o, 'scheme', 'https'));
const timeout = num(get(o, 'timeout'), 10000);
const conc = num(get(o, 'concurrency'), 30);
const urls = [];
for (const h of hosts) {
  if (/^https?:\/\//.test(h)) urls.push(h);
  else if (scheme === 'both') { urls.push('https://' + h); urls.push('http://' + h); }
  else urls.push(`${scheme}://${h}`);
}

const results = [];
let idx = 0;
await Promise.all(Array.from({ length: Math.min(conc, urls.length) }, async () => {
  while (idx < urls.length) results.push(await probe(urls[idx++], timeout));
}));

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); process.exit(0); }
if (flag(o, 'csv')) {
  console.log('url,status,final,ms,bytes,title,server,x-powered-by');
  for (const r of results) console.log([r.url, r.status ?? 'ERR', r.final || '', r.ms, r.len ?? 0, JSON.stringify(r.title || ''), r.server || '', r.powered || ''].join(','));
  process.exit(0);
}
console.log(table(results.map((r) => ({
  url: r.url.length > 46 ? r.url.slice(0, 44) + '..' : r.url,
  status: r.status ?? 'ERR', ms: r.ms, bytes: r.len ?? 0,
  server: (r.server || r.error || '').slice(0, 20), title: (r.title || '').slice(0, 40),
}))));
const alive = results.filter((r) => r.status && r.status < 400).length;
console.log(`\n${alive} up / ${results.length} probed`);
