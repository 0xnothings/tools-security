// wayback.js — archived URL harvester via the Wayback CDX API.
// Copyright (c) 2026 0xnothings
// @tool wayback
// @desc Harvest historical URLs for a domain from the Wayback CDX index, filtered and deduped by path
// @usage node tools/wayback.js example.com --filter js,php,json --limit 5000 --json
// @tags security,recon,osint
import { args, get, num, flag, die, inputLines } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`wayback — historical URL harvester

  node tools/wayback.js <domain|domains.txt|-> [options]

  --filter <ext>     only keep these extensions: js,php,json,env,sql,bak,zip
  --from <YYYYMMDD>  start timestamp
  --to <YYYYMMDD>    end timestamp
  --limit <n>        max raw records to fetch per domain (default: 2000)
  --collapse         dedupe by URL path (default on)
  --json             machine-readable output
  -h, --help         this text`);
  process.exit(0);
}

const filters = String(get(o, 'filter', '')).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const limit = num(get(o, 'limit'), 2000);
const collapse = o.f.collapse !== false;

async function harvest(domain) {
  const p = new URLSearchParams({ url: `${domain}/*`, output: 'json', limit: String(limit), fl: 'original,timestamp,mimetype,statuscode', collapse: collapse ? 'urlkey' : 'none' });
  if (o.f.from) p.set('from', String(get(o, 'from')));
  if (o.f.to) p.set('to', String(get(o, 'to')));
  const url = `http://web.archive.org/cdx/search/cdx?${p}`;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 60000);
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { 'user-agent': '0xnothings-wayback/1.0' } });
    if (!res.ok) return { domain, error: `HTTP ${res.status}` };
    const rows = await res.json().catch(() => []);
    if (!Array.isArray(rows) || rows.length < 2) return { domain, count: 0, urls: [] };
    const [head, ...body] = rows;
    const idx = Object.fromEntries(head.map((h, i) => [h, i]));
    let urls = body.map((r) => ({ url: r[idx.original], ts: r[idx.timestamp], mime: r[idx.mimetype], status: r[idx.statuscode] }));
    if (filters.length) urls = urls.filter((u) => filters.some((f) => u.url.toLowerCase().split('?')[0].endsWith('.' + f) || u.mime?.toLowerCase().includes(f)));
    const seen = new Set();
    urls = urls.filter((u) => {
      const key = collapse ? u.url.split('?')[0] : u.url;
      if (seen.has(key)) return false; seen.add(key); return true;
    });
    return { domain, count: urls.length, urls };
  } catch (e) { return { domain, error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

let raw = o._.length ? o._ : ['-'];
let domains = [];
for (const r of raw) if (/-$|\.txt$/.test(r)) domains.push(...(await inputLines(r))); else domains.push(r);
domains = [...new Set(domains.map((d) => d.replace(/^https?:\/\//, '').replace(/\/.*$/, '')).filter(Boolean))];
if (!domains.length) die('no domain given');

const results = [];
for (const d of domains) {
  const r = await harvest(d);
  results.push(r);
  if (!flag(o, 'json')) {
    if (r.error) { console.log(`[${d}] ERROR ${r.error}`); continue; }
    console.log(`\n=== ${d}  ${r.count} unique urls`);
    r.urls.slice(0, 200).forEach((u) => console.log(`  ${u.status ?? ''}  ${u.ts || ''}  ${u.url}`));
    if (r.count > 200) console.log(`  ... ${r.count - 200} more`);
  }
}
if (flag(o, 'json')) console.log(JSON.stringify(results, null, 2));
