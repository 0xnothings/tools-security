// jsenum.js — mine JavaScript bundles for endpoints and secrets.
// Copyright (c) 2026 0xnothings
// @tool jsenum
// @desc Extract API paths, hidden routes, domains, cloud buckets and secret-like strings from JS files
// @usage node tools/jsenum.js https://example.com/app.js --json
// @tags security,recon,js
import { args, get, num, flag, die, inputLines } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`jsenum — JavaScript bundle miner

  node tools/jsenum.js <js-url|html-url|urls.txt|-> [options]

  --depth <n>        follow script src discovered in HTML (default: 1)
  --timeout <ms>     request timeout (default: 15000)
  --json             machine-readable output
  -h, --help         this text`);
  process.exit(0);
}

const PATH_RE = /["'`](\/(?:[a-zA-Z0-9_\-.~%]+)(?:\/[a-zA-Z0-9_\-.~%{}:]*)*)["'`]/g;
const API_RE = /["'`]((?:https?:\/\/|\/\/)[a-zA-Z0-9_\-.]+(?::\d+)?(?:\/[a-zA-Z0-9_\-.~%/{}\$:]*)*)["'`]/g;
const FETCH_RE = /(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(\s*["'`]([^"'`]{2,200})["'`]/g;
const SECRET_RE = [
  ['aws', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['google', /\bAIza[0-9A-Za-z_\-]{35}\b/],
  ['stripe', /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b/],
  ['github', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['slack', /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/],
  ['mapbox', /\bpk\.[A-Za-z0-9_\-]{60,}\b/],
  ['firebase', /\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b/],
  ['jwt', /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/],
  ['basic-auth', /["'`]Basic\s+[A-Za-z0-9+/=]{16,}["'`]/],
];
const INTERESTING = [/\/(?:admin|internal|debug|private|secret|upload|export|import|backup|config)(?:\/|["'`?])/i, /api[_-]?key/i, /graphql/i, /websocket|wss?:/i, /eval\(|new Function\(/];

async function grab(url, timeout) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { 'user-agent': 'Mozilla/5.0 (compatible; 0xnothings-jsenum/1.0)' } });
    return { ok: res.ok, status: res.status, text: await res.text(), ct: res.headers.get('content-type') || '' };
  } catch (e) { return { error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

function mine(text, origin) {
  const setOf = (re) => [...new Set([...text.matchAll(re)].map((m) => m[1]))];
  const paths = setOf(PATH_RE).filter((p) => p.length > 2 && !/\.(png|jpe?g|gif|svg|woff2?|css|ico)$/i.test(p));
  const absolute = setOf(API_RE);
  const fetches = setOf(FETCH_RE);
  const secrets = [];
  for (const [name, re] of SECRET_RE) { const m = text.match(re); if (m) secrets.push({ type: name, sample: m[0].slice(0, 70) }); }
  const flags = INTERESTING.filter((re) => re.test(text)).map((re) => re.source.slice(0, 40));
  const externals = [...new Set(absolute.filter((u) => /^https?:\/\//.test(u)).map((u) => { try { return new URL(u).host; } catch { return null; } }).filter(Boolean))];
  return { origin, paths: [...new Set([...paths, ...fetches.filter((f) => f.startsWith('/'))])].sort(), absolute: [...new Set([...absolute, ...fetches.filter((f) => /^https?/.test(f))])].sort(), externals, secrets, flags };
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) urls.push(...(await inputLines(e))); else urls.push(e);
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u)))];
if (!urls.length) die('no url given');
const timeout = num(get(o, 'timeout'), 15000);
const depth = num(get(o, 'depth'), 1);

const results = [];
const seen = new Set();
async function mineUrl(url, level) {
  if (seen.has(url) || level < 0) return;
  seen.add(url);
  const r = await grab(url, timeout);
  if (r.error) { results.push({ url, error: r.error }); return; }
  if (/html/.test(r.ct)) {
    const srcs = [...r.text.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]);
    const base = new URL(url);
    const abs = srcs.map((s) => { try { return new URL(s, base).toString(); } catch { return null; } }).filter(Boolean);
    results.push({ url, kind: 'html', scripts: abs.length });
    for (const s of abs.slice(0, 40)) await mineUrl(s, level - 1);
    return;
  }
  const mined = mine(r.text, url);
  mined.bytes = r.text.length;
  mined.kind = 'js';
  results.push(mined);
}

for (const u of urls) await mineUrl(u, depth);

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); process.exit(0); }
for (const r of results) {
  console.log(`\n=== ${r.url}`);
  if (r.error) { console.log('  ERROR ' + r.error); continue; }
  if (r.kind === 'html') { console.log(`  html with ${r.scripts} script src`); continue; }
  console.log(`  ${r.bytes} bytes`);
  if (r.paths.length) { console.log(`  paths (${r.paths.length}):`); r.paths.slice(0, 60).forEach((p) => console.log('    ' + p)); }
  if (r.absolute.length) { console.log(`  absolute urls (${r.absolute.length}):`); r.absolute.slice(0, 25).forEach((p) => console.log('    ' + p)); }
  if (r.externals.length) console.log(`  hosts: ${r.externals.join(', ')}`);
  if (r.secrets.length) { console.log('  [!] secret-like strings:'); r.secrets.forEach((s) => console.log(`    ${s.type}: ${s.sample}`)); }
  if (r.flags.length) console.log(`  interesting tokens: ${r.flags.join(' | ')}`);
}
