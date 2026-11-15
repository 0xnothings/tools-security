#!/usr/bin/env node
// dirb.js — HTTP path brute-forcer with soft-404 calibration.
// Copyright (c) 2026 0xnothings
// @tool dirb
// @desc HTTP path/directory brute-forcer with automatic soft-404 detection and extension expansion
// @usage node tools/dirb.js https://example.com --wordlist paths.txt --ext php,html,bak --json
// @tags security,web,recon
import { args, get, num, flag, die, inputLines, nowISO } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`dirb — HTTP path brute-forcer

  node tools/dirb.js <base-url> [options]

  --wordlist <file>   paths, one per line (default: built-in 70)
  --ext <list>        extensions to append: php,html,bak
  --concurrency <n>   parallel requests (default: 25)
  --timeout <ms>      request timeout   (default: 8000)
  --codes <list>      interesting codes (default: 200,201,204,301,302,307,401,403,405,500)
  --json              machine-readable output
  -h, --help          this text`);
  process.exit(0);
}

const BUILTIN = ['admin','administrator','admin.php','login','login.php','logout','dashboard','panel','cpanel','controlpanel','wp-admin','wp-login.php','wp-content','wp-includes','wp-json','xmlrpc.php','phpmyadmin','pma','adminer.php','db.php','sql','backup','backups','bak','old','test','tests','tmp','temp','dev','staging','demo','api','api/v1','api/v2','graphql','rest','v1','v2','swagger','swagger.json','openapi.json','api-docs','docs','documentation','status','health','healthz','metrics','debug','debug.log','error.log','access.log','phpinfo.php','info.php','config','config.php','config.json','.env','.git','.git/config','.git/HEAD','.svn','.htaccess','.htpasswd','robots.txt','sitemap.xml','sitemap_index.xml','crossdomain.xml','security.txt','.well-known/security.txt','uploads','files','static','assets','css','js','images','img','media','download','downloads','export','import','user','users','account','profile','settings','search','cgi-bin','server-status','server-info','web.config','composer.json','package.json','Dockerfile','docker-compose.yml','Makefile','README.md','CHANGELOG.md','LICENSE'];

const base = o._[0];
if (!base) die('usage: node tools/dirb.js <base-url> [--wordlist file] [--ext php,html]');
const root = base.replace(/\/+$/, '');
const words = o.f.wordlist ? await inputLines(get(o, 'wordlist')) : BUILTIN;
const exts = (get(o, 'ext', '') || '').split(',').map((s) => s.trim()).filter(Boolean);
const conc = num(get(o, 'concurrency'), 25);
const timeout = num(get(o, 'timeout'), 8000);
const codes = new Set(String(get(o, 'codes', '200,201,204,301,302,307,401,403,405,500')).split(',').map((s) => +s.trim()));
const ua = '0xnothings-dirb/1.0';

const paths = [];
for (const w of words) {
  paths.push(w);
  for (const e of exts) if (!w.endsWith('.' + e)) paths.push(`${w}.${e}`);
}

async function req(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, { redirect: 'manual', signal: ctl.signal, headers: { 'user-agent': ua } });
    const body = await res.text().catch(() => '');
    return { status: res.status, len: body.length, loc: res.headers.get('location') || '', title: (body.match(/<title[^>]*>([^<]{0,80})/i) || [, ''])[1].trim() };
  } catch { return null; } finally { clearTimeout(t); }
}

// soft-404 calibration: two random paths, if identical status+len treat as catch-all
const rnd1 = await req(`${root}/${Math.random().toString(36).slice(2, 12)}`);
const rnd2 = await req(`${root}/${Math.random().toString(36).slice(2, 12)}`);
let softLen = null;
if (rnd1 && rnd2 && rnd1.status === rnd2.status && Math.abs(rnd1.len - rnd2.len) < 32) softLen = rnd1.len;
if (softLen !== null) console.error(`[i] soft-404 calibrated: status ${rnd1.status}, len ~${softLen}`);

const hits = [];
let idx = 0;
await Promise.all(Array.from({ length: Math.min(conc, paths.length) }, async () => {
  while (idx < paths.length) {
    const p = paths[idx++];
    const url = `${root}/${p.replace(/^\/+/, '')}`;
    const r = await req(url);
    if (!r) continue;
    if (softLen !== null && r.status === rnd1.status && Math.abs(r.len - softLen) < 32) continue;
    if (!codes.has(r.status) && r.status !== 200) continue;
    if (r.status === 404) continue;
    hits.push({ status: r.status, len: r.len, url, loc: r.loc, title: r.title });
    if (!flag(o, 'json')) console.log(`${String(r.status).padEnd(4)} ${String(r.len).padEnd(8)} ${url}${r.loc ? '  -> ' + r.loc : ''}${r.title ? '  [' + r.title + ']' : ''}`);
  }
}));

hits.sort((a, b) => a.status - b.status || a.url.localeCompare(b.url));
if (flag(o, 'json')) console.log(JSON.stringify({ root, found_at: nowISO(), soft_404: softLen, count: hits.length, hits }, null, 2));
else console.log(`\n${hits.length} interesting paths on ${root} (${paths.length} probed)`);
