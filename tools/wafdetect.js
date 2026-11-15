#!/usr/bin/env node
// wafdetect.js — WAF and CDN detection.
// Copyright (c) 2026 0xnothings
// @tool wafdetect
// @desc Identify WAF/CDN by headers, cookies and blocked-payload behaviour; report likely bypass posture
// @usage node tools/wafdetect.js https://example.com --json
// @tags security,recon,waf
import { args, num, flag, die, inputLines, table, get } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`wafdetect — WAF / CDN identification

  node tools/wafdetect.js <url|urls.txt|-> [options]

  --timeout <ms>   request timeout (default: 10000)
  --active         send a benign attack payload to trip the WAF (default: on)
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

const SIGNATURES = [
  { name: 'Cloudflare', headers: [/^cf-ray$/i, /^cf-cache-status$/i], cookies: [/__cf_bm|cf_clearance/i], server: /cloudflare/i },
  { name: 'AWS CloudFront / WAF', headers: [/^x-amz-cf-id$/i, /^x-amz-cf-pop$/i], cookies: [/awsalb|aws-waf/i], server: /cloudfront/i },
  { name: 'Akamai', headers: [/^x-akamai-transformed$/i, /^akamai-grn$/i], cookies: [/^ak_bmsc|^bm_sz/i], server: /akamai|ghost/i },
  { name: 'Imperva / Incapsula', headers: [/^x-iinfo$/i], cookies: [/incap_ses|visid_incap|nlbi_/i], server: /incap/i },
  { name: 'F5 BIG-IP ASM', headers: [/^x-wa-info$/i], cookies: [/bigipserver|ts[a-f0-9]{8}/i], server: /big-?ip/i },
  { name: 'Sucuri', headers: [/^x-sucuri-id$/i, /^x-sucuri-cache$/i], cookies: [/sucuri/i], server: /sucuri/i },
  { name: 'Fastly', headers: [/^x-fastly-request-id$/i, /^fastly-debug/i], cookies: [/fastly/i], server: /fastly/i },
  { name: 'Varnish', headers: [/^x-varnish$/i, /^via$/i], cookies: [], server: /varnish/i },
  { name: 'Azure Front Door', headers: [/^x-azure-ref$/i, /^x-fd-int-roxy/i], cookies: [/afdv/i], server: /azure/i },
  { name: 'Google Cloud Armor', headers: [/^x-cloud-trace-context$/i], cookies: [/^gclb|^gcp/i], server: /gws|google/i },
  { name: 'Barracuda', headers: [/^x-barracuda/i], cookies: [/barra/i], server: /barracuda/i },
  { name: 'Fortinet FortiWeb', headers: [/^fortiwaf/i], cookies: [/fortiwaf/i], server: /fortiweb/i },
  { name: 'Citrix NetScaler', headers: [/^x-ns-request-id$/i, /^via.*ns-cache/i], cookies: [/^ns_af|citrix_ns_id/i], server: /netscaler/i },
  { name: 'Radware', headers: [/^x-rdwr/i], cookies: [/^rdwr/i], server: /radware/i },
  { name: 'StackPath / Highwinds', headers: [/^x-hw$/i], cookies: [], server: /stackpath|highwinds/i },
  { name: 'ModSecurity', headers: [], cookies: [], server: /mod_security|NOYB/i },
  { name: 'Wallarm', headers: [/^x-wallarm/i], cookies: [], server: /wallarm/i },
  { name: 'Reblaze', headers: [/^rbzid$/i], cookies: [/rbz/i], server: /reblaze/i },
  { name: 'DDoS-Guard', headers: [/^x-dd.*guard/i], cookies: [/ddg/i], server: /ddos-guard/i },
  { name: 'Qrator', headers: [/^x-qrator/i], cookies: [], server: /qrator/i },
];

async function detect(url, timeout) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  const found = [];
  let baseline;
  try {
    const res = await fetch(url, { signal: ctl.signal, redirect: 'follow', headers: { 'user-agent': 'Mozilla/5.0 (compatible; 0xnothings-waf/1.0)' } });
    const headers = [...res.headers.keys()];
    const cookies = (res.headers.getSetCookie?.() || []).join('; ');
    const server = res.headers.get('server') || '';
    baseline = { status: res.status, server };
    for (const sig of SIGNATURES) {
      const hitHeaders = sig.headers.filter((re) => headers.some((h) => re.test(h)));
      const hitCookies = sig.cookies.filter((re) => re.test(cookies));
      const hitServer = sig.server && sig.server.test(server);
      if (hitHeaders.length || hitCookies.length || hitServer) {
        found.push({ name: sig.name, evidence: [...hitHeaders.map(String), ...hitCookies.map(String), hitServer && `server:${server}`].filter(Boolean).join(', ') });
      }
    }
  } catch (e) { return { url, error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }

  const active = [];
  const probe = `${url}${url.includes('?') ? '&' : '?'}q=%3Cscript%3Ealert(1)%3C%2Fscript%3E%27%20OR%201%3D1--`;
  const t2 = setTimeout(() => {}, 0);
  try {
    const res2 = await fetch(probe, { headers: { 'user-agent': 'Mozilla/5.0 (compatible; 0xnothings-waf/1.0)' } });
    const body = await res2.text().catch(() => '');
    if (res2.status === 403 || res2.status === 406 || res2.status === 419 || res2.status === 429 || res2.status === 503) active.push(`blocked with HTTP ${res2.status}`);
    if (/access denied|blocked|request rejected|attention required|web application firewall|suspicious/i.test(body.slice(0, 4000))) active.push('block page text');
    if (baseline && res2.status !== baseline.status) active.push(`status changed ${baseline.status} -> ${res2.status}`);
  } catch (e) { if (/ECONNRESET|ECONNREFUSED/.test(String(e.cause?.code))) active.push('connection dropped on payload'); }
  clearTimeout(t2);
  return { url, server: baseline?.server || '-', waf: found, active_signals: active, protected: found.length > 0 || active.length > 0 };
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) urls.push(...(await inputLines(e))); else urls.push(e);
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u)))];
if (!urls.length) die('no url given');
const timeout = num(get(o, 'timeout'), 10000);

const results = [];
for (const u of urls) results.push(await detect(u, timeout));
if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); process.exit(0); }
console.log(table(results.map((r) => ({ url: r.url.slice(0, 40), server: r.server || r.error || '-', waf: (r.waf || []).map((w) => w.name).join(', ') || 'none', active: (r.active_signals || []).join('; ') || '-' }))));
for (const r of results) if (r.waf?.length) console.log(`\n${r.url}\n  ${r.waf.map((w) => `${w.name} (${w.evidence})`).join('\n  ')}`);
console.log(`\n${results.filter((r) => r.protected).length}/${results.length} hosts appear protected`);
