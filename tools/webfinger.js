#!/usr/bin/env node
// webfinger.js — passive technology fingerprinting from headers, cookies and body.
// Copyright (c) 2026 0xnothings
// @tool webfinger
// @desc Passive tech fingerprint: server, framework, CMS, JS libs, analytics, CDN, WAF
// @usage node tools/webfinger.js https://example.com --json
// @tags security,recon,fingerprint
import { args, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`webfinger — passive technology fingerprint

  node tools/webfinger.js <url|urls.txt|-> [options]

  --json           machine-readable output
  --timeout <ms>   request timeout (default: 12000)
  -h, --help       this text`);
  process.exit(0);
}

const HEADER_SIGS = [
  [/nginx/i, 'nginx'], [/apache/i, 'Apache'], [/iis/i, 'Microsoft IIS'], [/cloudflare/i, 'Cloudflare'],
  [/gunicorn/i, 'Gunicorn'], [/uvicorn/i, 'Uvicorn'], [/werkzeug/i, 'Werkzeug'], [/express/i, 'Express'],
  [/openresty/i, 'OpenResty'], [/litespeed/i, 'LiteSpeed'], [/caddy/i, 'Caddy'], [/deno/i, 'Deno Deploy'],
  [/vercel/i, 'Vercel'], [/netlify/i, 'Netlify'], [/github\.com/i, 'GitHub Pages'], [/amazons3/i, 'Amazon S3'],
  [/akamai/i, 'Akamai'], [/fastly/i, 'Fastly'], [/varnish/i, 'Varnish'], [/sucuri/i, 'Sucuri WAF'],
  [/incapsula|imperva/i, 'Imperva'], [/awselb/i, 'AWS ELB'], [/firebase/i, 'Firebase Hosting'],
];
const BODY_SIGS = [
  [/wp-content|wp-includes|\/wp-json\//i, 'WordPress'], [/\/sites\/default\/files|Drupal\.settings/i, 'Drupal'],
  [/joomla/i, 'Joomla'], [/Shopify\.theme|cdn\.shopify\.com/i, 'Shopify'], [/wixstatic|wix\.com/i, 'Wix'],
  [/squarespace/i, 'Squarespace'], [/webflow/i, 'Webflow'], [/__NEXT_DATA__|\/_next\//i, 'Next.js'],
  [/data-reactroot|react(-dom)?[.\-]/i, 'React'], [/vue(\.runtime)?[.\-]|__VUE__/i, 'Vue.js'],
  [/ng-version|angular[.\-]/i, 'Angular'], [/svelte/i, 'Svelte'], [/nuxt/i, 'Nuxt'],
  [/jquery[.\-]?(\d|\/)/i, 'jQuery'], [/bootstrap[.\-]/i, 'Bootstrap'], [/tailwind/i, 'Tailwind CSS'],
  [/gtag\/js|googletagmanager|google-analytics/i, 'Google Analytics/GTM'],
  [/connect\.facebook\.net|fbq\(/i, 'Meta Pixel'], [/static\.hotjar/i, 'Hotjar'], [/clarity\.ms/i, 'MS Clarity'],
  [/cloudflareinsights|cdn-cgi\//i, 'Cloudflare'], [/jsdelivr|unpkg\.com/i, 'Public CDN'],
  [/recaptcha|hcaptcha|turnstile/i, 'CAPTCHA'], [/stripe\.com\/v3|js\.stripe\.com/i, 'Stripe.js'],
  [/fonts\.googleapis\.com/i, 'Google Fonts'], [/matomo|piwik/i, 'Matomo'],
];

async function scan(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), Number(o.f.timeout) || 12000);
  try {
    const res = await fetch(url, { redirect: 'follow', signal: ctl.signal, headers: { 'user-agent': '0xnothings-finger/1.0' } });
    const body = await res.text().catch(() => '');
    const headerBlob = [...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n');
    const tech = [];
    for (const [re, name] of HEADER_SIGS) if (re.test(headerBlob)) tech.push({ name, via: 'header' });
    for (const [re, name] of BODY_SIGS) if (re.test(body)) tech.push({ name, via: 'body' });
    if (res.headers.get('x-powered-by')) tech.push({ name: res.headers.get('x-powered-by'), via: 'x-powered-by' });
    const cookies = (res.headers.getSetCookie?.() || []).map((c) => c.split('=')[0]).filter(Boolean);
    if (cookies.some((c) => /wordpress|wp-/i.test(c))) tech.push({ name: 'WordPress', via: 'cookie' });
    if (cookies.some((c) => /laravel_session/i.test(c))) tech.push({ name: 'Laravel', via: 'cookie' });
    if (cookies.some((c) => /JSESSIONID/i.test(c))) tech.push({ name: 'Java (JSESSIONID)', via: 'cookie' });
    if (cookies.some((c) => /PHPSESSID/i.test(c))) tech.push({ name: 'PHP (PHPSESSID)', via: 'cookie' });
    if (cookies.some((c) => /csrftoken/i.test(c))) tech.push({ name: 'Django (csrftoken)', via: 'cookie' });
    const seen = new Set();
    const uniq = tech.filter((x) => !seen.has(x.name.toLowerCase()) && seen.add(x.name.toLowerCase()));
    return { url, status: res.status, title: (body.match(/<title[^>]*>([^<]{0,120})/i) || [, ''])[1].trim(), bytes: body.length, cookies, tech: uniq };
  } catch (e) {
    return { url, error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) };
  } finally { clearTimeout(t); }
}

let raw = o._.length ? o._ : ['-'];
let urls = [];
for (const r of raw) if (/-$|\.txt$/.test(r)) urls.push(...(await inputLines(r))); else urls.push(r);
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u)))];
if (!urls.length) die('no urls given');

const out = [];
for (const u of urls) out.push(await scan(u));
if (flag(o, 'json')) { console.log(JSON.stringify(out, null, 2)); process.exit(0); }
for (const r of out) {
  console.log(`\n=== ${r.url}`);
  if (r.error) { console.log('  ERROR ' + r.error); continue; }
  console.log(`  ${r.status} | ${r.bytes} bytes | ${r.title || '(no title)'}`);
  console.log('  ' + (r.tech.length ? r.tech.map((x) => `${x.name} [${x.via}]`).join(', ') : 'no signature matched'));
  if (r.cookies.length) console.log('  cookies: ' + r.cookies.join(', '));
}
