// takeover.js — subdomain takeover candidate detector.
// Copyright (c) 2026 0xnothings
// @tool takeover
// @desc Resolve subdomains, match response bodies against 40+ dangling-service fingerprints, report CNAME target
// @usage node tools/takeover.js subdomains.txt --concurrency 20 --json
// @tags security,recon,takeover
import dns from 'node:dns';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`takeover — subdomain takeover detector

  node tools/takeover.js <host|hosts.txt|-> [options]

  --concurrency <n>  parallel checks (default: 20)
  --timeout <ms>     request timeout  (default: 9000)
  --json             machine-readable output
  -h, --help         this text`);
  process.exit(0);
}

const FP = [
  [/NoSuchBucket/i, 'AWS S3', 'create a bucket with that name'],
  [/The specified bucket does not exist/i, 'AWS S3', 'register the bucket'],
  [/Repository not found|There isn.t a GitHub Pages site here/i, 'GitHub Pages', 'claim the repo + pages site'],
  [/project not found|Your connection is not private.*gitlab/i, 'GitLab Pages', 'claim the namespace'],
  [/Do not have permission to access this page.*s3/i, 'AWS S3 permission', 'bucket takeover'],
  [/404 Web Site not found|This site is no longer available/i, 'Azure App Service', 'create the app service name'],
  [/".*cloudapp.azure.com" not found/i, 'Azure CloudApp', 'register the cloudapp'],
  [/herokucdn\.com\/error-pages|No such app/i, 'Heroku', 'register the app name'],
  [/There isn.t a Github Pages site here/i, 'GitHub Pages', 'claim pages'],
  [/Fastly error: unknown domain/i, 'Fastly', 'add the domain to your service'],
  [/The feed has not been found|Sorry, looks like we can.t find that page/i, 'FeedPress', 'claim the feed'],
  [/This domain is not configured|is not configured on this/i, 'Pantheon', 'claim site'],
  [/Unrecognized domain|no such app/i, 'Shopify', 'claim the shop domain'],
  [/page not found.*tumblr/i, 'Tumblr', 'claim blog'],
  [/Whatever you were looking for doesn.t currently exist/i, 'Tumblr', 'claim blog'],
  [/The page you are looking for doesn.t exist.*wordpress/i, 'WordPress.com', 'claim subdomain'],
  [/Domain not found|Do you want to register/i, 'Generic DNS/parking', 'register domain'],
  [/Looks like you.ve traveled too far|project not found/i, 'Netlify', 'claim the site name'],
  [/This site can.t be reached|DNS_PROBE_FINISHED_NXDOMAIN/i, 'Dangling DNS (no host)', 'claim the target host'],
  [/nginx.*404 Not Found.*amazonaws/i, 'AWS ELB dangling', 'claim the load balancer'],
  [/<title>Site not found<\/title>/i, 'Generic host not found', 'claim host'],
  [/webflow.*not found|This site is not published/i, 'Webflow', 'claim the project'],
  [/Kinsta.*not found|site not linked/i, 'Kinsta', 'claim site'],
  [/cargo.*site not found|404.*cargo/i, 'Cargo (Cargo Collective)', 'claim site'],
  [/Surge.*project not found|project not found.*surge/i, 'Surge.sh', 'claim project'],
  [/This page is not yet available|Vercel.*DEPLOYMENT_NOT_FOUND/i, 'Vercel', 'claim deployment'],
  [/DEPLOYMENT_NOT_FOUND|The deployment could not be found/i, 'Vercel', 'claim deployment'],
  [/not found.*bitbucket|Repository not found.*bitbucket/i, 'Bitbucket Cloud', 'claim repo'],
  [/Sorry, this shop is currently unavailable/i, 'Shopify (closed)', 'claim shop'],
  [/This UserVoice instance is currently unavailable/i, 'UserVoice', 'claim instance'],
  [/No settings were found for this company/i, 'Help Scout', 'claim docs site'],
  [/This help center no longer exists/i, 'Zendesk', 'claim subdomain'],
  [/Sorry, this page isn.t available/i, 'Unbounce', 'claim page'],
  [/is forbidden.*amazonaws|AccessDenied.*s3/i, 'S3 AccessDenied', 'bucket enumeration'],
  [/The specified key does not exist/i, 'S3 key missing', 'bucket exists, path wrong'],
  [/Please use the direct URL|Statuspage.*not found/i, 'Statuspage', 'claim page'],
  [/app not found|Application error/i, 'Heroku app not found', 'claim app name'],
];

async function check(host, timeout) {
  const out = { host };
  try {
    const cname = await dns.promises.resolveCname(host).catch(() => []);
    if (cname.length) out.cname = cname.join(', ');
    const a = await dns.promises.resolve4(host).catch(() => []);
    if (a.length) out.a = a.join(', ');
  } catch {}
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(`http://${host}/`, { signal: ctl.signal, redirect: 'follow', headers: { 'user-agent': 'Mozilla/5.0' } });
    const body = await res.text().catch(() => '');
    out.status = res.status;
    for (const [re, svc, action] of FP) {
      if (re.test(body)) { out.service = svc; out.action = action; out.evidence = (body.match(re) || [''])[0].slice(0, 80); break; }
    }
  } catch (e) { out.error = e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message); }
  finally { clearTimeout(t); }
  return out;
}

let entries = o._.length ? o._ : ['-'];
let hosts = [];
for (const e of entries) if (/-$|\.txt$|\.[a-z]{2,}$/.test(e) && !/^https?:/.test(e)) hosts.push(e.trim()); else hosts.push(...(await inputLines(e)));
hosts = [...new Set(hosts.map((h) => h.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase()).filter(Boolean))];
if (!hosts.length) die('no hosts given');

const conc = num(get(o, 'concurrency'), 20);
const timeout = num(get(o, 'timeout'), 9000);
const results = [];
let idx = 0;
await Promise.all(Array.from({ length: Math.min(conc, hosts.length) }, async () => {
  while (idx < hosts.length) {
    const r = await check(hosts[idx++], timeout);
    results.push(r);
    if (!flag(o, 'json') && r.service) console.log(`[TAKEOVER] ${r.host}  ${r.service}  -> ${r.action}   cname=${r.cname || '-'}`);
  }
}));

const vulnerable = results.filter((r) => r.service);
if (flag(o, 'json')) console.log(JSON.stringify({ checked: results.length, vulnerable: vulnerable.length, results }, null, 2));
else {
  console.log(table(vulnerable.map((r) => ({ host: r.host, service: r.service, cname: r.cname || '-', action: r.action }))));
  console.log(`\n${vulnerable.length} takeover candidate(s) of ${results.length} hosts`);
  const dangling = results.filter((r) => !r.a && !r.cname);
  if (dangling.length) console.log(`nxdomain (${dangling.length}): ${dangling.slice(0, 20).map((d) => d.host).join(', ')}`);
}
