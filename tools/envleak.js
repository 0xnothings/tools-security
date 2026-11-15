#!/usr/bin/env node
// envleak.js — exposed config/secret file discovery.
// Copyright (c) 2026 0xnothings
// @tool envleak
// @desc Check hosts for exposed .env, .git, .svn, backup archives, phpinfo and CI config files
// @usage node tools/envleak.js https://example.com --json
// @tags security,web,exposure
import { args, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`envleak — exposed sensitive file discovery

  node tools/envleak.js <url|urls.txt|-> [options]

  --timeout <ms>   request timeout (default: 8000)
  --concurrency <n> parallel requests (default: 10)
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

const PATHS = [
  ['.env', /(APP_KEY|DB_PASSWORD|AWS_|SECRET)/],
  ['.env.local', /(APP_KEY|DB_|SECRET)/],
  ['.env.production', /=/],
  ['.env.backup', /=/],
  ['.git/config', /\[core\]/],
  ['.git/HEAD', /ref: refs\//],
  ['.gitignore', /^(node_modules|\/vendor|\.env)/m],
  ['.svn/entries', /\d+/],
  ['.DS_Store', /Bud1/],
  ['config.php.bak', /<\?php|\$db_/],
  ['wp-config.php.bak', /DB_PASSWORD/],
  ['wp-config.php.old', /DB_PASSWORD/],
  ['wp-config.php~', /DB_PASSWORD/],
  ['backup.zip', null],
  ['backup.tar.gz', null],
  ['db.sql', /CREATE TABLE|INSERT INTO/],
  ['dump.sql', /CREATE TABLE|INSERT INTO/],
  ['phpinfo.php', /PHP Version/],
  ['info.php', /PHP Version/],
  ['composer.json', /"require"/],
  ['package.json', /"dependencies"|"name"/],
  ['Dockerfile', /^FROM /m],
  ['docker-compose.yml', /services:/],
  ['.dockerignore', /node_modules/],
  ['server-status', /Apache Server Status/],
  ['web.config', /configuration/],
  ['appsettings.json', /ConnectionStrings/],
  ['.htpasswd', /:\$apr1\$|:\$2y\$/],
  ['id_rsa', /BEGIN (RSA |OPENSSH )?PRIVATE KEY/],
  ['credentials.json', /private_key/],
  ['.aws/credentials', /aws_access_key_id/],
  ['.npmrc', /_authToken/],
  ['.well-known/security.txt', /Contact:/],
  ['robots.txt', /Disallow:|User-agent:/],
  ['sitemap.xml', /<urlset/],
  ['adminer.php', /adminer/i],
  ['phpmyadmin/', /phpMyAdmin/],
  ['.vscode/sftp.json', /"password"|"privateKeyPath"/],
];

const SENSITIVE = new Set(['.env', '.env.local', '.env.production', '.env.backup', '.git/config', '.git/HEAD', 'db.sql', 'dump.sql', 'id_rsa', '.aws/credentials', '.npmrc', 'credentials.json', '.vscode/sftp.json', 'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php~', '.htpasswd', 'config.php.bak', 'appsettings.json']);

async function head(url, timeout) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, { signal: ctl.signal, redirect: 'manual', headers: { 'user-agent': '0xnothings-envleak/1.0' } });
    const body = res.status === 200 ? await res.text().catch(() => '') : '';
    return { status: res.status, ct: res.headers.get('content-type') || '', len: Number(res.headers.get('content-length') || body.length), body };
  } catch (e) { return { error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) urls.push(...(await inputLines(e))); else urls.push(e);
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u).replace(/\/+$/, '')))];
if (!urls.length) die('no url given');
const timeout = num(get(o, 'timeout'), 8000);
const conc = num(get(o, 'concurrency'), 10);

const jobs = [];
for (const u of urls) for (const [p, sig] of PATHS) jobs.push({ u, p, sig });
const hits = [];
let idx = 0;
await Promise.all(Array.from({ length: Math.min(conc, jobs.length) }, async () => {
  while (idx < jobs.length) {
    const j = jobs[idx++];
    const url = `${j.u}/${j.p}`;
    const r = await head(url, timeout);
    if (r.error || r.status !== 200) continue;
    if (r.ct.includes('text/html') && !['server-status', 'phpinfo.php', 'info.php', 'phpmyadmin/', '.well-known/security.txt', 'robots.txt', 'sitemap.xml'].includes(j.p)) continue;
    if (j.sig && !j.sig.test(r.body)) continue;
    const leak = j.p.startsWith('.env') && /(PASSWORD|SECRET|KEY)=/.test(r.body);
    hits.push({ url, path: j.p, bytes: r.len, sensitive: SENSITIVE.has(j.p), leak, sample: (r.body || '').split(/\r?\n/).filter((l) => /PASSWORD|SECRET|KEY|TOKEN/.test(l)).slice(0, 2).join(' | ').slice(0, 100) });
  }
}));

hits.sort((a, b) => Number(b.sensitive) - Number(a.sensitive));
if (flag(o, 'json')) console.log(JSON.stringify(hits, null, 2));
else {
  console.log(table(hits.map((h) => ({ sev: h.leak ? 'CRITICAL' : h.sensitive ? 'HIGH' : 'LOW', path: h.path, bytes: h.bytes, url: h.url.slice(0, 60), sample: h.sample }))));
  console.log(`\n${hits.length} exposed file(s) across ${urls.length} host(s)`);
}
