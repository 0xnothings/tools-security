// dorkgen.js — generate ready-to-click search dork URLs for a domain.
// Copyright (c) 2026 0xnothings
// @tool dorkgen
// @desc Generate a categorised list of Google/Bing dork URLs for a domain (exposed files, panels, secrets, listings)
// @usage node tools/dorkgen.js example.com --category panels --json
// @tags security,recon,osint
import { args, get, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`dorkgen — dork URL generator

  node tools/dorkgen.js <domain|list.txt|-> [options]

  --engine <e>      google | bing | duckduckgo | all (default: google)
  --category <c>    files | panels | secrets | listing | vuln | cloud | social | api | all (default: all)
  --list            list categories and exit
  --open            also print the first match URL of each category shortlist
  --markdown        emit a markdown checklist instead of a table
  --json            machine-readable output
  -h, --help        this text

  Example: node tools/dorkgen.js example.com --category secrets`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };

const ENGINES = {
  google: (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}&num=50`,
  bing: (q) => `https://www.bing.com/search?q=${encodeURIComponent(q)}&count=50`,
  duckduckgo: (q) => `https://duckduckgo.com/?q=${encodeURIComponent(q)}`,
};

const DORKS = {
  files: [
    { d: 'exposed env files', q: 'site:{d} filetype:env' },
    { d: 'SQL dumps', q: 'site:{d} filetype:sql' },
    { d: 'log files', q: 'site:{d} filetype:log' },
    { d: 'backup archives', q: 'site:{d} (filetype:bak OR filetype:zip OR filetype:tar OR filetype:gz)' },
    { d: 'config files', q: 'site:{d} (filetype:config OR filetype:ini OR filetype:conf)' },
    { d: 'XML/YAML config', q: 'site:{d} (filetype:xml OR filetype:yml OR filetype:yaml) (password OR secret OR key)' },
    { d: 'spreadsheets', q: 'site:{d} (filetype:xls OR filetype:xlsx OR filetype:csv)' },
    { d: 'documents', q: 'site:{d} (filetype:pdf OR filetype:doc OR filetype:docx)' },
    { d: 'swap/editor leftovers', q: 'site:{d} (filetype:swp OR filetype:orig OR filetype:save)' },
    { d: 'source maps', q: 'site:{d} filetype:map inurl:.js.map' },
  ],
  panels: [
    { d: 'login panels', q: 'site:{d} inurl:login' },
    { d: 'admin panels', q: 'site:{d} (inurl:admin OR inurl:administrator)' },
    { d: 'dashboards', q: 'site:{d} intitle:dashboard' },
    { d: 'control panels', q: 'site:{d} inurl:cpanel OR inurl:webmail OR inurl:plesk' },
    { d: 'phpMyAdmin', q: 'site:{d} inurl:phpmyadmin' },
    { d: 'grafana/kibana', q: 'site:{d} (inurl:grafana OR inurl:kibana OR inurl:8086)' },
    { d: 'jenkins/ci', q: 'site:{d} (inurl:jenkins OR inurl:gitlab OR inurl:ci)' },
    { d: 'signup/register', q: 'site:{d} (inurl:signup OR inurl:register)' },
    { d: 'password reset', q: 'site:{d} (inurl:reset OR inurl:forgot)' },
    { d: 'staging/dev hosts', q: 'site:*.{d} (intitle:staging OR intitle:dev OR intitle:test)' },
  ],
  secrets: [
    { d: 'inline passwords', q: 'site:{d} (intext:password OR intext:passwd OR intext:pwd) -inurl:login' },
    { d: 'api keys', q: 'site:{d} (intext:"api_key" OR intext:"apikey" OR intext:"api-key")' },
    { d: 'aws keys', q: 'site:{d} (intext:AKIA OR intext:"aws_secret")' },
    { d: 'tokens', q: 'site:{d} (intext:"access_token" OR intext:"bearer" OR intext:"authorization:")' },
    { d: 'private keys', q: 'site:{d} (intext:"BEGIN RSA PRIVATE KEY" OR intext:"BEGIN OPENSSH PRIVATE KEY")' },
    { d: 'db connection strings', q: 'site:{d} (intext:"mysql://" OR intext:"postgres://" OR intext:"mongodb://" OR intext:"redis://")' },
    { d: 'slack/webhook urls', q: 'site:{d} (intext:"hooks.slack.com" OR intext:"webhook")' },
    { d: 'gitlab/github tokens', q: 'site:{d} (intext:"glpat-" OR intext:"ghp_" OR intext:"gho_")' },
    { d: 'jwt strings', q: 'site:{d} intext:"eyJhbGciOi"' },
    { d: 'pastebin leaks', q: 'site:pastebin.com "{d}"' },
  ],
  listing: [
    { d: 'open directory index', q: 'site:{d} intitle:"index of /"' },
    { d: 'index of admin', q: 'site:{d} intitle:"index of" inurl:admin' },
    { d: 'index of backup', q: 'site:{d} intitle:"index of" (backup OR backups OR bkp)' },
    { d: 'index of uploads', q: 'site:{d} intitle:"index of" (upload OR uploads)' },
    { d: 'parent directory', q: 'site:{d} intext:"parent directory"' },
    { d: 'index of logs', q: 'site:{d} intitle:"index of" (log OR logs)' },
    { d: 'index of db', q: 'site:{d} intitle:"index of" (db OR database OR sql)' },
    { d: 'exposed .git', q: 'site:{d} inurl:/.git' },
    { d: 'exposed .svn', q: 'site:{d} inurl:/.svn' },
    { d: 'DS_Store', q: 'site:{d} inurl:.DS_Store' },
  ],
  vuln: [
    { d: 'error pages', q: 'site:{d} (intext:"stack trace" OR intext:"SQL syntax" OR intext:"Warning: mysql")' },
    { d: 'php errors', q: 'site:{d} (intext:"Fatal error" OR intext:"Parse error")' },
    { d: 'phpinfo', q: 'site:{d} (inurl:phpinfo.php OR intitle:"phpinfo()")' },
    { d: 'crossdomain.xml', q: 'site:{d} inurl:crossdomain.xml' },
    { d: 'clientaccesspolicy', q: 'site:{d} inurl:clientaccesspolicy.xml' },
    { d: 'open redirects', q: 'site:{d} inurl:redirect' },
    { d: 'file upload', q: 'site:{d} (inurl:upload OR inurl:filemanager)' },
    { d: 'unrestricted POST forms', q: 'site:{d} inurl:action=' },
    { d: 'swagger docs', q: 'site:{d} (inurl:swagger OR inurl:api-docs OR inurl:openapi)' },
    { d: 'graphql', q: 'site:{d} (inurl:graphql OR inurl:graphiql)' },
  ],
  cloud: [
    { d: 'S3 buckets', q: 'site:s3.amazonaws.com "{d}"' },
    { d: 'Azure blobs', q: 'site:blob.core.windows.net "{d}"' },
    { d: 'GCS buckets', q: 'site:storage.googleapis.com "{d}"' },
    { d: 'digitalocean spaces', q: 'site:digitaloceanspaces.com "{d}"' },
    { d: 'firebase', q: 'site:firebaseio.com "{d}"' },
    { d: 'heroku apps', q: 'site:herokuapp.com "{d}"' },
    { d: 'netlify', q: 'site:netlify.app "{d}"' },
    { d: 'vercel', q: 'site:vercel.app "{d}"' },
  ],
  social: [
    { d: 'pastebin mentions', q: 'site:pastebin.com "{d}"' },
    { d: 'github code', q: 'site:github.com "{d}" (password OR secret OR token)' },
    { d: 'github gists', q: 'site:gist.github.com "{d}"' },
    { d: 'trello boards', q: 'site:trello.com "{d}"' },
    { d: 'linkedin employees', q: 'site:linkedin.com/in "{d}"' },
    { d: 'stackoverflow leaks', q: 'site:stackoverflow.com "{d}"' },
    { d: 'shodan-free hostnames', q: '"{d}" (shodan OR censys OR zoomeye)' },
    { d: 'email addresses', q: '"{d}" (email OR mailto) -site:{d}' },
  ],
  api: [
    { d: 'api endpoints', q: 'site:{d} inurl:api' },
    { d: 'json responses', q: 'site:{d} filetype:json' },
    { d: 'v1/v2 versioning', q: 'site:{d} (inurl:/v1/ OR inurl:/v2/ OR inurl:/v3/)' },
    { d: 'graphql introspection', q: 'site:{d} inurl:graphql (query OR mutation)' },
    { d: 'soap wsdl', q: 'site:{d} (inurl:.wsdl OR inurl:?wsdl)' },
    { d: 'api keys in urls', q: 'site:{d} (inurl:key= OR inurl:token= OR inurl:apikey=)' },
    { d: 'debug params', q: 'site:{d} (inurl:debug= OR inurl:test= OR inurl:dev=)' },
    { d: 'callback urls', q: 'site:{d} (inurl:callback= OR inurl:returnurl=)' },
  ],
};

if (flag(o, 'list')) {
  console.log(table(Object.entries(DORKS).map(([k, v]) => ({ category: k, dorks: v.length }))));
  exitSoon(0);
}

const engine = String(get(o, 'engine', 'google')).toLowerCase();
const cat = String(get(o, 'category', 'all')).toLowerCase();
if (engine !== 'all' && !ENGINES[engine]) die(`unknown engine "${engine}" (google|bing|duckduckgo|all)`);
if (cat !== 'all' && !DORKS[cat]) die(`unknown category "${cat}" — run with --list`);

let targets = o._.length ? o._ : ['-'];
let domains = [];
for (const t of targets) {
  if (t === '-' || /\.txt$/.test(t)) domains.push(...(await inputLines(t)));
  else domains.push(t.trim());
}
domains = [...new Set(domains.map((d) => d.replace(/^\*\./, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase()).filter(Boolean))];
if (!domains.length) die('no domain given');

const cats = cat === 'all' ? Object.keys(DORKS) : [cat];
const engines = engine === 'all' ? Object.keys(ENGINES) : [engine];
const out = [];
for (const d of domains) {
  for (const c of cats) {
    for (const entry of DORKS[c]) {
      const q = entry.q.replace(/\{d\}/g, d);
      const row = { domain: d, category: c, description: entry.d, query: q };
      for (const e of engines) row[e === 'google' ? 'url' : `${e}_url`] = ENGINES[e](q);
      out.push(row);
    }
  }
}

if (flag(o, 'json')) {
  console.log(JSON.stringify({ generated: new Date().toISOString(), count: out.length, dorks: out }, null, 2));
  exitSoon(0);
}

if (flag(o, 'markdown')) {
  for (const c of cats) {
    console.log(`\n## ${c}`);
    for (const r of out.filter((x) => x.category === c)) {
      console.log(`- [ ] **${r.description}** — \`${r.query}\``);
      console.log(`      ${r.url}`);
    }
  }
  console.log(`\n${out.length} dork(s) generated for ${domains.length} domain(s)`);
  exitSoon(0);
}

console.log(table(out.map((r) => ({ domain: r.domain, category: r.category, what: r.description, query: r.query.slice(0, 62) }))));
console.log(`\n${out.length} dork(s) across ${cats.length} category(ies) for ${domains.length} domain(s)`);
if (flag(o, 'open')) { console.log('\nURLs:'); for (const r of out) console.log(r.url); }
exitSoon(0);
