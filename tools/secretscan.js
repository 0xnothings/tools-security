// secretscan.js — scan files for hardcoded credentials and API keys.
// Copyright (c) 2026 0xnothings
// @tool secretscan
// @desc Scan source trees for hardcoded secrets: AWS/GCP/Stripe/Slack keys, private keys, JWTs, DB URLs
// @usage node tools/secretscan.js ./src --json --exclude node_modules,.git
// @tags security,secrets,audit
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname, relative } from 'node:path';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`secretscan — hardcoded credential scanner

  node tools/secretscan.js <path> [options]

  --exclude <list>    dirs to skip (default: node_modules,.git,dist,build,vendor)
  --ext <list>        only these extensions
  --max-size <kb>     skip files larger than this (default: 2048)
  --entropy           also flag high-entropy strings assigned to suspicious names
  --json              machine-readable output
  -h, --help          this text`);
  process.exit(0);
}

const RULES = [
  ['AWS Access Key ID', /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/, 'critical'],
  ['AWS Secret Key', /(?:aws)?_?(?:secret)?_?(?:access)?_?key['"]?\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]/i, 'critical'],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/, 'critical'],
  ['GitLab token', /\bglpat-[A-Za-z0-9_\-]{20,}\b/, 'critical'],
  ['Slack token', /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/, 'critical'],
  ['Stripe live key', /\bsk_live_[A-Za-z0-9]{20,}\b/, 'critical'],
  ['Stripe test key', /\bsk_test_[A-Za-z0-9]{20,}\b/, 'low'],
  ['Google API key', /\bAIza[0-9A-Za-z_\-]{35}\b/, 'high'],
  ['Google OAuth secret', /\bGOCSPX-[A-Za-z0-9_\-]{20,}\b/, 'high'],
  ['SendGrid key', /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/, 'high'],
  ['Twilio SID', /\bAC[a-f0-9]{32}\b/, 'medium'],
  ['OpenAI key', /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/, 'critical'],
  ['Anthropic key', /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/, 'critical'],
  ['HuggingFace token', /\bhf_[A-Za-z0-9]{30,}\b/, 'high'],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/, 'high'],
  ['Private key block', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, 'critical'],
  ['JWT', /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/, 'medium'],
  ['DB connection URI', /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s'"]*:[^\s'"@]{3,}@[^\s'"]+/i, 'high'],
  ['Basic auth in URL', /\bhttps?:\/\/[^\s'":@]{2,}:[^\s'":@]{3,}@[^\s/]+/i, 'high'],
  ['Hardcoded password', /(?:password|passwd|pwd|secret|token|apikey|api_key)['"]?\s*[:=]\s*['"]([^'"\s]{8,64})['"]/i, 'medium'],
  ['Firebase URL', /\bhttps:\/\/[a-z0-9\-]+\.firebaseio\.com\b/, 'low'],
  ['Heroku API key', /heroku[a-z0-9_]{0,10}['"]?\s*[:=]\s*['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]/i, 'high'],
];
const EXCLUDE = String(get(o, 'exclude', 'node_modules,.git,dist,build,vendor,coverage,.next,target')).split(',').map((s) => s.trim());
const EXTS = String(get(o, 'ext', '')).split(',').map((s) => s.trim()).filter(Boolean);
const MAXSIZE = num(get(o, 'max-size'), 2048) * 1024;
const root = o._[0] || '.';
const LOOKS_LIKE_PLACEHOLDER = /(example|sample|dummy|placeholder|your[_-]?key|xxxx|changeme|redacted|fake|test123|<[^>]+>|\$\{|\{\{)/i;

function* walk(dir) {
  let ents;
  try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (EXCLUDE.includes(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (e.isFile()) yield p;
  }
}

function shannon(s) {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  return -Object.values(f).reduce((a, n) => a + (n / s.length) * Math.log2(n / s.length), 0);
}

const findings = [];
const allowExt = EXTS.length ? new Set(EXTS.map((e) => (e.startsWith('.') ? e : '.' + e))) : null;
let files = 0;
for (const f of walk(root)) {
  if (allowExt && !allowExt.has(extname(f))) continue;
  let st; try { st = statSync(f); } catch { continue; }
  if (st.size > MAXSIZE) continue;
  if (/\.(png|jpe?g|gif|webp|ico|woff2?|ttf|eot|pdf|zip|gz|tar|mp4|mov|exe|dll|so|dylib|bin|class|jar|wasm)$/i.test(f)) continue;
  let text; try { text = readFileSync(f, 'utf8'); } catch { continue; }
  if (text.includes('\u0000')) continue;
  files++;
  const ls = text.split(/\r?\n/);
  for (let i = 0; i < ls.length; i++) {
    const line = ls[i];
    if (line.length > 4000) continue;
    for (const [rule, re, sev] of RULES) {
      const m = line.match(re);
      if (!m) continue;
      const hit = (m[1] || m[0]).trim();
      if (LOOKS_LIKE_PLACEHOLDER.test(hit)) continue;
      if (new Set(hit).size < 5) continue;
      findings.push({ file: relative(root, f), line: i + 1, rule, severity: sev, match: hit.slice(0, 60), context: line.trim().slice(0, 120) });
    }
    if (flag(o, 'entropy')) {
      for (const m of line.matchAll(/['"]([A-Za-z0-9+/=_\-]{20,80})['"]/g)) {
        const s = m[1];
        if (shannon(s) > 4.3 && /(?:key|secret|token|pass|salt|iv)/i.test(line)) {
          findings.push({ file: relative(root, f), line: i + 1, rule: 'high-entropy string', severity: 'low', match: s.slice(0, 60), context: line.trim().slice(0, 120) });
        }
      }
    }
  }
}

const order = { critical: 0, high: 1, medium: 2, low: 3 };
findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file));
if (flag(o, 'json')) console.log(JSON.stringify({ root, files_scanned: files, count: findings.length, findings }, null, 2));
else {
  console.log(table(findings.map((f) => ({ sev: f.severity, rule: f.rule, file: `${f.file}:${f.line}`, match: f.match }))));
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => c[f.severity]++);
  console.log(`\n${files} files scanned | ${findings.length} findings  (critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low})`);
}
