// vulncheck.js — local web-app hardening audit (no network).
// Copyright (c) 2026 0xnothings
// @tool vulncheck
// @desc Static audit of a web project: dangerous sinks, missing auth checks, insecure randoms, upload handling
// @usage node tools/vulncheck.js ./src --json
// @tags security,sast,audit
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname, relative } from 'node:path';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`vulncheck — static sink-driven security audit

  node tools/vulncheck.js <dir> [options]

  --exclude <list>   dirs to skip (default: node_modules,.git,dist,build,vendor)
  --max-size <kb>    skip large files (default: 1024)
  --json             machine-readable output
  -h, --help         this text`);
  process.exit(0);
}

const SINKS = [
  [/exec\s*\(|execSync\s*\(|spawn\s*\(|spawnSync\s*\(/g, 'HIGH', 'command execution'],
  [/eval\s*\(|new\s+Function\s*\(/g, 'HIGH', 'dynamic code execution'],
  [/child_process/g, 'MEDIUM', 'child_process import'],
  [/\.query\s*\(|\.execute\s*\(|\.raw\s*\(/g, 'MEDIUM', 'raw SQL call — verify parameterisation'],
  [/\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)/gi, 'HIGH', 'SQL string interpolation'],
  [/(?:readFile|writeFile|unlink|rm|rmdir|readdir)\s*\(/g, 'MEDIUM', 'filesystem operation — verify path is not user controlled'],
  [/\brequire\s*\(\s*[a-zA-Z_$]/g, 'MEDIUM', 'dynamic require'],
  [/(?:innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML)/g, 'MEDIUM', 'DOM XSS sink'],
  [/\bres\.redirect\s*\(|\bres\.location\b/g, 'LOW', 'redirect — check allowlist'],
  [/(?:JSON\.parse\s*\(\s*req\.|deserialize|unserialize)/g, 'MEDIUM', 'unsafe deserialisation'],
  [/Math\.random\s*\(/g, 'LOW', 'Math.random in security context — use crypto.randomBytes'],
  [/(?:createCipheriv|createHmac)[^)]*['"](?:des|rc4|md5|sha1)['"]/gi, 'HIGH', 'weak crypto primitive'],
  [/rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED/g, 'HIGH', 'TLS verification disabled'],
  [/(?:cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"])|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*/g, 'HIGH', 'wildcard CORS'],
  [/localStorage\.(?:setItem|getItem)\s*\(\s*['"][^'"]*(?:token|jwt|auth|session)/gi, 'MEDIUM', 'token in localStorage'],
  [/session\s*=\s*false|httpOnly\s*:\s*false/gi, 'MEDIUM', 'cookie hardening disabled'],
];
const AUTH_HINTS = /\b(?:router|app)\.(get|post|put|patch|delete)\s*\(\s*['"`][^'"`]+/;
const AUTH_MIDDLEWARE = /(?:requireAuth|isAuthenticated|authMiddleware|verifyToken|checkPermission|ensureAdmin|guard|jwt\.verify|passport\.authenticate)/;
const PARSERS = /express\.json|bodyParser|multer|formidable|busboy|express\.urlencoded|fastify\.multipart/;
const UPLOAD = /\.upload\s*\(|multer\s*\(|move_uploaded_file|file\.mv\s*\(/;

const EXCLUDE = String(get(o, 'exclude', 'node_modules,.git,dist,build,vendor,coverage,.next,target')).split(',').map((s) => s.trim());
const MAXSIZE = num(get(o, 'max-size'), 1024) * 1024;
const root = o._[0] || '.';
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.php', '.py', '.rb', '.go', '.java']);

function* walk(dir) {
  let ents; try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (EXCLUDE.includes(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p); else if (e.isFile()) yield p;
  }
}

const findings = [];
const routeStats = [];
let files = 0;
for (const f of walk(root)) {
  if (!CODE_EXT.has(extname(f))) continue;
  let st; try { st = statSync(f); } catch { continue; }
  if (st.size > MAXSIZE) continue;
  files++;
  const text = readFileSync(f, 'utf8');
  const ls = text.split(/\r?\n/);
  const hasParser = PARSERS.test(text);
  const hasAuthMw = AUTH_MIDDLEWARE.test(text);
  let routes = 0, unguarded = 0;
  for (let i = 0; i < ls.length; i++) {
    const line = ls[i];
    if (line.length > 3000) continue;
    for (const [re, sev, why] of SINKS) {
      re.lastIndex = 0;
      if (!re.test(line)) continue;
      if (/^\s*(?:\/\/|#|\*)/.test(line)) continue;
      findings.push({ severity: sev, file: relative(root, f), line: i + 1, issue: why, code: line.trim().slice(0, 110) });
    }
    if (AUTH_HINTS.test(line)) {
      routes++;
      if (!AUTH_MIDDLEWARE.test(line)) {
        unguarded++;
        findings.push({ severity: 'MEDIUM', file: relative(root, f), line: i + 1, issue: 'route without inline auth middleware', code: line.trim().slice(0, 110) });
      }
    }
  }
  if (hasParser && UPLOAD.test(text)) findings.push({ severity: 'LOW', file: relative(root, f), line: 0, issue: 'upload handler present without visible type/size validation', code: '(file-level)' });
  if (routes) routeStats.push({ file: relative(root, f), routes, unguarded, authMw: hasAuthMw });
}

const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
findings.sort((a, b) => order[a.severity] - order[b.severity]);

if (flag(o, 'json')) console.log(JSON.stringify({ root, files_scanned: files, routes: routeStats, count: findings.length, findings }, null, 2));
else {
  console.log(table(findings.slice(0, 80).map((f) => ({ sev: f.severity, issue: f.issue, where: `${f.file}:${f.line}`, code: f.code.slice(0, 60) }))));
  if (findings.length > 80) console.log(`... ${findings.length - 80} more (use --json)`);
  const c = { HIGH: 0, MEDIUM: 0, LOW: 0 }; findings.forEach((f) => c[f.severity]++);
  console.log(`\n${files} files | ${findings.length} findings (high ${c.HIGH}, medium ${c.MEDIUM}, low ${c.LOW})`);
  if (routeStats.length) console.log(`${routeStats.reduce((a, r) => a + r.routes, 0)} route definitions, ${routeStats.reduce((a, r) => a + r.unguarded, 0)} without inline auth middleware`);
}
