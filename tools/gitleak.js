#!/usr/bin/env node
// gitleak.js — scan a git history for dangling secrets in diffs.
// Copyright (c) 2026 0xnothings
// @tool gitleak
// @desc Walk `git log -p` and flag secrets that were committed (even if later removed) plus .env/.pem blobs
// @usage node tools/gitleak.js ./repo --since 1.year --json
// @tags security,git,secrets
import { execFileSync } from 'node:child_process';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`gitleak — git history secret scanner

  node tools/gitleak.js <repo-dir> [options]

  --since <when>     git --since value (default: all history)
  --max-commits <n>  limit history depth (default: 3000)
  --history-only     only scan diffs, skip the working tree
  --json             machine-readable output
  -h, --help         this text`);
  process.exit(0);
}

const repo = o._[0] || '.';
const git = (argsArr, maxBuffer = 512 * 1024 * 1024) => execFileSync('git', ['-C', repo, ...argsArr], { maxBuffer, encoding: 'utf8' });

try { git(['rev-parse', '--is-inside-work-tree']); } catch { die(`${repo} is not a git repository`); }

const RULES = [
  ['AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_\-]{20,}\b/],
  ['Slack token', /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/],
  ['Stripe live key', /\bsk_live_[A-Za-z0-9]{20,}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_\-]{35}\b/],
  ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/],
  ['SendGrid key', /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/],
  ['.env assignment', /^\+\s*(?:DB_|AWS_|SECRET|API_KEY|TOKEN|PASSWORD|PRIVATE)[A-Z0-9_]*\s*=\s*\S{6,}/m],
  ['URI with password', /(?:postgres|mysql|mongodb|redis|amqp)(?:\+srv)?:\/\/[^\s:@]+:[^\s:@]+@/],
  ['Generic secret assign', /(?:secret|password|passwd|token|api[_-]?key)\s*[:=]\s*['"][^'"]{12,}['"]/i],
];
const SAFE = /(example|placeholder|your[_-]?(key|token)|xxxx|changeme|redacted|<[^>]+>|\$\{|process\.env|os\.environ|getenv)/i;

let diff = '';
try {
  const since = o.f.since ? [`--since=${get(o, 'since')}`] : [];
  const depth = o.f['max-commits'] ? [`-${get(o, 'max-commits')}`] : [];
  diff = git(['log', '-p', '--all', '--no-color', '--unified=0', ...since, ...depth]);
} catch (e) { die('git log failed: ' + e.message); }

const findings = [];
let commit = '', file = '', line = '';
for (const l of diff.split(/\r?\n/)) {
  if (/^commit [0-9a-f]{7,40}/.test(l)) commit = l.split(' ')[1].slice(0, 10);
  else if (l.startsWith('+++ b/')) file = l.slice(6);
  else if (l.startsWith('@@')) line = (l.match(/\+(\d+)/) || [, '?'])[1];
  else if (l.startsWith('+') && !l.startsWith('+++')) {
    for (const [rule, re] of RULES) {
      const m = l.match(re);
      if (!m || SAFE.test(m[0])) continue;
      findings.push({ commit, file, line, rule, match: m[0].slice(0, 70) });
    }
  }
}
const flagged = diff.split(/\r?\n/).filter((l) => /^\+\+\+ b\/.*\.(env|pem|key|pfx|p12|keystore|jks|sql|bak|dump)$/.test(l)).map((l) => l.slice(6));
const files = [...new Set(flagged)];

if (flag(o, 'json')) console.log(JSON.stringify({ repo, commits_scanned: (diff.match(/^commit /gm) || []).length, secret_files: files, count: findings.length, findings }, null, 2));
else {
  console.log(table(findings.map((f) => ({ rule: f.rule, commit: f.commit, location: `${f.file}:${f.line}`, match: f.match }))));
  console.log(`\n${findings.length} secret hit(s) across ${(diff.match(/^commit /gm) || []).length} commit(s)`);
  if (files.length) console.log(`sensitive files ever committed:\n  ` + files.join('\n  '));
}
