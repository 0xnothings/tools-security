// jwtpeek.js — Decode, inspect and lint JSON Web Tokens.
// Copyright (c) 2026 0xnothings
// @tool jwtpeek
// @desc Decode JWT header/payload, flag alg=none, missing expiry, weak claims, and HMAC-crackable secrets
// @usage node tools/jwtpeek.js eyJhbGci... --wordlist secrets.txt
// @tags security,auth,jwt
import crypto from 'node:crypto';
import { args, get, flag, die, inputLines } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`jwtpeek — JWT inspector

  node tools/jwtpeek.js <token|tokens.txt|-> [options]

  --wordlist <file>   brute-force the HMAC secret against this list
  --check-expiry      exit 2 if the token is expired (CI gate)
  --json              machine-readable output
  -h, --help          this text`);
  process.exit(0);
}

const b64u = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

function inspect(token) {
  const parts = token.split('.');
  if (parts.length < 2) return { token: token.slice(0, 24) + '...', error: 'not a JWT' };
  let head, payload;
  try { head = JSON.parse(b64u(parts[0])); } catch { return { token, error: 'bad header' }; }
  try { payload = JSON.parse(b64u(parts[1])); } catch { return { token, error: 'bad payload' }; }
  const issues = [];
  if (!head.alg) issues.push('alg missing');
  if (String(head.alg).toLowerCase() === 'none') issues.push('CRITICAL alg=none accepted signature-less');
  if (!payload.exp) issues.push('no exp claim (token never expires)');
  else if (payload.exp < Math.floor(Date.now() / 1000)) issues.push(`expired at ${new Date(payload.exp * 1000).toISOString()}`);
  else if (payload.exp - Math.floor(Date.now() / 1000) > 86400 * 30) issues.push('exp more than 30 days out');
  if (!payload.iat) issues.push('no iat claim');
  if (payload.aud === undefined) issues.push('no aud claim (cross-service replay)');
  if (payload.iss === undefined) issues.push('no iss claim');
  const interesting = ['role', 'roles', 'admin', 'is_admin', 'isAdmin', 'scope', 'scopes', 'perms', 'permissions', 'uid', 'user_id', 'sub', 'email', 'tenant', 'org'];
  const claims = Object.keys(payload).filter((k) => interesting.includes(k));
  return { token: token.length > 40 ? token.slice(0, 40) + '...' : token, parts: parts.length, alg: head.alg, typ: head.typ || '-', header: head, payload, interesting_claims: claims.map((k) => `${k}=${JSON.stringify(payload[k])}`), issues };
}

async function crack(token, words) {
  const [h, p, sig] = token.split('.');
  if (!sig) return null;
  for (const secret of words) {
    const mac = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
    if (mac === sig || crypto.createHmac('sha384', secret).update(`${h}.${p}`).digest('base64url') === sig || crypto.createHmac('sha512', secret).update(`${h}.${p}`).digest('base64url') === sig) return secret;
  }
  return null;
}

let tokens = [];
if (o._.length) {
  for (const t of o._) {
    if (/-$|\.txt$|\.lst$/.test(t)) tokens.push(...(await inputLines(t)));
    else tokens.push(t);
  }
} else tokens = await inputLines('-');
tokens = [...new Set(tokens.filter((t) => t.split('.').length >= 2))];
if (!tokens.length) die('no JWT found in input');

const results = [];
for (const t of tokens) {
  const r = inspect(t);
  if (o.f.wordlist && r.alg && /^HS/i.test(r.alg)) {
    const secret = await crack(t, await inputLines(get(o, 'wordlist')));
    if (secret) { r.cracked_secret = secret; r.issues = [...(r.issues || []), `WEAK SECRET CRACKED: "${secret}"`]; }
  }
  results.push(r);
}

if (flag(o, 'json')) console.log(JSON.stringify(results, null, 2));
else for (const r of results) {
  console.log(`\n--- ${r.token}`);
  if (r.error) { console.log(`  ${r.error}`); continue; }
  console.log(`  alg: ${r.alg}   typ: ${r.typ}   segments: ${r.parts}`);
  console.log(`  payload: ${JSON.stringify(r.payload)}`);
  if (r.interesting_claims.length) console.log(`  auth-relevant claims: ${r.interesting_claims.join(', ')}`);
  if (r.issues.length) { console.log('  issues:'); r.issues.forEach((i) => console.log(`    [!] ${i}`)); }
  else console.log('  no structural issues');
}

const first = results[0];
if (flag(o, 'check-expiry') && first?.payload?.exp && first.payload.exp < Math.floor(Date.now() / 1000)) process.exit(2);
