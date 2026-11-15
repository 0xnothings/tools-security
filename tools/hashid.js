#!/usr/bin/env node
// hashid.js — identify and generate hashes.
// Copyright (c) 2026 0xnothings
// @tool hashid
// @desc Identify hash type by format/prefix/length, or generate md5/sha1/sha256/sha512 for input
// @usage node tools/hashid.js '$2y$10$abc...' --gen sha256 --text hello
// @tags security,crypto,forensics
import crypto from 'node:crypto';
import { args, get, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`hashid — hash identification and generation

  node tools/hashid.js <hash|hashes.txt|-> [options]
  node tools/hashid.js --text <string> --gen <algo[,algo]>

  --text <s>       string to hash
  --gen <algos>    md5,sha1,sha256,sha512,sha3-256,ripemd160,base64,hex,url
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

const PATTERNS = [
  [/^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/, 'bcrypt', 'very slow (cost parameter embedded)'],
  [/^\$argon2(id|i|d)\$/, 'argon2', 'very slow'],
  [/^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$/, 'md5crypt (unix)', 'fast'],
  [/^\$5\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{43,}$/, 'sha256crypt (unix)', 'medium'],
  [/^\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86,}$/, 'sha512crypt (unix)', 'medium'],
  [/^\$y\$/, 'yescrypt', 'slow'],
  [/^[a-f0-9]{32}$/i, 'MD5 / NTLM / MD4', 'fast — use a wordlist'],
  [/^[a-f0-9]{40}$/i, 'SHA-1 (or MySQL5 / RIPEMD-160)', 'fast'],
  [/^[a-f0-9]{56}$/i, 'SHA-224', 'fast'],
  [/^[a-f0-9]{64}$/i, 'SHA-256 (or SHA3-256 / Keccak-256)', 'fast'],
  [/^[a-f0-9]{96}$/i, 'SHA-384', 'fast'],
  [/^[a-f0-9]{128}$/i, 'SHA-512 / Whirlpool', 'fast'],
  [/^[a-f0-9]{16}$/i, 'CRC-64 / DES crypt, half MD5', 'fast'],
  [/^[a-f0-9]{8}$/i, 'CRC-32 / Adler-32', 'fast'],
  [/^\*[A-F0-9]{40}$/, 'MySQL 4.1+ (mysql_native_password)', 'fast'],
  [/^\{SSHA\}[A-Za-z0-9+/=]{20,}$/, 'LDAP SSHA', 'fast'],
  [/^\{SHA\}[A-Za-z0-9+/=]{20,}$/, 'LDAP SHA', 'fast'],
  [/^[0-9a-f]{31}[0-9a-f]?\$?[A-Za-z0-9.]*$/, 'possible sha1 with salt variant', 'fast'],
  [/^\$P\$|\$H\$/, 'phpass (WordPress <2.5 / phpBB3)', 'medium'],
  [/^sha256\$|\$pbkdf2-sha256\$/, 'PBKDF2-SHA256', 'medium'],
  [/^[a-f0-9]{32}:[a-f0-9]{32}$/i, 'MD5(salt):MD5(pass) — vBulletin style', 'fast'],
  [/^[A-Za-z0-9+/]{27}=$/, 'possible base64 of a 16-byte value', 'encoding, not a hash'],
];
const ENCODERS = {
  md5: (s) => crypto.createHash('md5').update(s).digest('hex'),
  sha1: (s) => crypto.createHash('sha1').update(s).digest('hex'),
  sha256: (s) => crypto.createHash('sha256').update(s).digest('hex'),
  sha512: (s) => crypto.createHash('sha512').update(s).digest('hex'),
  'sha3-256': (s) => crypto.createHash('sha3-256').update(s).digest('hex'),
  ripemd160: (s) => crypto.createHash('ripemd160').update(s).digest('hex'),
  base64: (s) => Buffer.from(s).toString('base64'),
  hex: (s) => Buffer.from(s).toString('hex'),
  url: (s) => encodeURIComponent(s),
};

if (o.f.text !== undefined) {
  const s = String(get(o, 'text'));
  const algos = String(get(o, 'gen', 'md5,sha1,sha256,sha512')).split(',').map((x) => x.trim()).filter((x) => ENCODERS[x]);
  if (!algos.length) die(`unknown --gen value; supported: ${Object.keys(ENCODERS).join(', ')}`);
  const rows = algos.map((a) => ({ algo: a, digest: ENCODERS[a](s) }));
  if (flag(o, 'json')) console.log(JSON.stringify({ input: s, hashes: rows }, null, 2));
  else { console.log(table(rows)); console.log(`\nlength ${s.length} chars`); }
  process.exit(0);
}

let hashes = [];
if (o._.length) for (const h of o._) if (/-$|\.txt$/.test(h)) hashes.push(...(await inputLines(h))); else hashes.push(h);
else hashes = await inputLines('-');
if (!hashes.length) die('no hash given (pass a hash, a file, or pipe via stdin; or use --text/--gen)');

const out = [];
for (const h of hashes) {
  const matches = [];
  for (const [re, name, speed] of PATTERNS) if (re.test(h)) matches.push({ name, speed });
  out.push({ hash: h.length > 60 ? h.slice(0, 60) + '...' : h, len: h.length, matches: matches.length ? matches : [{ name: 'unknown', speed: '-' }] });
}

if (flag(o, 'json')) console.log(JSON.stringify(out, null, 2));
else for (const r of out) {
  console.log(`\n${r.hash}  (${r.len} chars)`);
  r.matches.forEach((m, i) => console.log(`  ${i === 0 ? '->' : '  '} ${m.name}${m.speed !== '-' ? '  [' + m.speed + ']' : ''}`));
}
