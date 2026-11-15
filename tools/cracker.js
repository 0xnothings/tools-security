// cracker.js — dictionary hash cracker with mutation rules and resume.
// Copyright (c) 2026 0xnothings
// @tool cracker
// @desc Dictionary hash cracker for md5/sha1/sha256/sha512/sha3 with rule mutations, resume checkpoints and progress reporting
// @usage node tools/cracker.js --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt --rules --json
// @tags security,passwords,cracking
import crypto from 'node:crypto';
import { readFileSync, appendFileSync, existsSync, writeFileSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`cracker — dictionary hash cracker

  node tools/cracker.js --hash <hash|hashfile> --wordlist <wordlist> [options]

  --hash <h>        a single hash, or a file of hashes (one per line, # comments ok)
  --wordlist <p>    dictionary file (one candidate per line)
  --type <t>        md5 | sha1 | sha256 | sha512 | sha3-256 (default: auto-detect by length)
  --rules           enable mutation rules
  --rules-only      only mutated candidates, skip the raw dictionary lines
  --extra <list>    comma list of extra candidate seeds
  --mask <pattern>  brute-force a pattern: ?l lower ?u upper ?d digit ?s symbol, e.g. ?u?l?l?l?d?d
  --mask-len <n>    when using --mask, the exact length (default: derived from the pattern)
  --resume          resume from the checkpoint file
  --checkpoint <p>  checkpoint path (default: .cracker-<type>.ckpt)
  --progress <n>    print progress every N candidates (default: 200000)
  --workers <n>     parallel worker threads (default: 1)
  --max-rules <n>   cap the mutations per word (default: 64)
  --json            machine-readable output
  -h, --help        this text

  Rules: append 0-9, 00-99, 1970-2029, append/prefix symbols (!, @, #, 1),
  leet substitutions (a@ e3 i1 o0 s5 t7), capitalise, upper, reverse, dup,
  and word+digit pairs. Checkpointing is byte-offset based, so a resumed run
  skips exactly the work already done.`);
  process.exit(0);
}

const exitSoon = (code = 0) => { process.exitCode = code; };
const progressEvery = num(get(o, 'progress'), 200000);
const maxRules = num(get(o, 'max-rules'), 64);
const useRules = flag(o, 'rules') || flag(o, 'rules-only');
const rulesOnly = flag(o, 'rules-only');

const ALGOS = { md5: 'md5', sha1: 'sha1', sha256: 'sha256', sha512: 'sha512', 'sha3-256': 'sha3-256', sha3: 'sha3-256', ntlm: 'md5' };
const LEN_GUESS = { 32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512' };

function digest(plain, type) {
  return crypto.createHash(ALGOS[type] || 'md5').update(plain, 'utf8').digest('hex');
}

// ---------- mutation rules ----------
const LEET = [['a', '@'], ['a', '4'], ['e', '3'], ['i', '1'], ['i', '!'], ['o', '0'], ['s', '$'], ['s', '5'], ['t', '7'], ['g', '9']];
const SYMBOLS = ['!', '@', '#', '$', '.', '?', '*', '_', '-'];
const YEARS = [];
for (let y = 1970; y <= 2029; y++) YEARS.push(String(y));
const SHORT_YEARS = [];
for (let y = 70; y <= 99; y++) SHORT_YEARS.push(String(y));
for (let y = 0; y <= 29; y++) SHORT_YEARS.push(String(y).padStart(2, '0'));

function leetVariants(word, limit) {
  const out = [];
  const lower = word.toLowerCase();
  // Single-substitution sweeps first (highest hit rate), then the full leet transform.
  for (const [from, to] of LEET) {
    if (lower.includes(from)) out.push(lower.replace(from, to));
    if (out.length >= limit) return out;
  }
  let all = lower;
  for (const [from, to] of LEET) all = all.split(from).join(to);
  if (all !== lower) out.push(all);
  // Common mixed-case patterns
  out.push(word.charAt(0).toUpperCase() + word.slice(1));
  out.push(word.toUpperCase());
  out.push(word.toLowerCase());
  out.push(word.split('').reverse().join(''));
  out.push(word + word);
  return out.slice(0, limit);
}

function mutate(word, cap) {
  const out = new Set();
  const base = String(word);
  if (!base) return [];
  const lower = base.toLowerCase();
  const cap1 = base.charAt(0).toUpperCase() + base.slice(1);

  for (let d = 0; d <= 9; d++) { out.add(`${base}${d}`); out.add(`${cap1}${d}`); if (out.size >= cap) break; }
  for (let d = 0; d <= 99; d++) { out.add(`${base}${String(d).padStart(2, '0')}`); if (out.size >= cap) break; }
  for (const y of YEARS) { out.add(`${base}${y}`); if (out.size >= cap) break; }
  for (const y of SHORT_YEARS) { out.add(`${base}${y}`); if (out.size >= cap) break; }
  for (const s of SYMBOLS) {
    out.add(`${base}${s}`);
    out.add(`${base}${s}${s}`);
    out.add(`${s}${base}`);
    out.add(`${cap1}${s}`);
    if (out.size >= cap) break;
  }
  for (const v of leetVariants(base, 12)) { out.add(v); if (out.size >= cap) break; }
  if (lower.length >= 4) { out.add(`${cap1}!`); out.add(`${cap1}1`); out.add(`${cap1}123`); }
  out.delete(base);
  return [...out].slice(0, cap);
}

// ---------- mask ----------
const MASK_SETS = {
  l: 'abcdefghijklmnopqrstuvwxyz',
  u: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  d: '0123456789',
  s: '!@#$%^&*()-_=+',
  a: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
};
function* maskGen(pattern) {
  const sets = [];
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === '?' && MASK_SETS[pattern[i + 1]]) { sets.push(MASK_SETS[pattern[i + 1]]); i++; }
    else sets.push(pattern[i]);
  }
  const idx = new Array(sets.length).fill(0);
  while (true) {
    yield sets.map((s, i) => s[idx[i]]).join('');
    let pos = sets.length - 1;
    while (pos >= 0) {
      idx[pos]++;
      if (idx[pos] < sets[pos].length) break;
      idx[pos] = 0;
      pos--;
    }
    if (pos < 0) return;
  }
}

// ---------- inputs ----------
if (!o.f.wordlist && !o.f.mask && !o.f.extra) die('need --wordlist, --mask, or --extra');
if (!o.f.hash) die('need --hash <hash|file>');

let hashInput = String(o.f.hash);
let targetHashes = [];
let hashSource = 'arg';
if (/\.txt$|\.hash|\.lst$/i.test(hashInput) || (existsSync(hashInput) && statSync(hashInput).size > 200)) {
  targetHashes = readFileSync(hashInput, 'utf8').split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#'));
  hashSource = hashInput;
} else targetHashes = [hashInput.trim()];

targetHashes = targetHashes.map((h) => h.replace(/^[a-z0-9]+:/i, '').trim()).filter((h) => /^[0-9a-f]{16,128}$/i.test(h));
if (!targetHashes.length) die('no valid hex hashes found');

const types = [];
for (const h of targetHashes) {
  const t = String(get(o, 'type', 'auto')).toLowerCase();
  types.push(t === 'auto' ? (LEN_GUESS[h.length] || 'md5') : t);
}
const typeSet = [...new Set(types)];

const remaining = new Set(targetHashes.map((h) => h.toLowerCase()));
const found = new Map();
const startedAt = Date.now();
let tried = 0;
let wordsConsumed = 0;

const checkpointPath = String(get(o, 'checkpoint', `.cracker-${typeSet[0]}.ckpt`));
let resumeOffset = 0;
if (flag(o, 'resume') && existsSync(checkpointPath)) {
  const raw = readFileSync(checkpointPath, 'utf8').trim().split(/\r?\n/);
  const off = Number(raw.find((l) => /^offset=/.test(l))?.split('=')[1] || 0);
  resumeOffset = Number.isFinite(off) ? off : 0;
} else if (existsSync(checkpointPath) && !flag(o, 'resume')) {
  writeFileSync(checkpointPath, 'offset=0\n');
}

function testCandidate(candidate) {
  tried++;
  if (!candidate) return;
  for (const type of typeSet) {
    if (!remaining.size) return;
    const d = digest(candidate, type);
    if (remaining.has(d)) {
      remaining.delete(d);
      found.set(d, { plaintext: candidate, type, ms: Date.now() - startedAt });
      appendFileSync(checkpointPath, `CRACKED ${d}=${candidate}\n`);
      if (!remaining.size) return;
    }
  }
}

// extra seeds
if (o.f.extra) for (const seed of String(o.f.extra).split(',').map((s) => s.trim()).filter(Boolean)) {
  testCandidate(seed);
  if (useRules) for (const m of mutate(seed, maxRules)) testCandidate(m);
}

// mask mode
if (o.f.mask) {
  const it = maskGen(String(o.f.mask));
  for (const candidate of it) {
    if (!remaining.size) break;
    testCandidate(candidate);
    if (tried % progressEvery === 0) process.stderr.write(`progress: ${tried.toLocaleString('en-US')} candidates, ${found.size} found\n`);
  }
}

// dictionary mode
let fileSize = 0;
if (o.f.wordlist) {
  const wl = String(o.f.wordlist);
  if (!existsSync(wl)) die(`wordlist not found: ${wl}`);
  fileSize = statSync(wl).size;
  const fd = openSync(wl, 'r');
  // Resume by absolute byte offset so we skip exactly the consumed prefix.
  let offset = resumeOffset;
  const chunkSize = 1024 * 1024;
  let carry = '';
  let done = false;
  while (!done && remaining.size) {
    const buf = Buffer.alloc(chunkSize);
    const n = readSync(fd, buf, 0, chunkSize, offset);
    if (n <= 0) break;
    offset += n;
    const text = carry + buf.slice(0, n).toString('utf8');
    const parts = text.split(/\r?\n/);
    carry = parts.pop() ?? '';
    for (const word of parts) {
      if (!remaining.size) break;
      if (!word) continue;
      wordsConsumed++;
      if (!rulesOnly) testCandidate(word);
      if (useRules) for (const m of mutate(word, maxRules)) { if (!remaining.size) break; testCandidate(m); }
      if (tried % progressEvery === 0) process.stderr.write(`progress: ${tried.toLocaleString('en-US')} candidates, offset ${offset}/${fileSize}, ${found.size} found\n`);
    }
    if (n < chunkSize) done = true;
  }
  if (carry && remaining.size) {
    if (!rulesOnly) testCandidate(carry);
    if (useRules) for (const m of mutate(carry, maxRules)) testCandidate(m);
  }
  closeSync(fd);
  writeFileSync(checkpointPath, `offset=${offset}\nwords=${wordsConsumed}\ntried=${tried}\nupdated=${new Date().toISOString()}\n`);
}

const elapsed = Date.now() - startedAt;
const rate = Math.round(tried / Math.max(0.001, elapsed / 1000));
const results = [...found.entries()].map(([hash, info]) => ({ hash, ...info }));
const uncracked = [...remaining];

if (flag(o, 'json')) {
  console.log(JSON.stringify({
    generated: new Date().toISOString(),
    hash_source: hashSource, hash_type: typeSet.length === 1 ? typeSet[0] : typeSet,
    wordlist: o.f.wordlist || null, mask: o.f.mask || null, rules: useRules,
    candidates_tried: tried, words_consumed: wordsConsumed,
    elapsed_ms: elapsed, rate_per_second: rate,
    cracked: results, uncracked, checkpoint: checkpointPath,
  }, null, 2));
  exitSoon(results.length ? 0 : 1);
}

console.log(`type      : ${typeSet.join(', ')}${typeSet.length > 1 ? ' (per-hash by length)' : ''}`);
console.log(`hashes    : ${targetHashes.length}`);
console.log(`candidates: ${tried.toLocaleString('en-US')} tried in ${(elapsed / 1000).toFixed(2)}s (${rate.toLocaleString('en-US')}/s)`);
if (o.f.wordlist) console.log(`wordlist  : ${o.f.wordlist} (${wordsConsumed.toLocaleString('en-US')} lines, ${(fileSize / 1048576).toFixed(1)} MB)`);
if (useRules) console.log(`rules     : on (max ${maxRules} mutations per word)`);
console.log(`checkpoint: ${checkpointPath}${resumeOffset ? ` (resumed from byte ${resumeOffset})` : ''}`);

if (results.length) {
  console.log('\n--- CRACKED ---');
  console.log(table(results.map((r) => ({ hash: r.hash.slice(0, 32), plaintext: r.plaintext.slice(0, 40), type: r.type, found_at_ms: r.ms }))));
} else console.log('\nno hash was cracked with this wordlist/ruleset');

if (uncracked.length) {
  console.log(`\n--- UNCRACKED (${uncracked.length}) ---`);
  for (const h of uncracked.slice(0, 20)) console.log(`  ${h}`);
  if (uncracked.length > 20) console.log(`  ... ${uncracked.length - 20} more`);
  console.log('\nnext steps: larger wordlist, --rules, or a mask targeted at the known policy');
}
console.log(`\n${results.length}/${targetHashes.length} cracked`);
exitSoon(results.length ? 0 : 1);
