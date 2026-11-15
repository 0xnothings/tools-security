// pwnedpass.js — k-anonymity breach check against Pwned Passwords.
// Copyright (c) 2026 0xnothings
// @tool pwnedpass
// @desc Check passwords against the Pwned Passwords range API using k-anonymity — only a 5-char SHA-1 prefix leaves the machine
// @usage node tools/pwnedpass.js --password 'hunter2' --json
// @tags security,passwords,osint
import crypto from 'node:crypto';
import { args, get, num, flag, die, readInput, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`pwnedpass — Pwned Passwords check with k-anonymity

  node tools/pwnedpass.js [password|file|-] [options]

  Password sources, in order of precedence:
    --password <p>     a single literal password
    --hash <sha1hex>   a pre-computed SHA-1 (skips local hashing)
    <file|->           a file or stdin, one password per line

  --timeout <ms>     per-request timeout (default: 10000)
  --delay <ms>       delay between range requests (default: 120)
  --min-count <n>    only report entries seen at least this many times (default: 1)
  --fail-closed      treat network errors as a hard failure (default: report unknown)
  --json             machine-readable output
  -h, --help         this text

  Privacy: the password is SHA-1 hashed locally; only the FIRST FIVE hex
  characters of that hash are sent. The API returns every suffix sharing the
  prefix, and the comparison happens entirely on this machine. The full hash
  and the plaintext never leave the host.`);
  process.exit(0);
}

const exitSoon = (code = 0) => { process.exitCode = code; };
const timeout = num(get(o, 'timeout'), 10000);
const delay = num(get(o, 'delay'), 120);
const minCount = num(get(o, 'min-count'), 1);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const sha1 = (s) => crypto.createHash('sha1').update(String(s), 'utf8').digest('hex').toUpperCase();

async function rangeQuery(prefix) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'user-agent': 'pwnedpass-cli/1.0', 'add-padding': 'true' },
      signal: ctl.signal,
    });
    if (!r.ok) return { error: `HTTP ${r.status}`, map: null };
    const text = await r.text();
    const map = new Map();
    for (const line of text.split(/\r?\n/)) {
      const m = line.trim().match(/^([0-9A-F]{35}):(\d+)$/i);
      if (m) map.set(m[1].toUpperCase(), Number(m[2]));
    }
    return { map, prefix, candidates: map.size };
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'timeout' : (e.message || 'fetch failed'), map: null };
  } finally { clearTimeout(t); }
}

function strength(pw) {
  const len = pw.length;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  const pool = (/[a-z]/.test(pw) ? 26 : 0) + (/[A-Z]/.test(pw) ? 26 : 0) + (/[0-9]/.test(pw) ? 10 : 0) + (/[^A-Za-z0-9]/.test(pw) ? 33 : 0);
  const bits = pool > 0 ? Math.round(len * Math.log2(pool)) : 0;
  return { length: len, classes, bits, weak: len < 12 || classes < 3 || bits < 60 };
}

// ---------- collect inputs ----------
const items = [];
if (o.f.password !== undefined) items.push({ label: '(literal --password)', value: String(o.f.password), plaintext: true });
else if (o.f.hash !== undefined) items.push({ label: '(literal --hash)', value: String(o.f.hash).toUpperCase(), plaintext: false, presetHash: true });
else {
  const p = o._[0];
  const text = p && p !== '-' ? await readInput(p) : await readInput(null);
  const lines = String(text).split(/\r?\n/).map((s) => s).filter((s) => s.length);
  if (!lines.length) die('no password given — use --password, --hash, a file, or stdin');
  lines.forEach((l, i) => items.push({ label: `line ${i + 1}`, value: l, plaintext: true }));
}

// ---------- process ----------
const results = [];
const cache = new Map();
for (const item of items) {
  const hash = item.presetHash ? item.value.padStart(40, '0').slice(0, 40) : sha1(item.value);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  let entry;
  if (cache.has(prefix)) entry = cache.get(prefix);
  else {
    entry = await rangeQuery(prefix);
    cache.set(prefix, entry);
    await sleep(delay);
  }
  const rec = {
    label: item.label,
    // plaintext is deliberately not echoed back into the report
    sha1_prefix_sent: prefix,
    hash_sha1: flag(o, 'show-hash') ? hash : undefined,
    strength: item.plaintext ? strength(item.value) : null,
    found: false, count: 0, error: null, candidates_in_bucket: entry.candidates ?? null,
  };
  if (entry.error) {
    rec.error = entry.error;
    if (flag(o, 'fail-closed')) rec.verdict = 'UNKNOWN (fail-closed)';
  } else {
    const seen = entry.map.get(suffix);
    if (seen !== undefined && seen !== null) {
      rec.found = seen > 0;   // padded responses use count 0 for non-matches
      rec.count = seen;
      rec.verdict = rec.found && seen >= minCount ? `PWNED (${seen.toLocaleString('en-US')} sightings)` : 'not in breach corpus';
    } else rec.verdict = 'not in breach corpus';
    if (rec.count > 0) {
      if (rec.count > 100000) rec.risk = 'CRITICAL — appears in every cracking wordlist';
      else if (rec.count > 1000) rec.risk = 'HIGH — in common attack dictionaries';
      else if (rec.count > 10) rec.risk = 'MEDIUM — known breach exposure';
      else rec.risk = 'LOW — rare exposure';
    } else rec.risk = 'none observed';
  }
  results.push(rec);
}

const pwned = results.filter((r) => r.found);
const errored = results.filter((r) => r.error);

if (flag(o, 'json')) {
  console.log(JSON.stringify({
    generated: new Date().toISOString(),
    privacy: 'only the 5-character SHA-1 prefix was transmitted',
    checked: results.length, pwned: pwned.length, errors: errored.length,
    results: results.map((r) => ({ ...r, plaintext_echoed: false })),
  }, null, 2));
  exitSoon(pwned.length ? 2 : (errored.length && flag(o, 'fail-closed') ? 1 : 0));
}

console.log(`checked ${results.length} password(s); only the 5-char SHA-1 prefix left this machine`);
console.log(table(results.map((r) => ({
  entry: r.label.slice(0, 20),
  prefix: r.sha1_prefix_sent,
  found: r.found ? 'YES' : 'no',
  sightings: r.count || '',
  bits: r.strength ? r.strength.bits : '',
  weak_locally: r.strength ? (r.strength.weak ? 'yes' : 'no') : '',
  verdict: (r.verdict || r.error || '').slice(0, 42),
}))));

for (const r of pwned) {
  console.log(`\n[PWNED] ${r.label}: ${r.count.toLocaleString('en-US')} breach sightings -> ${r.risk}`);
}
if (errored.length) {
  console.log('\nerrors:');
  for (const r of errored) console.log(`  ${r.label}: ${r.error} (result unknown — the API did not answer)`);
}
const weakLocal = results.filter((r) => r.strength && r.strength.weak);
if (weakLocal.length) console.log(`\n${weakLocal.length} password(s) are also weak on local estimation (<60 bits or <12 chars)`);
console.log(`\n${pwned.length} of ${results.length} found in the breach corpus`);
exitSoon(pwned.length ? 2 : (errored.length && flag(o, 'fail-closed') ? 1 : 0));
