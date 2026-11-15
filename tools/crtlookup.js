// crtlookup.js — certificate transparency subdomain enumeration via crt.sh.
// Copyright (c) 2026 0xnothings
// @tool crtlookup
// @desc Enumerate subdomains from certificate transparency logs (crt.sh + certspotter fallback)
// @usage node tools/crtlookup.js example.com --json
// @tags security,recon,osint,dns
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`crtlookup — certificate transparency subdomain enumeration

  node tools/crtlookup.js <domain|domains.txt|-> [options]

  --source <s>     crtsh | certspotter | both (default: crtsh)
  --full           include wildcards and non-matching names (default: filtered)
  --wild           only output names that resolved as wildcard certs
  --timeout <ms>   per-request timeout (default: 30000)
  --json           machine-readable output
  -h, --help       this text

  Example: node tools/crtlookup.js example.com`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };

const UA = 'crtlookup/1.0 (+security-research)';
const timeout = num(get(o, 'timeout'), 30000);
const source = String(get(o, 'source', 'crtsh')).toLowerCase();

async function getJson(u, extra) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(u, {
      headers: { 'user-agent': UA, accept: 'application/json', ...(extra || {}) },
      signal: ctl.signal,
      redirect: 'follow',
    });
    const text = await r.text();
    if (!r.ok) return { error: `HTTP ${r.status}`, body: text.slice(0, 200) };
    try { return { data: JSON.parse(text) }; } catch { return { error: 'non-json response', body: text.slice(0, 200) }; }
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'timeout' : (e.message || 'fetch failed') };
  } finally { clearTimeout(t); }
}

async function fromCrtsh(domain) {
  const out = [];
  for (const q of [`%.${domain}`, domain]) {
    const r = await getJson(`https://crt.sh/?q=${encodeURIComponent(q)}&output=json`);
    if (r.error) return { error: r.error, names: out };
    if (!Array.isArray(r.data)) continue;
    for (const row of r.data) {
      for (const n of String(row.name_value || '').split('\n')) {
        const clean = n.trim().toLowerCase();
        if (clean) out.push({
          name: clean,
          issuer: row.issuer_name || '',
          not_before: row.not_before || '',
          not_after: row.not_after || '',
          serial: row.serial_number || '',
          source: 'crtsh',
        });
      }
    }
    if (out.length) break;
  }
  return { names: out };
}

async function fromCertspotter(domain) {
  const out = [];
  const r = await getJson(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`);
  if (r.error) return { error: r.error, names: out };
  if (!Array.isArray(r.data)) return { names: out };
  for (const row of r.data) {
    for (const n of row.dns_names || []) {
      out.push({
        name: String(n).toLowerCase(),
        issuer: row.issuer?.name || '',
        not_before: row.not_before || '',
        not_after: row.not_after || '',
        serial: row.id || '',
        source: 'certspotter',
      });
    }
  }
  return { names: out };
}

let targets = o._.length ? o._ : ['-'];
let domains = [];
for (const t of targets) {
  if (t === '-' || /\.txt$/.test(t)) domains.push(...(await inputLines(t)));
  else domains.push(t.trim());
}
domains = [...new Set(domains.map((d) => d.replace(/^\*\./, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim()).filter(Boolean))];
if (!domains.length) die('no domains given');

const allFindings = [];
const perHost = [];
for (const d of domains) {
  let found = [];
  const errs = [];
  if (source === 'crtsh' || source === 'both') {
    const a = await fromCrtsh(d);
    if (a.error) errs.push(`crtsh: ${a.error}`);
    found = found.concat(a.names);
  }
  if (source === 'certspotter' || source === 'both' || (!found.length && errs.length)) {
    const b = await fromCertspotter(d);
    if (b.error) errs.push(`certspotter: ${b.error}`);
    found = found.concat(b.names);
  }

  const seen = new Map();
  for (const f of found) {
    for (const n of [f.name, ...f.name.split(/\s+/)]) {
      const clean = n.replace(/^\*\./, '').trim();
      if (!clean) continue;
      if (!seen.has(clean)) seen.set(clean, { ...f, name: clean, wildcard: f.name.startsWith('*') });
    }
  }

  const inScope = [...seen.values()].filter((f) => f.name.endsWith(d) || f.name === d);
  perHost.push({ domain: d, unique: inScope.length, errors: errs, rows: inScope });
  for (const f of inScope) allFindings.push({ domain: d, ...f });
}

if (flag(o, 'json')) {
  console.log(JSON.stringify({
    domains: perHost.map((h) => ({ domain: h.domain, unique_names: h.unique, errors: h.errors })),
    count: allFindings.length,
    names: allFindings.map((f) => ({
      name: f.name, domain: f.domain, wildcard: !!f.wildcard, issuer: f.issuer,
      not_before: f.not_before, not_after: f.not_after, serial: String(f.serial).slice(0, 32), source: f.source,
    })),
  }, null, 2));
  exitSoon(0);
}

let rows = allFindings;
if (flag(o, 'wild')) rows = rows.filter((f) => f.wildcard);
else if (!flag(o, 'full')) rows = rows.filter((f) => !f.wildcard);

const subnames = rows.map((f) => ({ subdomain: f.name, domain: f.domain, issuer: (f.issuer || '').replace(/^.*?O=([^,]+).*$/, '$1').slice(0, 40), not_after: (f.not_after || '').slice(0, 10), src: f.source }));
console.log(table(subnames));

const summary = perHost.map((h) => ({ domain: h.domain, names: h.unique, errors: h.errors.join('; ') || '' }));
console.log('\n' + table(summary));
console.log(`\n${allFindings.length} unique name(s) across ${domains.length} domain(s)`);
