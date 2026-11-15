// covertunnel.js — DNS/ICMP tunnel feasibility tester.
// Copyright (c) 2026 0xnothings
// @tool covertunnel
// @desc Measure whether a resolver forwards arbitrary subdomains and what DNS/ICMP tunnel throughput and payload capacity it allows
// @usage node tools/covertunnel.js example.com --json
// @tags security,network,tunneling,dns
import dns from 'node:dns';
import crypto from 'node:crypto';
import net from 'node:net';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`covertunnel — DNS/ICMP tunnel feasibility tester

  node tools/covertunnel.js <domain|list.txt|-> [options]

  --resolver <ip>    resolver to test (default: system resolver)
  --queries <n>      throughput sample size (default: 40)
  --conc <n>         parallel queries (default: 5)
  --payload <n>      payload bytes per label to test capacity (default: 63)
  --timeout <ms>     per-query timeout (default: 4000)
  --icmp             also measure ICMP echo reachability (needs raw socket privileges)
  --sink <ip>        tunnel endpoint to test for resolution of arbitrary names
  --json             machine-readable output
  -h, --help         this text

  Measurements:
    1. wildcard check      — does a random subdomain resolve?
    2. arbitrary forwarding — how many random names return an answer
    3. label capacity      — longest base32/base64 label the resolver accepts
    4. recursion           — does the resolver answer for a zone it is not authoritative for
    5. throughput          — queries/second achievable through it
    6. encoding budget     — usable bytes per query for hex/base32/base64 payloads`);
  process.exit(0);
}

const exitSoon = (code = 0) => { process.exitCode = code; };
const timeout = num(get(o, 'timeout'), 4000);
const queries = num(get(o, 'queries'), 40);
const conc = num(get(o, 'conc'), 5);
const payloadBytes = num(get(o, 'payload'), 63);

const resolver = get(o, 'resolver', null);
if (resolver) {
  try { dns.setServers(String(resolver).split(',').map((s) => s.trim())); } catch { die(`invalid resolver "${resolver}"`); }
}

function resolveRand(name) {
  return new Promise((resolve) => {
    const started = Date.now();
    const timer = setTimeout(() => resolve({ name, status: 'timeout', ms: Date.now() - started, answers: [] }), timeout);
    dns.resolve4(name, (err, addrs) => {
      clearTimeout(timer);
      if (err) return resolve({ name, status: err.code || 'ERROR', ms: Date.now() - started, answers: [] });
      resolve({ name, status: 'ANSWER', ms: Date.now() - started, answers: addrs || [] });
    });
  });
}

const randLabel = (n, alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789') => {
  const bytes = crypto.randomBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[bytes[i] % alphabet.length];
  return s;
};

async function runPool(items, fn, limit) {
  const out = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const i = cursor++;
      out[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

function icmpProbe(host, ms) {
  // ICMP requires raw sockets; without privileges we report an explicit limitation
  // rather than pretending the path is closed.
  return new Promise((resolve) => {
    let sock;
    try {
      // A SOCK_RAW ICMP socket is not portable from Node without native privileges.
      sock = net.createConnection({ host, port: 7 }); // fall back to an echo-service probe
    } catch (e) {
      return resolve({ reachable: false, note: `raw ICMP unavailable: ${e.message}` });
    }
    const t = setTimeout(() => { try { sock.destroy(); } catch { /* ignore */ } resolve({ reachable: false, note: 'timeout on the fallback echo port' }); }, ms);
    sock.on('connect', () => { clearTimeout(t); try { sock.destroy(); } catch { /* ignore */ } resolve({ reachable: true, note: 'TCP echo port 7 reachable (ICMP itself needs elevated privileges)' }); });
    sock.on('error', (e) => { clearTimeout(t); resolve({ reachable: false, note: `fallback echo probe failed: ${e.code || e.message}; ICMP requires root/CAP_NET_RAW` }); });
  });
}

let entries = o._.length ? o._ : ['-'];
let domains = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) domains.push(...(await inputLines(e)));
  else domains.push(e);
}
domains = [...new Set(domains.filter(Boolean).map((d) => d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim()))];
if (!domains.length) die('no domain given');

const results = [];
for (const domain of domains) {
  const rec = { domain, resolver: resolver || dns.getServers()[0] || 'system', tests: {}, findings: [] };

  // 1. wildcard check
  const wildcardLabel = randLabel(20);
  const wild = await resolveRand(`${wildcardLabel}.${domain}`);
  const wildcard2 = await resolveRand(`${randLabel(20)}.${domain}`);
  rec.tests.wildcard = {
    first: wild.status, second: wildcard2.status,
    wildcard_present: wild.status === 'ANSWER' || wildcard2.status === 'ANSWER',
    answers: wild.answers,
  };
  if (rec.tests.wildcard.wildcard_present) {
    rec.findings.push({ id: 'wildcard-dns', severity: 'INFO', detail: `*.${domain} resolves to ${wild.answers.join(',') || 'an address'} — tunnel reads need an out-of-band marker to distinguish real answers`, impact: 'wildcard responses mask tunnel data; use unique TXT/NULL records or a canary' });
  }

  // 2. arbitrary subdomain forwarding
  const labels = Array.from({ length: Math.min(12, queries) }, () => `${randLabel(12)}.${domain}`);
  const fwd = await runPool(labels, (n) => resolveRand(n), conc);
  const answered = fwd.filter((f) => f.status === 'ANSWER').length;
  const errors = fwd.reduce((acc, f) => { acc[f.status] = (acc[f.status] || 0) + 1; return acc; }, {});
  rec.tests.forwarding = { probed: fwd.length, answered, error_codes: errors, forwarded: answered > 0 };
  if (answered === 0) {
    rec.findings.push({ id: 'no-arbitrary-forwarding', severity: 'INFO', detail: `none of ${fwd.length} random subdomains of ${domain} returned an A record (${JSON.stringify(errors)})`, impact: 'DNS tunnel requires the authoritative server to answer arbitrary names; without that, only a real tunnel endpoint can carry data' });
  } else {
    rec.findings.push({ id: 'arbitrary-forwarding-possible', severity: 'MEDIUM', detail: `${answered}/${fwd.length} random subdomains resolved — the resolver forwards arbitrary names downward`, impact: 'a tunnel client can encode data in subdomain labels and receive answers through the resolver' });
  }

  // 3. label capacity
  const capacity = [];
  for (const len of [32, 48, 63, 64, 100, 150, 200, 253]) {
    const label = randLabel(Math.min(len, 253));
    const r = await resolveRand(`${label}.${domain}`);
    const accepted = r.status === 'ANSWER' || /NODATA|ENOTFOUND|ENOTIMP/.test(r.status);
    const rejected = /EBADNAME|EFORMERR|EBADRESP|EINVAL/.test(r.status) || (label.length > 63 && r.status !== 'ANSWER');
    capacity.push({ label_len: label.length, fqdn_len: label.length + 1 + domain.length, status: r.status, accepted: accepted && !rejected });
  }
  const maxLabel = capacity.filter((c) => c.accepted).reduce((m, c) => Math.max(m, c.label_len), 0);
  rec.tests.capacity = { probes: capacity, max_label_bytes: maxLabel };
  if (maxLabel >= 63) rec.findings.push({ id: 'full-label-capacity', severity: 'MEDIUM', detail: `labels up to ${maxLabel} bytes are accepted — full 63-byte DNS labels can carry payload`, impact: 'encodes 63 bytes raw, ~39 base64 or ~50 base32 characters per query' });

  // 4. recursion test — the resolver should answer for a zone it is not authoritative for
  const outside = await resolveRand(`covertunnel-${randLabel(8)}.wikipedia.org`);
  rec.tests.recursion = { status: outside.status, answered: outside.status === 'ANSWER', answers: outside.answers.slice(0, 3) };
  if (outside.status === 'ANSWER' || outside.status === 'ENOTFOUND' || outside.status === 'ENODATA') {
    rec.findings.push({ id: 'open-recursion', severity: 'INFO', detail: `resolver performs recursion for external zones (status ${outside.status})`, impact: 'recursion is required for a DNS tunnel to reach an external authoritative server' });
  }

  // 5. throughput
  const burst = Array.from({ length: queries }, () => `${randLabel(10)}.${domain}`);
  const t0 = Date.now();
  const burstRes = await runPool(burst, (n) => resolveRand(n), conc);
  const elapsed = Date.now() - t0;
  const qps = +(burstRes.length / Math.max(0.001, elapsed / 1000)).toFixed(1);
  const latencies = burstRes.map((b) => b.ms).sort((a, b) => a - b);
  const p50 = latencies[Math.floor(latencies.length / 2)] || 0;
  const p95 = latencies[Math.floor(latencies.length * 0.95)] || latencies[latencies.length - 1] || 0;
  rec.tests.throughput = { queries: burstRes.length, elapsed_ms: elapsed, qps, p50_ms: p50, p95_ms: p95, answered: burstRes.filter((b) => b.status === 'ANSWER').length };
  const bytesPerQuery = { raw: maxLabel, base32: Math.floor(maxLabel * 5 / 8), base64: Math.floor(maxLabel * 3 / 4), hex: Math.floor(maxLabel / 2) };
  rec.tests.encoding_budget = { per_query: bytesPerQuery, theoretical_bps: +(qps * bytesPerQuery.base32).toFixed(1), theoretical_kbps: +((qps * bytesPerQuery.base32 * 8) / 1000).toFixed(2) };
  rec.findings.push({ id: 'throughput-estimate', severity: 'INFO', detail: `${qps} qps with p50 ${p50}ms; at ${bytesPerQuery.base32} bytes/query the ceiling is ~${rec.tests.encoding_budget.theoretical_kbps} kbit/s down-path`, impact: 'DNS tunnels are viable for command-and-control but poor for bulk transfer' });

  // 6. optional ICMP
  if (flag(o, 'icmp') && o.f.sink) {
    rec.tests.icmp = await icmpProbe(String(o.f.sink), timeout);
    if (rec.tests.icmp.reachable) rec.findings.push({ id: 'icmp-path', severity: 'INFO', detail: rec.tests.icmp.note, impact: 'an ICMP echo path exists, which can carry payloads when DNS is filtered' });
  }

  results.push(rec);
}

if (flag(o, 'json')) {
  console.log(JSON.stringify({ generated: new Date().toISOString(), results }, null, 2));
  exitSoon(0);
}

for (const r of results) {
  console.log(`\n### ${r.domain}  (resolver ${r.resolver})`);
  console.log(table([
    { metric: 'wildcard', value: r.tests.wildcard.wildcard_present ? 'PRESENT' : 'none', note: `probes: ${r.tests.wildcard.first}, ${r.tests.wildcard.second}` },
    { metric: 'arbitrary forwarding', value: `${r.tests.forwarding.answered}/${r.tests.forwarding.probed}`, note: JSON.stringify(r.tests.forwarding.error_codes) },
    { metric: 'max label bytes', value: r.tests.capacity.max_label_bytes, note: `accepted at 63: ${r.tests.capacity.max_label_bytes >= 63 ? 'yes' : 'no'}` },
    { metric: 'recursion', value: r.tests.recursion.answered ? 'answers external zones' : r.tests.recursion.status, note: '' },
    { metric: 'throughput', value: `${r.tests.throughput.qps} qps`, note: `p50 ${r.tests.throughput.p50_ms}ms, p95 ${r.tests.throughput.p95_ms}ms` },
    { metric: 'capacity/query', value: `${r.tests.encoding_budget.per_query.base32} B (base32)`, note: `~${r.tests.encoding_budget.theoretical_kbps} kbit/s ceiling` },
  ]));
  console.log('\nencoding budget per query:');
  console.log(table(Object.entries(r.tests.encoding_budget.per_query).map(([enc, bytes]) => ({ encoding: enc, bytes_per_query: bytes }))));
  console.log('\nlabel capacity probes:');
  console.log(table(r.tests.capacity.probes.map((c) => ({ label_len: c.label_len, fqdn_len: c.fqdn_len, status: c.status, accepted: c.accepted ? 'yes' : 'no' }))));
  console.log('\nfindings:');
  for (const f of r.findings) console.log(`  [${f.severity}] ${f.id}: ${f.detail}\n      -> ${f.impact}`);
}
exitSoon(0);
