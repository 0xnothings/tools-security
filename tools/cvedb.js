// cvedb.js — CVE intelligence lookup with NVD + CISA KEV + EPSS.
// Copyright (c) 2026 0xnothings
// @tool cvedb
// @desc Fetch CVE detail from NVD, exploit status from CISA KEV, and exploitation likelihood from EPSS
// @usage node tools/cvedb.js CVE-2024-3400 CVE-2023-34362 --json
// @tags security,cve,intel
import { args, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`cvedb — CVE intelligence aggregator

  node tools/cvedb.js <CVE-YYYY-NNNN ...|cves.txt|-> [options]

  --no-kev    skip the CISA KEV feed
  --no-epss   skip EPSS scoring
  --json      machine-readable output
  -h, --help  this text`);
  process.exit(0);
}

async function j(url, timeout = 30000) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { 'user-agent': '0xnothings-cvedb/1.0', accept: 'application/json' } });
    if (!res.ok) return { error: `HTTP ${res.status}` };
    return await res.json();
  } catch (e) { return { error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

let ids = [];
if (o._.length) for (const a of o._) if (/-$|\.txt$/.test(a)) ids.push(...(await inputLines(a))); else ids.push(a);
else ids = await inputLines('-');
ids = [...new Set(ids.map((s) => s.trim().toUpperCase()).filter((s) => /^CVE-\d{4}-\d{4,}$/.test(s)))];
if (!ids.length) die('no valid CVE IDs given');

let kev = null;
if (!flag(o, 'no-kev')) {
  const k = await j('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 45000);
  if (!k.error) kev = new Map((k.vulnerabilities || []).map((v) => [v.cveID, v]));
}

async function epss(id) {
  const r = await j(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(id)}`, 15000);
  const d = r?.data?.[0];
  return d ? { score: Number(d.epss), percentile: Number(d.percentile) } : null;
}

async function nvd(id) {
  const r = await j(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`, 40000);
  if (r.error || !r.vulnerabilities?.[0]) return { error: r.error || 'not in NVD' };
  const c = r.vulnerabilities[0].cve;
  const desc = (c.descriptions || []).find((d) => d.lang === 'en')?.value || '';
  const m = c.metrics || {};
  const cvss = (m.cvssMetricV31?.[0] || m.cvssMetricV30?.[0] || m.cvssMetricV2?.[0])?.cvssData;
  const cwe = (c.weaknesses || []).flatMap((w) => (w.description || []).map((d) => d.value)).filter((v) => v.startsWith('CWE'));
  return {
    id, description: desc, published: c.published, modified: c.lastModified,
    score: cvss?.baseScore ?? null, severity: cvss?.baseSeverity ?? (m.cvssMetricV2?.[0]?.baseSeverity ?? '?'),
    vector: cvss?.vectorString || '', cwe: [...new Set(cwe)].join(', ') || '-',
    cpeCount: (c.configurations || []).flatMap((cfg) => cfg.nodes || []).flatMap((n) => n.cpeMatch || []).length,
    references: (c.references || []).slice(0, 5).map((r) => r.url),
  };
}

const results = [];
for (const id of ids) {
  const [base, e] = await Promise.all([nvd(id), flag(o, 'no-epss') ? null : epss(id)]);
  const entry = { ...base, id, epss: e, kev: kev?.has(id) ? { dateAdded: kev.get(id).dateAdded, ransomware: kev.get(id).knownRansomwareCampaignUse, action: kev.get(id).requiredAction } : null, epss_meta: null };
  if (e) entry.epss_meta = e.score > 0.5 ? 'very likely exploited in the wild' : e.score > 0.1 ? 'elevated' : e.score > 0.01 ? 'low' : 'very low';
  results.push(entry);
}

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); process.exit(0); }
for (const r of results) {
  console.log(`\n######## ${r.id}`);
  if (r.error) { console.log('  ' + r.error); }
  else {
    console.log(`  CVSS ${r.score} (${r.severity})   ${r.vector}`);
    console.log(`  CWE  ${r.cwe}   CPE entries ${r.cpeCount}   published ${(r.published || '').slice(0, 10)}`);
    console.log(`  ${r.description.slice(0, 400)}`);
  }
  if (r.kev) console.log(`  [!!] CISA KEV — exploited in the wild (added ${r.kev.dateAdded}, ransomware=${r.kev.ransomware})`);
  if (r.epss) console.log(`  EPSS ${(r.epss.score * 100).toFixed(2)}% (p${Math.round(r.epss.percentile * 100)}) — ${r.epss_meta}`);
  if (r.references?.length) console.log('  refs: ' + r.references.slice(0, 3).join('  '));
}
const kevCount = results.filter((r) => r.kev).length;
console.log(`\n${results.length} CVE(s) | ${kevCount} in CISA KEV`);
