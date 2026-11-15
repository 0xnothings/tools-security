// xssprobe.js — reflection-based XSS candidate finder.
// Copyright (c) 2026 0xnothings
// @tool xssprobe
// @desc Send a canary into parameters/headers and report reflected contexts that can break out
// @usage node tools/xssprobe.js "https://site.com/?q=1" --json
// @tags security,web,xss
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`xssprobe — reflection XSS candidate finder

  node tools/xssprobe.js <url|urls.txt|-> [options]

  --marker <s>      canary (default: 0xn0th1ngs)
  --headers         also test Referer/User-Agent/Origin reflections
  --timeout <ms>    request timeout (default: 9000)
  --json            machine-readable output
  -h, --help        this text`);
  process.exit(0);
}

const MARKER = String(get(o, 'marker', '0xn0th1ngs'));
const PAYLOAD = `${MARKER}"'><img/src=x>`;
const timeout = num(get(o, 'timeout'), 9000);

function contextOf(body, needle) {
  const i = body.indexOf(needle);
  if (i < 0) return null;
  const before = body.slice(Math.max(0, i - 120), i);
  let ctx = 'html-text';
  if (/<script[^>]*>[^<]*$/i.test(before)) ctx = 'js-string/block';
  else if (/<style[^>]*>[^<]*$/i.test(before)) ctx = 'css';
  else if (/=[^>]*$/.test(before) && /<[a-z][^>]*$/i.test(before)) ctx = 'html-attribute';
  else if (/<!--/.test(before)) ctx = 'html-comment';
  return { ctx, before: before.slice(-80) };
}

async function probe(url, headers = {}, label = '') {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { 'user-agent': '0xnothings-xss/1.0', ...headers } });
    const body = await res.text().catch(() => '');
    const c = contextOf(body, MARKER);
    return { status: res.status, reflected: !!c, ctx: c?.ctx, before: c?.before, label };
  } catch (e) { return { error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) urls.push(...(await inputLines(e))); else urls.push(e);
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u)))];
if (!urls.length) die('no url given');

const findings = [];
for (const raw of urls) {
  const u = new URL(raw);
  const params = [...u.searchParams.keys()];
  if (!params.length) { console.error(`[skip] no query params: ${raw}`); continue; }
  for (const p of params) {
    const t = new URL(raw); t.searchParams.set(p, PAYLOAD);
    const r = await probe(t.toString());
    if (!r.error && r.reflected) findings.push({ url: raw, vector: `query:${p}`, ctx: r.ctx, evidence: r.before });
  }
  if (flag(o, 'headers')) {
    for (const h of ['referer', 'user-agent', 'origin', 'x-forwarded-host']) {
      const r = await probe(raw, { [h]: PAYLOAD });
      if (!r.error && r.reflected) findings.push({ url: raw, vector: `header:${h}`, ctx: r.ctx, evidence: r.before });
    }
  }
}

if (flag(o, 'json')) console.log(JSON.stringify(findings, null, 2));
else {
  console.log(table(findings.map((f) => ({ vector: f.vector, ctx: f.ctx || '-', url: f.url, evidence: (f.evidence || '').slice(-60) }))));
  console.log(`\n${findings.length} reflected injection point(s) — verify break-out manually`);
}
