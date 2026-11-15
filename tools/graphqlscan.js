#!/usr/bin/env node
// graphqlscan.js — GraphQL endpoint introspection and exposure check.
// Copyright (c) 2026 0xnothings
// @tool graphqlscan
// @desc Detect live GraphQL endpoints, test introspection exposure, and list queries/mutations/subscriptions
// @usage node tools/graphqlscan.js https://api.example.com/graphql --json
// @tags security,api,graphql
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`graphqlscan — GraphQL endpoint reconnaissance

  node tools/graphqlscan.js <url|urls.txt|-> [options]

  --paths <list>   candidate paths to try on each host (default: common 12)
  --timeout <ms>   request timeout (default: 12000)
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

const PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql', '/query', '/api/query', '/gql', '/index.php?graphql', '/graphiql', '/api', '/graphql/v1', '/altair'];
const INTROSPECT = { query: `query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name args { name } } } } }` };

async function post(url, body, timeout) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, { method: 'POST', signal: ctl.signal, headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': '0xnothings-gql/1.0' }, body: JSON.stringify(body) });
    const text = await res.text().catch(() => '');
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: res.status, ct: res.headers.get('content-type') || '', len: text.length, json, text: text.slice(0, 300) };
  } catch (e) { return { error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) }; }
  finally { clearTimeout(t); }
}

function summarize(r) {
  const s = r.json?.data?.__schema;
  if (!s) return null;
  const types = (s.types || []).filter((t) => !t.name.startsWith('__') && t.fields);
  const byRoot = (name) => types.find((t) => t.name === name)?.fields?.map((f) => f.name) || [];
  return {
    query_type: s.queryType?.name || '-', mutation_type: s.mutationType?.name || null, subscription_type: s.subscriptionType?.name || null,
    custom_types: types.length, queries: byRoot(s.queryType?.name), mutations: byRoot(s.mutationType?.name), subscriptions: byRoot(s.subscriptionType?.name),
  };
}

let entries = o._.length ? o._ : ['-'];
let bases = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) bases.push(...(await inputLines(e))); else bases.push(e);
bases = [...new Set(bases.map((b) => (/^https?:\/\//.test(b) ? b : 'https://' + b)))];
if (!bases.length) die('no url given');
const timeout = num(get(o, 'timeout'), 12000);
const paths = String(get(o, 'paths', PATHS.join(','))).split(',').map((s) => s.trim()).filter(Boolean);

const results = [];
for (const base of bases) {
  const isDirect = !/^https?:\/\/[^/]+$/.test(base);
  const candidates = isDirect ? [base] : paths.map((p) => base.replace(/\/+$/, '') + p);
  for (const url of candidates) {
    const ping = await post(url, { query: '{__typename}' }, timeout);
    if (ping.error || ping.status >= 500) continue;
    const looksGql = ping.status === 200 && (ping.json?.data?.__typename || ping.json?.errors);
    if (!looksGql) continue;
    const intro = await post(url, INTROSPECT, timeout);
    const schema = summarize(intro);
    const entry = { url, endpoint_alive: true, introspection: !!schema, schema, sample_error: ping.json?.errors?.[0]?.message || null };
    results.push(entry);
    if (!flag(o, 'json')) {
      console.log(`\n=== ${url}  [ENDPOINT LIVE]`);
      if (!schema) { console.log('  introspection blocked (good)'); if (entry.sample_error) console.log(`  hint: ${entry.sample_error}`); continue; }
      console.log('  [!!] INTROSPECTION ENABLED');
      console.log(`  queries (${schema.queries.length}): ${schema.queries.slice(0, 25).join(', ')}`);
      console.log(`  mutations (${schema.mutations.length}): ${schema.mutations.slice(0, 25).join(', ')}`);
      console.log(`  subscriptions (${schema.subscriptions.length}): ${schema.subscriptions.slice(0, 10).join(', ') || '-'}`);
    }
  }
}
if (flag(o, 'json')) console.log(JSON.stringify(results, null, 2));
else console.log(`\n${results.length} live GraphQL endpoint(s), ${results.filter((r) => r.introspection).length} exposing introspection`);
