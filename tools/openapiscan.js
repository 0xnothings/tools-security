#!/usr/bin/env node
// openapiscan.js — OpenAPI/Swagger spec security review.
// Copyright (c) 2026 0xnothings
// @tool openapiscan
// @desc Fetch an OpenAPI spec and report auth coverage, sensitive endpoints, and unauthenticated operations
// @usage node tools/openapiscan.js https://api.example.com/openapi.json --json
// @tags security,api,openapi
import { args, get, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`openapiscan — OpenAPI spec audit

  node tools/openapiscan.js <spec-url|file.json|-> [options]

  --json       machine-readable output
  --verbose    list every operation
  -h, --help   this text`);
  process.exit(0);
}

const SENSITIVE = /(admin|internal|debug|user|account|auth|token|key|secret|payment|billing|transfer|delete|remove|export|dump|config|role|permission|impersonat|webhook)/i;
const MUTATING = /^(post|put|patch|delete)$/i;

async function load(src) {
  if (/^https?:\/\//.test(src)) {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 20000);
    try {
      const res = await fetch(src, { signal: ctl.signal, headers: { accept: 'application/json, application/yaml, text/yaml' } });
      const text = await res.text();
      try { return JSON.parse(text); } catch { return { error: 'spec is not JSON (YAML specs: convert first with `npx yaml2json`)' }; }
    } catch (e) { return { error: String(e.cause?.code || e.message) }; }
    finally { clearTimeout(t); }
  }
  try { return JSON.parse(await inputLines(src).then((l) => l.join('\n')).catch(() => '')); } catch {}
  try { const { readFileSync } = await import('node:fs'); return JSON.parse(readFileSync(src, 'utf8')); } catch (e) { return { error: String(e.message) }; }
}

const src = o._[0] || '-';
const spec = await load(src);
if (spec.error) die(spec.error);
const paths = spec.paths || {};
const globalSecurity = (spec.security || []).length > 0;
const schemes = Object.keys(spec.components?.securitySchemes || spec.securityDefinitions || {});

const ops = [];
for (const [p, methods] of Object.entries(paths)) {
  for (const [m, op] of Object.entries(methods)) {
    if (!['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(m.toLowerCase())) continue;
    const sec = op.security !== undefined ? op.security : spec.security;
    const hasSec = Array.isArray(sec) && sec.length > 0;
    const params = (op.parameters || []).map((x) => `${x.name}(${x.in})`);
    ops.push({
      method: m.toUpperCase(), path: p, secured: hasSec, schemes: hasSec ? sec.flatMap((s) => Object.keys(s)) : [],
      sensitive: SENSITIVE.test(p) || SENSITIVE.test(op.operationId || ''), mutating: MUTATING.test(m),
      summary: (op.summary || op.operationId || '').slice(0, 60), params,
      deprecated: !!op.deprecated,
    });
  }
}

const unauthSensitive = ops.filter((o) => !o.secured && o.sensitive);
const unauthMutating = ops.filter((o) => !o.secured && o.mutating);
const uniq = (arr) => [...new Set(arr)];

const report = {
  source: src, spec_version: spec.openapi || spec.swagger || '?', title: spec.info?.title || '-',
  global_security: globalSecurity, schemes, total_ops: ops.length,
  unauth_ops: ops.filter((o) => !o.secured).length,
  unauth_sensitive: unauthSensitive.length, unauth_mutating: unauthMutating.length,
  operations: flag(o, 'verbose') ? ops : ops.filter((x) => !x.secured || x.sensitive),
  findings: [
    ...unauthSensitive.map((o) => ({ severity: 'HIGH', issue: `sensitive operation without auth: ${o.method} ${o.path}` })),
    ...unauthMutating.filter((x) => !unauthSensitive.includes(x)).map((o) => ({ severity: 'MEDIUM', issue: `mutating operation without auth: ${o.method} ${o.path}` })),
    ...(schemes.length === 0 ? [{ severity: 'HIGH', issue: 'no securitySchemes defined in the spec' }] : []),
    ...(spec.servers || []).filter((s) => /^http:\/\//.test(s.url)).map((s) => ({ severity: 'MEDIUM', issue: `plaintext server url: ${s.url}` })),
  ],
};

if (flag(o, 'json')) {
  // keep the HTTP-only bearer tokens out of our own schema report — nothing to redact beyond paths
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}
console.log(`\n${report.title}  (${report.spec_version})  from ${src}`);
console.log(`${report.total_ops} operations | ${report.unauth_ops} unauthenticated | ${report.unauth_sensitive} sensitive+unauth | ${report.unauth_mutating} mutating+unauth`);
console.log(`global security: ${report.global_security}   schemes: ${schemes.join(', ') || 'NONE'}`);
if (report.findings.length) console.log(table(report.findings));
if (unauthSensitive.length) {
  console.log('\nsensitive endpoints reachable without auth:');
  uniq(unauthSensitive.map((o) => `${o.method} ${o.path}`)).slice(0, 40).forEach((x) => console.log('  ' + x));
}
