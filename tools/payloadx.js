// payloadx.js — payload encoder/decoder toolkit.
// Copyright (c) 2026 0xnothings
// @tool payloadx
// @desc Encode/decode payloads for filters: url, double-url, base64, hex, unicode, html-entity, sql-comment, leet
// @usage node tools/payloadx.js encode --in "<script>alert(1)</script>" --via url,unicode --json
// @tags security,payload,encoding
import { args, get, num, flag, die, inputLines } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`payloadx — payload encoder/decoder

  node tools/payloadx.js <encode|decode|list> [options]

  --in <string>     input value (or read stdin)
  --via <list>      url,url2,base64,base64url,hex,unicode,html,htmldec,sqlcomment,leet,reverse,rot13,jsescape,cstr
  --json            machine-readable output
  -h, --help        this text

  examples:
    node tools/payloadx.js encode --in "' OR 1=1--" --via url,hex
    node tools/payloadx.js decode --in "%3Cscript%3E" --via url`);
  process.exit(0);
}

const CODE = {
  url: (s) => encodeURIComponent(s),
  url2: (s) => encodeURIComponent(encodeURIComponent(s)),
  base64: (s) => Buffer.from(s).toString('base64'),
  base64url: (s) => Buffer.from(s).toString('base64url'),
  hex: (s) => [...Buffer.from(s)].map((b) => b.toString(16).padStart(2, '0')).join(''),
  hexpref: (s) => [...Buffer.from(s)].map((b) => '\\x' + b.toString(16).padStart(2, '0')).join(''),
  unicode: (s) => [...s].map((c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
  html: (s) => [...s].map((c) => `&#${c.charCodeAt(0)};`).join(''),
  htmlhex: (s) => [...s].map((c) => `&#x${c.charCodeAt(0).toString(16)};`).join(''),
  jsescape: (s) => [...s].map((c) => (/[a-zA-Z0-9]/.test(c) ? c : '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))).join(''),
  cstr: (s) => '"' + [...s].map((c) => (c === '"' ? '\\"' : /[\\\x00-\x1f]/.test(c) ? '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0') : c)).join('') + '"',
  sqlcomment: (s) => s.replace(/\s+/g, '/**/'),
  leet: (s) => s.replace(/a/gi, '4').replace(/e/gi, '3').replace(/i/gi, '1').replace(/o/gi, '0').replace(/s/gi, '5').replace(/t/gi, '7'),
  reverse: (s) => [...s].reverse().join(''),
  rot13: (s) => s.replace(/[a-zA-Z]/g, (c) => String.fromCharCode((c <= 'Z' ? 90 : 122) >= c.charCodeAt(0) + 13 ? c.charCodeAt(0) + 13 : c.charCodeAt(0) - 13)),
};
const DECODE = {
  url: (s) => decodeURIComponent(s),
  url2: (s) => decodeURIComponent(decodeURIComponent(s)),
  base64: (s) => Buffer.from(s, 'base64').toString('utf8'),
  base64url: (s) => Buffer.from(s, 'base64url').toString('utf8'),
  hex: (s) => Buffer.from(s.replace(/\\x|0x/gi, ''), 'hex').toString('utf8'),
  hexpref: (s) => Buffer.from(s.replace(/\\x|0x/gi, ''), 'hex').toString('utf8'),
  unicode: (s) => s.replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))),
  html: (s) => s.replace(/&#x?[0-9a-f]+;/gi, (m) => String.fromCharCode(parseInt(m.replace(/&#x?/i, '').replace(';', ''), /x/i.test(m) ? 16 : 10))),
  cstr: (s) => s.replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/\\(.)/g, '$1'),
  rot13: (s) => CODE.rot13(s),
  reverse: (s) => [...s].reverse().join(''),
};

const mode = o._[0] || 'list';
if (mode === 'list' || (!o.f.in && !o.f.via && mode !== 'list')) {
  console.log('encoders:  ' + Object.keys(CODE).join(', '));
  console.log('decoders:  ' + Object.keys(DECODE).join(', '));
  process.exit(0);
}

const input = o.f.in !== undefined ? String(get(o, 'in')) : (await inputLines('-')).join('\n');
const via = String(get(o, 'via', mode === 'encode' ? 'url' : 'url')).split(',').map((s) => s.trim()).filter(Boolean);
const table = mode === 'encode' ? CODE : DECODE;
const out = {};
for (const v of via) {
  if (!table[v]) { out[v] = 'ERROR: unknown codec'; continue; }
  try { out[v] = table[v](input); } catch (e) { out[v] = 'ERROR: ' + e.message; }
}

if (flag(o, 'json')) console.log(JSON.stringify({ mode, input, results: out }, null, 2));
else {
  for (const [k, v] of Object.entries(out)) console.log(`${k.padEnd(11)} ${v}`);
  if (mode === 'encode') {
    const combo = via.map((v) => CODE[v]?.(input) ?? input).join('');
    console.log(`${'chained'.padEnd(11)} ${combo}`);
  }
}
