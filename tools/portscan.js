// portscan.js — Fast async TCP connect scanner with banner grabbing.
// Copyright (c) 2026 0xnothings
// @tool portscan
// @desc Async TCP connect port scanner with service banner grab and JSON/CSV output
// @usage node tools/portscan.js 10.0.0.1 --ports 1-1024 --timeout 800 --banner
// @tags security,recon,network
import net from 'node:net';
import { args, get, num, flag, die, lines, inputLines, table, nowISO } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`portscan — async TCP connect scanner

  node tools/portscan.js <host|hosts.txt|-> [options]

  --ports <spec>    ports: 80,443,8000-8100  (default: common 24)
  --timeout <ms>    connect timeout             (default: 800)
  --concurrency <n> parallel sockets            (default: 500)
  --banner          read up to 256 bytes after connect
  --json            machine-readable output
  --open-only       only print open ports (default true unless --all)
  --all             also print closed/filtered
  -h, --help        this text`);
  process.exit(0);
}

const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017];

function parsePorts(spec) {
  if (!spec) return DEFAULT_PORTS;
  const out = new Set();
  for (const part of String(spec).split(',')) {
    const p = part.trim(); if (!p) continue;
    const m = p.match(/^(\d+)\s*-\s*(\d+)$/);
    if (m) { const [a, b] = [Math.min(+m[1], +m[2]), Math.max(+m[1], +m[2])]; for (let i = a; i <= b; i++) out.add(i); }
    else if (/^\d+$/.test(p)) out.add(+p);
  }
  return [...out].filter((p) => p > 0 && p < 65536).sort((a, b) => a - b);
}

function probe(host, port, timeout, wantBanner) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const sock = new net.Socket();
    let done = false;
    const finish = (status, banner) => {
      if (done) return; done = true;
      sock.destroy();
      resolve({ host, port, status, ms: Date.now() - t0, banner: banner || '' });
    };
    sock.setTimeout(timeout);
    sock.once('connect', () => {
      if (!wantBanner) return finish('open');
      let buf = '';
      sock.on('data', (d) => { buf += d.toString('utf8'); if (buf.length > 256) sock.destroy(); });
      sock.once('close', () => finish('open', buf.replace(/[\r\n\t]+/g, ' ').slice(0, 200)));
      setTimeout(() => finish('open', buf.replace(/[\r\n\t]+/g, ' ').slice(0, 200)), Math.min(timeout, 700));
    });
    sock.once('timeout', () => finish('filtered'));
    sock.once('error', (e) => finish(e.code === 'ECONNREFUSED' ? 'closed' : 'filtered'));
    sock.connect(port, host);
  });
}

const targets = (o._.length ? o._ : ['-']);
let hosts = [];
for (const t of targets) {
  if (t === '-' ) hosts.push(...(await inputLines('-')).map((h) => h.split(/\s+/)[0]));
  else if (/\.txt$/.test(t) || /\.lst$/.test(t)) hosts.push(...(await inputLines(t)).map((h) => h.split(/\s+/)[0]));
  else hosts.push(t);
}
hosts = [...new Set(hosts.filter(Boolean))];
if (!hosts.length) die('no hosts given (pass a host, a file of hosts, or pipe via stdin)');

const ports = parsePorts(get(o, 'ports'));
const timeout = num(get(o, 'timeout'), 800);
const conc = num(get(o, 'concurrency'), 500);
const banner = flag(o, 'banner');

const jobs = [];
for (const h of hosts) for (const p of ports) jobs.push([h, p]);
const results = [];
let idx = 0;
await Promise.all(Array.from({ length: Math.min(conc, jobs.length) }, async () => {
  while (idx < jobs.length) {
    const [h, p] = jobs[idx++];
    const r = await probe(h, p, timeout, banner);
    if (r.status === 'open' || flag(o, 'all')) results.push(r);
    if (!flag(o, 'json') && r.status === 'open') process.stdout.write(`open   ${r.host}:${r.port}  (${r.ms}ms)${r.banner ? '  ' + r.banner : ''}\n`);
  }
}));

if (flag(o, 'json')) {
  console.log(JSON.stringify({ scanned_at: nowISO(), hosts: hosts.length, ports: ports.length, results }, null, 2));
} else {
  console.log(`\n${results.filter((r) => r.status === 'open').length} open / ${jobs.length} probed`);
}
