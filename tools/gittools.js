#!/usr/bin/env node
// gittools.js — detect and reconstruct exposed .git directories.
// Copyright (c) 2026 0xnothings
// @tool gittools
// @desc Detect an exposed .git directory and reconstruct source from loose objects, pack files and refs
// @usage node tools/gittools.js https://target/.git/ --json
// @tags security,web,source-disclosure
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`gittools — exposed .git detector and source reconstructor

  node tools/gittools.js <https://target/.git/ | domain | list.txt | -> [options]

  --timeout <ms>    per-request timeout (default: 10000)
  --max-objects <n> cap on objects fetched during reconstruction (default: 400)
  --depth <n>       how deep to walk trees (default: 3)
  --dump <dir>      write reconstructed files into this directory
  --no-reconstruct  only probe for exposure, skip object fetching
  --json            machine-readable output
  -h, --help        this text

  Exposure probes: HEAD, config, index, packed-refs, logs/HEAD, refs/heads/*,
  info/refs, objects/info/packs, plus a pack-file probe. Reconstruction:
  reads loose objects (zlib inflate + git header parse) and pack files
  (delta-free object extraction), then lists/restores reachable files.`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };
const timeout = num(get(o, 'timeout'), 10000);
const maxObjects = num(get(o, 'max-objects'), 400);
const depth = num(get(o, 'depth'), 3);
const { writeFileSync, mkdirSync } = await import('node:fs');
const { join } = await import('node:path');

async function getBytes(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(url, { headers: { 'user-agent': 'gittools/1.0' }, signal: ctl.signal, redirect: 'follow' });
    if (!r.ok) return { status: r.status, bytes: null, len: 0, error: `HTTP ${r.status}` };
    const buf = Buffer.from(await r.arrayBuffer());
    return { status: r.status, bytes: buf, len: buf.length, error: null, text: buf.toString('utf8').slice(0, 4000) };
  } catch (e) {
    return { status: 0, bytes: null, len: 0, error: e.name === 'AbortError' ? 'timeout' : (e.message || 'failed') };
  } finally { clearTimeout(t); }
}

// ---------- git object parsing ----------
function parseLoose(buf) {
  let inflated;
  try { inflated = zlib.inflateSync(buf); } catch { return null; }
  const nul = inflated.indexOf(0);
  if (nul < 0) return null;
  const header = inflated.slice(0, nul).toString('utf8');
  const [type, sizeStr] = header.split(' ');
  const body = inflated.slice(nul + 1);
  return { type, size: Number(sizeStr), body };
}

const sha1 = (buf) => crypto.createHash('sha1').update(buf).digest('hex');
const toPath = (sha) => `${sha.slice(0, 2)}/${sha.slice(2)}`;

function parseTree(body) {
  const entries = [];
  let i = 0;
  while (i < body.length) {
    const sp = body.indexOf(32, i);           // space before the filename
    if (sp < 0) break;
    const mode = body.slice(i, sp).toString('utf8');
    const nul = body.indexOf(0, sp);
    if (nul < 0) break;
    const fname = body.slice(sp + 1, nul).toString('utf8');
    const sha = body.slice(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name: fname, sha });
    i = nul + 21;
  }
  return entries;
}

function parseCommit(body) {
  const text = body.toString('utf8');
  const tree = (text.match(/^tree ([0-9a-f]{40})$/m) || [])[1] || null;
  const parent = (text.match(/^parent ([0-9a-f]{40})$/m) || [])[1] || null;
  const author = (text.match(/^author ([^<]*)<([^>]*)> (\d+)/m) || []);
  const msg = text.split(/\r?\n\r?\n/).slice(1).join('\n\n').split('\n')[0] || '';
  return { tree, parent, author_name: (author[1] || '').trim(), author_email: author[2] || '', author_time: author[3] ? new Date(Number(author[3]) * 1000).toISOString() : null, message: msg.slice(0, 120) };
}

function parsePack(buf) {
  if (buf.slice(0, 4).toString('latin1') !== 'PACK') return { objects: [], version: null };
  const version = buf.readUInt32BE(4);
  const count = buf.readUInt32BE(8);
  const objects = [];
  let i = 12;
  while (i < buf.length - 20 && objects.length < count) {
    const start = i;
    let byte = buf[i++];
    const typeNum = (byte >> 4) & 7;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) { byte = buf[i++]; size |= (byte & 0x7f) << shift; shift += 7; }
    const types = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag', 6: 'ofs-delta', 7: 'ref-delta' };
    const type = types[typeNum] || `type${typeNum}`;
    // Delta base reference (only OFS_DELTA carries an offset we can parse inline).
    let deltaBase = null;
    if (typeNum === 6) {
      let b = buf[i++];
      let off = b & 0x7f;
      while (b & 0x80) { b = buf[i++]; off = ((off + 1) << 7) | (b & 0x7f); }
      deltaBase = start - off;
    } else if (typeNum === 7) { deltaBase = buf.slice(i, i + 20).toString('hex'); i += 20; }

    let body = null;
    if (type === 'blob' || type === 'tree' || type === 'commit' || type === 'tag') {
      try {
        body = zlib.inflateSync(buf.slice(i), { finishFlush: zlib.constants.Z_SYNC_FLUSH });
      } catch { body = null; }
    }
    objects.push({ offset: start, type, size, delta_base: deltaBase, body, is_delta: type.includes('delta') });
    if (!body) break; // cannot know the compressed length reliably once a delta is hit
    i += zlib.deflateSync(body).length;
    // Fall back to a scan for the next object header if the deflate length round-trip is off.
    const guess = buf.indexOf(Buffer.from([0x78, 0x9c]), i);
    if (guess > i && guess - i < 8) i = guess;
  }
  return { objects, version, declared_count: count };
}

// ---------- probes ----------
const PROBES = [
  'HEAD', 'config', 'index', 'packed-refs', 'logs/HEAD', 'info/refs', 'description',
  'COMMIT_EDITMSG', 'objects/info/packs', 'refs/heads/master', 'refs/heads/main',
  'hooks/README.sample', 'info/exclude', 'ORIG_HEAD', 'FETCH_HEAD',
];

function baseOf(input) {
  let b = input.trim();
  if (!/^https?:\/\//.test(b)) b = `https://${b}`;
  b = b.replace(/\/+$/, '');
  // If the path already ends in .git keep it; otherwise treat a bare host as
  // host/.git and strip a deeper path (e.g. /app/index.php -> /app/.git).
  if (/\.git$/.test(b)) return b;
  const m = b.match(/^(https?:\/\/[^/]+)(\/.*)?$/);
  const origin = m ? m[1] : b;
  const pathPart = m && m[2] ? m[2].replace(/\/+$/, '') : '';
  if (!pathPart) return `${origin}/.git`;
  // Drop a filename if the last segment looks like a file.
  const segs = pathPart.split('/').filter(Boolean);
  if (segs.length && /\.[a-z0-9]{1,5}$/i.test(segs[segs.length - 1])) segs.pop();
  return `${origin}/${segs.join('/')}${segs.length ? '/' : ''}.git`;
}

let entries = o._.length ? o._ : ['-'];
let targets = [];
for (const e of entries) {
  if (e === '-' || /\.txt$/.test(e)) targets.push(...(await inputLines(e)));
  else targets.push(e);
}
targets = [...new Set(targets.filter(Boolean))];
if (!targets.length) die('no target given');

const results = [];
for (const target of targets) {
  const base = baseOf(target);
  const probes = [];
  for (const p of PROBES) {
    const r = await getBytes(`${base}/${p}`);
    const ok = r.status === 200 && r.len > 0;
    let valid = false;
    if (ok) {
      if (p === 'HEAD') valid = /^ref: refs\/|^[0-9a-f]{40}/.test(String(r.text || '').trim());
      else if (p === 'config') valid = /\[core\]|\[remote/.test(String(r.text || ''));
      else if (p === 'info/refs' || p.startsWith('refs/')) valid = /[0-9a-f]{40}\s+\S+|ref:/i.test(String(r.text || ''));
      else valid = true;
    }
    probes.push({ path: p, status: r.status, bytes: r.len, valid, preview: ok ? String(r.text || '').replace(/\n/g, ' ').slice(0, 90) : (r.error || '') });
    if (p === 'HEAD' && !valid && r.status === 200) {
      // A 200 with an HTML body is a soft-404 SPA fallback, not a .git directory.
      probes[probes.length - 1].valid = false;
      probes[probes.length - 1].preview = 'html or non-git body — likely soft-404';
    }
  }
  const confirmed = probes.filter((p) => p.valid);
  const rec = {
    target, base,
    exposed: confirmed.length > 0,
    confirmed_probes: confirmed.map((p) => p.path),
    probes,
    head_ref: null, head_sha: null,
    config: null, packed_refs: [], refs: {},
    commits: [], objects: { loose: 0, from_pack: 0, trees: 0, blobs: 0 },
    files: [], reconstructed: [],
    notes: [],
  };

  if (rec.exposed && !flag(o, 'no-reconstruct')) {
    const head = await getBytes(`${base}/HEAD`);
    const headText = String(head.text || '').trim();
    rec.head_ref = (headText.match(/^ref:\s*(\S+)/) || [])[1] || null;
    rec.head_sha = (headText.match(/^([0-9a-f]{40})/) || [])[1] || null;

    const cfg = await getBytes(`${base}/config`);
    if (cfg.status === 200) rec.config = String(cfg.text || '').slice(0, 1500);

    const packed = await getBytes(`${base}/packed-refs`);
    if (packed.status === 200) {
      for (const line of String(packed.text || '').split(/\r?\n/)) {
        const m = line.match(/^([0-9a-f]{40})\s+(\S+)/);
        if (m) rec.packed_refs.push({ sha: m[1], ref: m[2] });
      }
    }

    for (const ref of ['refs/heads/main', 'refs/heads/master', 'refs/heads/dev', rec.head_ref].filter(Boolean)) {
      if (rec.refs[ref]) continue;
      const r = await getBytes(`${base}/${ref}`);
      const sha = String(r.text || '').trim().match(/^[0-9a-f]{40}/);
      if (r.status === 200 && sha) rec.refs[ref] = sha[0];
    }

    // Fetch and parse the HEAD commit object.
    const blockNames = [...new Set([rec.head_sha, ...Object.values(rec.refs)].filter(Boolean))];
    const objectCache = new Map();
    async function fetchLoose(sha) {
      if (objectCache.has(sha)) return objectCache.get(sha);
      const r = await getBytes(`${base}/objects/${toPath(sha)}`);
      if (r.status !== 200 || !r.bytes) { objectCache.set(sha, null); return null; }
      const parsed = parseLoose(r.bytes);
      objectCache.set(sha, parsed);
      if (parsed) { rec.objects.loose++; if (parsed.type === 'tree') rec.objects.trees++; if (parsed.type === 'blob') rec.objects.blobs++; }
      return parsed;
    }

    // Pack files
    const packList = await getBytes(`${base}/objects/info/packs`);
    const packNames = [];
    if (packList.status === 200) {
      for (const m of String(packList.text || '').matchAll(/pack-([0-9a-f]{40})\.pack/g)) packNames.push(`pack-${m[1]}`);
    }
    for (const pn of packNames.slice(0, 3)) {
      const pk = await getBytes(`${base}/objects/pack/${pn}.pack`);
      if (pk.status !== 200 || !pk.bytes) continue;
      const parsedPack = parsePack(pk.bytes);
      rec.objects.from_pack += parsedPack.objects.length;
      rec.notes.push(`pack ${pn}: ${parsedPack.objects.length} object header(s) parsed of ${parsedPack.declared_count} declared (deltas are not resolved without a local index)`);
      for (const obj of parsedPack.objects) {
        if (!obj.body) continue;
        if (obj.type === 'blob') { rec.objects.blobs++; rec.files.push({ sha: sha1(Buffer.concat([Buffer.from(`blob ${obj.body.length}\0`), obj.body])), path: '(from pack, name unknown)', size: obj.body.length, type: 'blob' }); }
        if (obj.type === 'tree') { rec.objects.trees++; }
      }
    }

    // Walk commits -> trees -> blobs
    let fetched = 0;
    async function walk(sha, prefix, level) {
      if (fetched >= maxObjects || level > depth) return;
      const obj = await fetchLoose(sha);
      fetched++;
      if (!obj) return;
      if (obj.type === 'tree') {
        const ents = parseTree(obj.body);
        for (const e of ents) {
          if (fetched >= maxObjects) return;
          const path = prefix ? `${prefix}/${e.name}` : e.name;
          if (e.mode === '40000' || e.mode === '040000') { await walk(e.sha, path, level + 1); continue; }
          const child = await fetchLoose(e.sha);
          fetched++;
          if (child && child.type === 'blob') {
            rec.files.push({ sha: e.sha, path, size: child.size, type: 'blob', mode: e.mode });
            rec.reconstructed.push({ path, size: child.size, body: child.body });
          } else if (!child) {
            rec.files.push({ sha: e.sha, path, size: null, type: 'blob (unfetched)', mode: e.mode });
          }
        }
      }
    }

    for (const sha of blockNames) {
      const c = await fetchLoose(sha);
      if (c && c.type === 'commit') {
        const meta = parseCommit(c.body);
        rec.commits.push({ sha, ...meta });
        if (meta.tree) await walk(meta.tree, '', 0);
      } else if (c && c.type === 'tree') {
        await walk(sha, '', 0);
      }
    }

    if (rec.files.length && o.f.dump) {
      const outDir = String(o.f.dump);
      mkdirSync(outDir, { recursive: true });
      let wrote = 0;
      for (const f of rec.reconstructed.slice(0, maxObjects)) {
        try {
          const clean = f.path.replace(/\.\./g, '_').replace(/^\/+/, '');
          const full = join(outDir, clean);
          mkdirSync(join(full, '..'), { recursive: true });
          writeFileSync(full, f.body);
          wrote++;
        } catch { /* skip unwritable paths */ }
      }
      rec.notes.push(`wrote ${wrote} file(s) into ${outDir}`);
    }
    rec.reconstructed = rec.reconstructed.map((f) => ({ path: f.path, size: f.size }));
  }

  results.push(rec);
}

if (flag(o, 'json')) {
  console.log(JSON.stringify({ generated: new Date().toISOString(), results }, null, 2));
  exitSoon(results.some((r) => r.exposed) ? 1 : 0);
}

for (const r of results) {
  console.log(`\n### ${r.target}`);
  console.log(`base : ${r.base}`);
  console.log(`state: ${r.exposed ? 'EXPOSED .git DIRECTORY' : 'not exposed'}`);
  console.log(table(r.probes.map((p) => ({ path: p.path, status: p.status, bytes: p.bytes, valid: p.valid ? 'YES' : '', preview: String(p.preview).slice(0, 54) }))));
  if (!r.exposed) continue;

  console.log(`\nhead : ${r.head_ref || '(detached)'} ${r.head_sha || ''}`);
  if (r.config) console.log(`config:\n${r.config.trim()}`);
  if (r.packed_refs.length) console.log(`refs : ${r.packed_refs.map((x) => `${x.ref}@${x.sha.slice(0, 8)}`).join(' ')}`);
  if (rec_hasCommits(r)) {
    console.log('\ncommits:');
    console.log(table(r.commits.map((c) => ({ sha: c.sha.slice(0, 10), author: (c.author_name || '').slice(0, 18), email: (c.author_email || '').slice(0, 22), date: (c.author_time || '').slice(0, 10), message: (c.message || '').slice(0, 40) }))));
  }
  console.log(`objects: loose=${r.objects.loose} pack=${r.objects.from_pack} trees=${r.objects.trees} blobs=${r.objects.blobs}`);
  if (r.files.length) {
    console.log('\nfiles:');
    console.log(table(r.files.slice(0, 80).map((f) => ({ path: f.path.slice(0, 60), size: f.size ?? '', sha: f.sha.slice(0, 10) }))));
    if (r.files.length > 80) console.log(`... ${r.files.length - 80} more file(s)`);
  } else {
    console.log('no files reconstructed (loose objects may be pruned; packs need a local index)');
  }
  for (const n of r.notes) console.log(`note: ${n}`);
}
function rec_hasCommits(r) { return r.commits && r.commits.length; }
const exposedCount = results.filter((r) => r.exposed).length;
console.log(`\n${results.length} target(s), ${exposedCount} with an exposed .git directory`);
exitSoon(exposedCount ? 1 : 0);
