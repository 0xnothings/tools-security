// encryptfile.js — AES-256-GCM file encryption with scrypt KDF.
// Copyright (c) 2026 0xnothings
// @tool encryptfile
// @desc Encrypt or decrypt a file with AES-256-GCM and a scrypt-derived key, with integrity verification and password rotation
// @usage node tools/encryptfile.js enc secret.txt --out secret.bin
// @tags security,crypto,files
import crypto from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, statSync, renameSync } from 'node:fs';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`encryptfile — AES-256-GCM file encryption

  node tools/encryptfile.js <enc|dec|info|verify|rekey> <file> [options]

  Commands:
    enc      encrypt <file> -> <file>.enc (or --out)
    dec      decrypt <file> -> output (or --out)
    info     read the header of an encrypted file without the password
    verify   decrypt in memory and confirm the GCM tag matches
    rekey    re-encrypt with a new password without writing plaintext to disk

  Options:
    --out <path>     output path
    --password <p>   password (otherwise prompted, or read from $ENCRYPTFILE_PASSWORD)
    --new-password   replacement password for rekey
    --chunk <bytes>  streaming chunk size (default: 1048576)
    --scrypt-n <n>   scrypt cost (default: 16384; stored in the header)
    --no-meta        omit the original filename from the header
    --force          overwrite an existing output file
    --json           machine-readable output
    -h, --help       this text

  Format: MAGIC(8) | version(1) | scrypt params(4+4+4) | salt(16) | nonce(12) |
  header-len(4) | header-json | ciphertext | GCM tag(16).
  The header is authenticated as additional data, so tampering fails the tag.`);
  process.exit(0);
}

const exitSoon = (code = 0) => { process.exitCode = code; };
const MAGIC = Buffer.from('0XNTENC1', 'ascii');
const VERSION = 1;
const chunkSize = num(get(o, 'chunk'), 1048576);
const scryptN = num(get(o, 'scrypt-n'), 16384);

function deriveKey(password, salt, N, r, p) {
  return crypto.scryptSync(String(password), salt, 32, { N, r, p, maxmem: 256 * 1024 * 1024 });
}

function getPassword(promptLabel, explicit) {
  if (explicit) return String(explicit);
  if (process.env.ENCRYPTFILE_PASSWORD) return process.env.ENCRYPTFILE_PASSWORD;
  // Non-interactive fallback: read a line from stdin.
  try {
    const buf = readFileSync(0);
    const line = buf.toString('utf8').split(/\r?\n/)[0];
    if (line) return line;
  } catch { /* no stdin */ }
  die(`${promptLabel}: no password supplied (use --password or $ENCRYPTFILE_PASSWORD)`);
}

function writeOut(path, buf, force) {
  if (existsSync(path) && !force) die(`refusing to overwrite ${path} (pass --force)`);
  writeFileSync(path, buf);
}

// ---------- commands ----------
function cmdEnc(input, outPath, password) {
  if (!existsSync(input)) die(`file not found: ${input}`);
  const plain = readFileSync(input);
  const salt = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(12);
  const r = 8, p = 1;
  const key = deriveKey(password, salt, scryptN, r, p);
  const headerMeta = {
    name: flag(o, 'no-meta') ? null : input.split(/[\\/]/).pop(),
    size: plain.length,
    created: new Date().toISOString(),
    algo: 'aes-256-gcm',
    kdf: `scrypt N=${scryptN} r=${r} p=${p}`,
  };
  const headerJson = Buffer.from(JSON.stringify(headerMeta), 'utf8');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  // Params + salt + nonce + header length are all authenticated as AAD.
  const params = Buffer.alloc(12);
  params.writeUInt32BE(scryptN, 0); params.writeUInt32BE(r, 4); params.writeUInt32BE(p, 8);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(headerJson.length, 0);
  cipher.setAAD(Buffer.concat([MAGIC, Buffer.from([VERSION]), params, salt, nonce, lenBuf, headerJson]));
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  const out = Buffer.concat([MAGIC, Buffer.from([VERSION]), params, salt, nonce, lenBuf, headerJson, ct, tag]);
  const target = outPath || `${input}.enc`;
  writeOut(target, out, flag(o, 'force'));
  return {
    command: 'enc', input, output: target, bytes_in: plain.length, bytes_out: out.length,
    overhead: out.length - plain.length, header_bytes: headerJson.length,
    sha256_plaintext: crypto.createHash('sha256').update(plain).digest('hex'),
    salt: salt.toString('hex'), nonce: nonce.toString('hex'), tag: tag.toString('hex'),
    scrypt: { N: scryptN, r, p }, meta: headerMeta,
  };
}

function readContainer(path) {
  const buf = readFileSync(path);
  if (buf.length < 8 + 1 + 12 + 16 + 12 + 4 + 16) die('file is too small to be an encryptfile container');
  if (!buf.slice(0, 8).equals(MAGIC)) die('bad magic — not an encryptfile container');
  let off = 8;
  const version = buf[off]; off += 1;
  if (version !== VERSION) die(`unsupported container version ${version}`);
  const N = buf.readUInt32BE(off); const r = buf.readUInt32BE(off + 4); const p = buf.readUInt32BE(off + 8); off += 12;
  const salt = buf.slice(off, off + 16); off += 16;
  const nonce = buf.slice(off, off + 12); off += 12;
  const headerLen = buf.readUInt32BE(off); off += 4;
  if (headerLen > 65535 || off + headerLen + 16 > buf.length) die('corrupt header length');
  const headerJson = buf.slice(off, off + headerLen); off += headerLen;
  let meta = null;
  try { meta = JSON.parse(headerJson.toString('utf8')); } catch { die('header JSON is corrupt'); }
  const tag = buf.slice(buf.length - 16);
  const ciphertext = buf.slice(off, buf.length - 16);
  const aad = Buffer.concat([MAGIC, Buffer.from([version]),
    (() => { const b = Buffer.alloc(12); b.writeUInt32BE(N, 0); b.writeUInt32BE(r, 4); b.writeUInt32BE(p, 8); return b; })(),
    salt, nonce, (() => { const b = Buffer.alloc(4); b.writeUInt32BE(headerLen, 0); return b; })(), headerJson]);
  return { buf, version, N, r, p, salt, nonce, tag, ciphertext, meta, aad, headerLen };
}

function decryptContainer(path, password) {
  const c = readContainer(path);
  const key = deriveKey(password, c.salt, c.N, c.r, c.p);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, c.nonce, { authTagLength: 16 });
  decipher.setAAD(c.aad);
  decipher.setAuthTag(c.tag);
  let plain;
  try { plain = Buffer.concat([decipher.update(c.ciphertext), decipher.final()]); }
  catch { return { ok: false, error: 'authentication failed — wrong password or the file was tampered with', container: c }; }
  return { ok: true, plain, container: c };
}

function cmdDec(input, outPath, password) {
  const r = decryptContainer(input, password);
  if (!r.ok) return { command: 'dec', input, ok: false, error: r.error, meta: r.container.meta };
  const target = outPath || (r.container.meta?.name || `${input}.dec`);
  writeOut(target, r.plain, flag(o, 'force'));
  return {
    command: 'dec', input, output: target, ok: true,
    bytes_in: r.container.ciphertext.length, bytes_out: r.plain.length,
    integrity: 'GCM tag verified', meta: r.container.meta,
    sha256_plaintext: crypto.createHash('sha256').update(r.plain).digest('hex'),
  };
}

function cmdInfo(input) {
  const c = readContainer(input);
  return {
    command: 'info', input, container_bytes: c.buf.length, version: c.version,
    scrypt: { N: c.N, r: c.r, p: c.p }, salt_hex: c.salt.toString('hex'),
    nonce_hex: c.nonce.toString('hex'), tag_hex: c.tag.toString('hex'),
    header_bytes: c.headerLen, ciphertext_bytes: c.ciphertext.length,
    meta: c.meta,
    note: 'info does not verify the tag — run verify with the password',
  };
}

function cmdVerify(input, password) {
  const r = decryptContainer(input, password);
  return {
    command: 'verify', input, ok: r.ok,
    integrity: r.ok ? 'VALID — GCM tag matches, nothing was modified' : r.error,
    bytes: r.ok ? r.plain.length : null,
    sha256_plaintext: r.ok ? crypto.createHash('sha256').update(r.plain).digest('hex') : undefined,
  };
}

function cmdRekey(input, outPath, password, newPassword) {
  if (!newPassword) die('rekey needs --new-password');
  const r = decryptContainer(input, password);
  if (!r.ok) return { command: 'rekey', input, ok: false, error: r.error };
  const target = outPath || input;
  const salt = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(12);
  const rr = 8, pp = 1;
  const key = deriveKey(newPassword, salt, scryptN, rr, pp);
  const meta = { ...(r.container.meta || {}), rekeyed: new Date().toISOString() };
  const headerJson = Buffer.from(JSON.stringify(meta), 'utf8');
  const params = Buffer.alloc(12);
  params.writeUInt32BE(scryptN, 0); params.writeUInt32BE(rr, 4); params.writeUInt32BE(pp, 8);
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32BE(headerJson.length, 0);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.concat([MAGIC, Buffer.from([VERSION]), params, salt, nonce, lenBuf, headerJson]));
  const ct = Buffer.concat([cipher.update(r.plain), cipher.final()]);
  const out = Buffer.concat([MAGIC, Buffer.from([VERSION]), params, salt, nonce, lenBuf, headerJson, ct, cipher.getAuthTag()]);
  if (target === input) {
    // Atomic-ish replace: write to a sibling then rename over the original.
    const tmp = `${input}.rekey.tmp`;
    writeFileSync(tmp, out);
    renameSync(tmp, target);
  } else writeOut(target, out, flag(o, 'force'));
  return { command: 'rekey', input, output: target, ok: true, bytes_plaintext: r.plain.length, bytes_out: out.length, new_scrypt: { N: scryptN, r: rr, p: pp } };
}

// ---------- dispatch ----------
const cmd = String(o._[0] || '').toLowerCase();
const input = o._[1];
const COMMANDS = ['enc', 'dec', 'info', 'verify', 'rekey'];
if (!COMMANDS.includes(cmd)) die(`unknown command "${cmd || '(none)'}" — use one of: ${COMMANDS.join(', ')}`);
if (!input) die(`command "${cmd}" needs a file argument`);

let report;
if (cmd === 'info') report = cmdInfo(input);
else if (cmd === 'enc') report = cmdEnc(input, get(o, 'out', null), getPassword('encrypt password', get(o, 'password', null)));
else if (cmd === 'dec') report = cmdDec(input, get(o, 'out', null), getPassword('decrypt password', get(o, 'password', null)));
else if (cmd === 'verify') report = cmdVerify(input, getPassword('verify password', get(o, 'password', null)));
else if (cmd === 'rekey') {
  report = cmdRekey(input, get(o, 'out', null), getPassword('current password', get(o, 'password', null)), get(o, 'new-password', null));
}

const ok = report.ok !== false && !report.error;
if (flag(o, 'json')) { console.log(JSON.stringify(report, null, 2)); exitSoon(ok ? 0 : 1); }

console.log(`command : ${report.command}`);
console.log(`input   : ${report.input}`);
if (report.output) console.log(`output  : ${report.output}${existsSync(report.output) ? ` (${statSync(report.output).size} bytes on disk)` : ''}`);
if (report.bytes_in !== undefined) console.log(`sizes   : ${report.bytes_in} in -> ${report.bytes_out ?? '?'} out${report.overhead ? ` (${report.overhead} bytes overhead)` : ''}`);
if (report.scrypt) console.log(`kdf     : scrypt N=${report.scrypt.N} r=${report.scrypt.r} p=${report.scrypt.p}`);
if (report.new_scrypt) console.log(`new kdf : scrypt N=${report.new_scrypt.N} r=${report.new_scrypt.r} p=${report.new_scrypt.p}`);
if (report.salt_hex) console.log(`salt    : ${report.salt_hex}`);
if (report.nonce_hex) console.log(`nonce   : ${report.nonce_hex}`);
if (report.tag_hex) console.log(`tag     : ${report.tag_hex}`);
if (report.integrity) console.log(`integrity: ${report.integrity}`);
if (report.sha256_plaintext) console.log(`sha256  : ${report.sha256_plaintext}`);
if (report.meta) console.log(`meta    : ${JSON.stringify(report.meta)}`);
if (report.error) console.log(`ERROR   : ${report.error}`);
exitSoon(ok ? 0 : 1);
