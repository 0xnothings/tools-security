// sshkeyaudit.js — SSH key hygiene audit.
// Copyright (c) 2026 0xnothings
// @tool sshkeyaudit
// @desc Audit SSH keys: fingerprints, type/strength, passphrase presence, authorized_keys anomalies, duplicates and weak keys
// @usage node tools/sshkeyaudit.js ~/.ssh --json
// @tags security,ssh,audit,keys
import crypto from 'node:crypto';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, basename } from 'node:path';
import { args, get, num, flag, die, readInput, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`sshkeyaudit — SSH key hygiene audit

  node tools/sshkeyaudit.js <dir|file|-> [options]

  Audits every key found in a directory (recursive, default depth 3) plus
  authorized_keys / known_hosts anomalies.

  --user <name>       attribute keys to this account (for the report)
  --max-depth <n>     directory recursion depth (default: 3)
  --json              machine-readable output
  -h, --help          this text

  Per key: type, bits, SHA256/MD5 fingerprint, encrypted (header) status,
  world-readable permission, comment, and a verdict. Weak types (DSA,
  RSA < 2048) are flagged. authorized_keys entries are checked for
  no-options pivots, duplicate blobs and non-standard paths.`);
  process.exit(0);
}

// process.exit() after a fetch deadlocks libuv on Windows; halting via a thrown
// sentinel keeps the exit code intact without tripping the async handle assert.
class ExitSignal extends Error { constructor() { super('exit-signal'); this.__exitSignal = true; } }
const __exitGuard = (e) => { if (!e || !e.__exitSignal) { process.stderr.write(String(e && e.stack || e) + '\n'); process.exitCode = 1; } };
process.on('uncaughtException', __exitGuard);
process.on('unhandledRejection', __exitGuard);
const exitSoon = (code = 0) => { process.exitCode = code; throw new ExitSignal(); };
const maxDepth = num(get(o, 'max-depth'), 3);

// ---------- key parsing ----------
function parseOpenSshPublicLine(line) {
  const t = line.trim();
  if (!t || t.startsWith('#')) return null;
  const parts = t.split(/\s+/);
  let idx = 0;
  const options = [];
  while (idx < parts.length && !/^(ssh-|ecdsa-|sk-|rsa-)/.test(parts[idx])) { options.push(parts[idx]); idx++; }
  const type = parts[idx] || '';
  const blobB64 = parts[idx + 1] || '';
  const comment = parts.slice(idx + 2).join(' ');
  if (!type || !blobB64) return null;
  let blob;
  try { blob = Buffer.from(blobB64, 'base64'); } catch { return null; }
  return { type, blob: blobB64, blobBuf: blob, comment, options: options.join(' ') };
}

function keyDetails(type, blob) {
  const out = { type, bits: null, curve: null, kind: null };
  try {
    if (type === 'ssh-rsa' || type === 'ssh-rsa-cert-v01@openssh.com') {
      // Wire format: string(type) | mpint(e) | mpint(n)
      let off = 0;
      const tlen = blob.readUInt32BE(off); off += 4 + tlen;
      const elen = blob.readUInt32BE(off); off += 4 + elen;
      const nlen = blob.readUInt32BE(off); off += 4;
      const modulus = blob.slice(off, off + nlen);
      // mpint is big-endian and may carry one leading 0x00 to keep it positive;
      // that pad byte is not part of the key size.
      let bits = modulus.length * 8;
      if (modulus[0] === 0) bits -= 8;
      const lead = modulus[0] === 0 ? modulus[1] : modulus[0];
      if (lead && lead < 0x80) bits -= (8 - lead.toString(2).length);
      out.bits = bits; out.kind = 'rsa';
    } else if (type === 'ssh-dss') { out.bits = 1024; out.kind = 'dsa'; }
    else if (type.startsWith('ecdsa-sha2-')) {
      out.kind = 'ecdsa';
      out.curve = type.replace('ecdsa-sha2-', '');
      out.bits = { nistp256: 256, nistp384: 384, nistp521: 521 }[out.curve] || null;
    } else if (type.startsWith('ssh-ed25519')) { out.kind = 'ed25519'; out.bits = 256; out.curve = 'curve25519'; }
    else if (type.startsWith('«redacted:sk-…»')) { out.kind = 'ed25519-sk'; out.bits = 256; }
    else if (type.startsWith('sk-ecdsa-')) { out.kind = 'ecdsa-sk'; out.bits = 256; }
    else out.kind = 'unknown';
  } catch { out.kind = 'unparseable'; }
  return out;
}

function fingerprints(blobBuf) {
  try {
    const sha256 = crypto.createHash('sha256').update(blobBuf).digest('base64').replace(/=+$/, '');
    const md5 = crypto.createHash('md5').update(blobBuf).digest('hex').match(/.{2}/g).join(':');
    return { sha256: `SHA256:${sha256}`, md5: `MD5:${md5}` };
  } catch { return { sha256: null, md5: null }; }
}

function privateKeyInfo(text) {
  const t = String(text);
  const header = (t.match(/^-----BEGIN ([A-Z0-9 ]+)-----/m) || [])[1] || null;
  if (!header) return { is_private: false };
  // OpenSSH-format keys do not say "ENCRYPTED" in the PEM armour; the cipher
  // name lives inside the decoded payload as an ASCII string (e.g. aes256-ctr).
  let encrypted = /BEGIN ENCRYPTED PRIVATE KEY|Proc-Type: 4,ENCRYPTED/.test(t);
  if (!encrypted) {
    try {
      const body = t.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      const raw = Buffer.from(body, 'base64').toString('latin1');
      if (/OPENSSH PRIVATE KEY/.test(t)) {
        encrypted = /aes(128|192|256)-(ctr|cbc|gcm)|chacha20-poly1305|bcrypt/i.test(raw);
      } else encrypted = /ENCRYPTED|bcrypt/i.test(raw.slice(0, 200));
    } catch { /* keep the armour-only verdict */ }
  }
  if (/bcrypt/i.test(t)) encrypted = true;
  let kind = null, bits = null;
  if (/RSA/.test(header)) kind = 'rsa';
  else if (/DSA/.test(header)) { kind = 'dsa'; bits = 1024; }
  else if (/EC/.test(header)) kind = 'ecdsa';
  else if (/OPENSSH/.test(header)) kind = 'openssh';
  else if (/PRIVATE KEY/.test(header)) kind = 'pkcs8';
  let parsed = null;
  if (!encrypted && kind) {
    try {
      const k = crypto.createPrivateKey(t);
      const det = k.asymmetricKeyDetails || {};
      parsed = { type: k.asymmetricKeyType, modulus_bits: det.modulusLength || null, named_curve: det.namedCurve || null };
      bits = det.modulusLength || (det.namedCurve ? ({ prime256v1: 256, secp384r1: 384, secp521r1: 521 }[det.namedCurve] || null) : bits);
    } catch { /* encrypted or unsupported */ }
  }
  return { is_private: true, header, encrypted, kind, bits, parsed };
}

function assessKey(k) {
  const issues = [];
  const notes = [];
  if (k.kind === 'dsa') issues.push({ id: 'dsa-key', severity: 'CRITICAL', detail: 'DSA key (1024-bit, effectively broken)' });
  if (k.kind === 'rsa' && k.bits && k.bits < 2048) issues.push({ id: 'weak-rsa', severity: 'CRITICAL', detail: `RSA key only ${k.bits} bits — factorable` });
  else if (k.kind === 'rsa' && k.bits === 2048) notes.push({ id: 'rsa-2048', severity: 'INFO', detail: 'RSA 2048 is acceptable but ed25519 is preferred' });
  if (k.kind === 'rsa' && k.bits && k.bits >= 4096) notes.push({ id: 'rsa-oversized', severity: 'INFO', detail: `RSA ${k.bits} increases handshake cost with little gain over ed25519` });
  if (k.is_private && !k.encrypted) issues.push({ id: 'no-passphrase', severity: 'HIGH', detail: 'private key is stored without a passphrase — anyone who reads the file owns the identity' });
  if (k.is_private && k.encrypted) notes.push({ id: 'encrypted', severity: 'INFO', detail: 'private key is passphrase-protected' });
  // Permissions only matter for secret material. Public keys, authorized_keys
  // and known_hosts are not secrets, and Windows does not apply POSIX bits.
  const isWindows = process.platform === 'win32';
  if (k.is_private && !isWindows && k.mode !== undefined && (k.mode & 0o077) !== 0) {
    issues.push({ id: 'bad-permissions', severity: 'HIGH', detail: `private key permissions ${(k.mode & 0o777).toString(8)} allow group/other access` });
  } else if (k.is_private && isWindows && k.mode !== undefined && (k.mode & 0o077) !== 0) {
    notes.push({ id: 'posix-bits-not-enforced', severity: 'INFO', detail: 'POSIX mode bits are not enforced on Windows; use the ACL to confirm the key is not world-readable' });
  }
  return { issues, notes };
}

const AUTHKEY_OPTIONS_OF_INTEREST = [
  { re: /command\s*=\s*"[^"]*"/i, sev: 'INFO', msg: 'forced command restricts the key' },
  { re: /no-pty|no-port-forwarding|no-agent-forwarding|no-x11-forwarding|restrict/i, sev: 'INFO', msg: 'key is restricted with options (good)' },
  { re: /permitopen|permitlisten/i, sev: 'LOW', msg: 'key has explicit forwarding permissions' },
  { re: /from\s*=\s*"[^"]*"/i, sev: 'INFO', msg: 'key is pinned to a source address' },
  { re: /environment\s*=/i, sev: 'MEDIUM', msg: 'key sets environment variables — can influence login shell behaviour' },
];

// ---------- discovery ----------
function walk(dir, level, out) {
  if (level > maxDepth) return out;
  let ents;
  try { ents = readdirSync(dir); } catch { return out; }
  for (const e of ents) {
    const full = join(dir, e);
    let st;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) { walk(full, level + 1, out); continue; }
    if (st.size > 1024 * 512) continue;
    out.push({ path: full, mode: st.mode & 0o777, size: st.size });
  }
  return out;
}

const target = o._[0];
if (!target) die('pass a directory, a key file, or - for stdin');
const report = { generated: new Date().toISOString(), user: get(o, 'user', null), files_scanned: 0, keys: [], authorized_keys: [], known_hosts: 0, findings: [] };

const files = [];
if (target === '-') {
  files.push({ path: '(stdin)', mode: 0o600, size: 0, inline: await readInput(null) });
} else if (existsSync(target)) {
  const st = statSync(target);
  if (st.isDirectory()) walk(target, 0, files);
  else files.push({ path: target, mode: st.mode & 0o777, size: st.size });
} else die(`path not found: ${target}`);

for (const f of files) {
  let text = f.inline;
  if (text === undefined) { try { text = readFileSync(f.path, 'utf8'); } catch { continue; } }
  report.files_scanned++;
  const base = basename(f.path);

  // known_hosts
  if (base === 'known_hosts' || base === 'known_hosts.old') {
    const n = text.split(/\r?\n/).filter((l) => l.trim() && !l.startsWith('#')).length;
    report.known_hosts += n;
    if (n > 250) report.findings.push({ id: 'large-known-hosts', severity: 'INFO', detail: `${f.path} has ${n} host entries — stale trust anchors accumulate`, fix: 'prune hosts that no longer exist' });
    continue;
  }

  // authorized_keys
  if (base === 'authorized_keys' || base === 'authorized_keys2' || base === 'authorized_keys.bak') {
    const lines = text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#'));
    const seen = new Map();
    for (const line of lines) {
      const parsedLine = parseOpenSshPublicLine(line);
      if (!parsedLine) { report.authorized_keys.push({ path: f.path, error: 'unparseable line', line: line.slice(0, 80) }); continue; }
      const det = keyDetails(parsedLine.type, parsedLine.blobBuf);
      const fp = fingerprints(parsedLine.blobBuf);
      const keyIssues = [];
      if (det.kind === 'dsa') keyIssues.push({ id: 'dsa-authorized', severity: 'CRITICAL', detail: 'DSA key authorized — can be forged' });
      if (det.kind === 'rsa' && det.bits && det.bits < 2048) keyIssues.push({ id: 'weak-rsa-authorized', severity: 'CRITICAL', detail: `weak RSA ${det.bits}-bit key authorized` });
      if (!parsedLine.options && !/restrict|no-pty|command=/.test(line)) keyIssues.push({ id: 'unrestricted-key', severity: 'LOW', detail: 'key has no options — full shell, agent and port forwarding' });
      for (const opt of AUTHKEY_OPTIONS_OF_INTEREST) if (opt.re.test(parsedLine.options || '') && opt.sev !== 'INFO') keyIssues.push({ id: 'key-option', severity: opt.sev, detail: opt.msg });
      if (seen.has(fp.sha256)) keyIssues.push({ id: 'duplicate-key', severity: 'MEDIUM', detail: `duplicate key entry (same fingerprint as line ${seen.get(fp.sha256)})` });
      else seen.set(fp.sha256, report.authorized_keys.length + 1);
      if (/^ssh-rsa/.test(parsedLine.type) && !/rsa-sha2/.test(line)) keyIssues.push({ id: 'legacy-rsa-sig', severity: 'MEDIUM', detail: 'ssh-rsa signature algorithm authorized (SHA-1 based)' });
      if (base === 'authorized_keys2') keyIssues.push({ id: 'authorized-keys2', severity: 'LOW', detail: 'legacy authorized_keys2 file still in use' });
      report.authorized_keys.push({ path: f.path, type: det.type, kind: det.kind, bits: det.bits, fingerprint: fp.sha256, comment: parsedLine.comment || '', options: parsedLine.options || '', issues: keyIssues });
      for (const i of keyIssues) report.findings.push({ ...i, path: f.path, fingerprint: fp.sha256 });
    }
    if (!lines.length) report.findings.push({ id: 'empty-authorized-keys', severity: 'INFO', detail: `${f.path} exists but is empty`, fix: 'remove the file if unused' });
    continue;
  }

  // public key file
  if (/\.pub$/.test(base) || /^(id_|ssh_host_)/.test(base) || /public/.test(base)) {
    const parsedLine = parseOpenSshPublicLine(text.split(/\r?\n/).find((l) => l.trim()) || '');
    if (parsedLine) {
      const det = keyDetails(parsedLine.type, parsedLine.blobBuf);
      const fp = fingerprints(parsedLine.blobBuf);
      const rec = { path: f.path, kind: det.kind, type: det.type, bits: det.bits, curve: det.curve, fingerprint: fp.sha256, md5: fp.md5, comment: parsedLine.comment || '', mode: f.mode.toString(8), is_private: false, issues: [] };
      const a = assessKey({ ...det, is_private: false, mode: f.mode });
      rec.issues = a.issues; rec.notes = a.notes;
      report.keys.push(rec);
      for (const i of a.issues) report.findings.push({ ...i, path: f.path, fingerprint: fp.sha256 });
      continue;
    }
  }

  // private or OpenSSH-format key
  const info = privateKeyInfo(text);
  if (info.is_private) {
    const rec = {
      path: f.path, kind: info.kind, type: info.parsed?.type || info.header, bits: info.bits,
      encrypted: info.encrypted, is_private: true, mode: f.mode.toString(8),
      fingerprint: null, comment: '', issues: [], notes: [],
    };
    // Derive the public fingerprint from an unencrypted private key.
    if (!info.encrypted) {
      try {
        const k = crypto.createPrivateKey(text);
        const pub = crypto.createPublicKey(k).export({ type: 'spki', format: 'der' });
        const rem = crypto.createHash('sha256').update(pub).digest('base64').replace(/=+$/, '');
        rec.fingerprint = `SHA256:${rem} (spki; openssh blob fingerprint differs)`;
      } catch { /* ignore */ }
    }
    const a = assessKey({ kind: info.kind, bits: info.bits, is_private: true, mode: f.mode, encrypted: info.encrypted });
    rec.issues = a.issues; rec.notes = a.notes;
    if (info.header && /BEGIN OPENSSH PRIVATE KEY/.test(info.header) && !info.encrypted) {
      rec.notes.push({ id: 'openssh-format', severity: 'INFO', detail: 'OpenSSH format without a passphrase — readable by the ssh client non-interactively' });
    }
    report.keys.push(rec);
    for (const i of a.issues) report.findings.push({ ...i, path: f.path });
  }
}

// Duplicate detection across all keys
const byFp = new Map();
for (const k of report.keys) {
  if (!k.fingerprint) continue;
  if (byFp.has(k.fingerprint)) report.findings.push({ id: 'duplicate-across-files', severity: 'MEDIUM', detail: `key material reused in ${byFp.get(k.fingerprint)} and ${k.path}`, fix: 'use distinct keys per host and purpose' });
  else byFp.set(k.fingerprint, k.path);
}

if (flag(o, 'json')) {
  const bySeverity = report.findings.reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {});
  console.log(JSON.stringify({ ...report, summary: { keys: report.keys.length, authorized_entries: report.authorized_keys.length, known_host_entries: report.known_hosts, by_severity: bySeverity } }, null, 2));
  exitSoon(report.findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH') ? 1 : 0);
}

console.log(`scanned ${report.files_scanned} file(s)${report.user ? ' for ' + report.user : ''}: ${report.keys.length} key(s), ${report.authorized_keys.length} authorized_keys entr(y/ies), ${report.known_hosts} known_hosts entr(y/ies)`);
if (report.keys.length) {
  console.log('\n--- keys ---');
  console.log(table(report.keys.map((k) => ({
    path: k.path.slice(-42), priv: k.is_private ? 'yes' : 'no', type: (k.type || k.kind || '').slice(0, 18),
    bits: k.bits ?? '', pass: k.is_private ? (k.encrypted ? 'yes' : 'NO') : '', mode: k.mode,
    fingerprint: (k.fingerprint || '').slice(0, 28), issues: (k.issues || []).length,
  }))));
}
if (report.authorized_keys.length) {
  console.log('\n--- authorized_keys ---');
  console.log(table(report.authorized_keys.map((a) => ({
    file: (a.path || '').slice(-28), type: (a.type || a.error || '').slice(0, 16), bits: a.bits ?? '',
    comment: (a.comment || '').slice(0, 22), options: (a.options || '-').slice(0, 24), issues: (a.issues || []).length,
  }))));
}
console.log(`\n--- FINDINGS (${report.findings.length}) ---`);
if (!report.findings.length) console.log('no key hygiene issues detected');
else {
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  report.findings.sort((a, b) => order[a.severity] - order[b.severity]);
  console.log(table(report.findings.map((f) => ({ severity: f.severity, id: f.id, detail: f.detail.slice(0, 70), path: (f.path || '').slice(-30) }))));
}
exitSoon(report.findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH') ? 1 : 0);
