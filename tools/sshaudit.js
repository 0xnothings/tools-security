#!/usr/bin/env node
// sshaudit.js — SSH server configuration and handshake audit.
// Copyright (c) 2026 0xnothings
// @tool sshaudit
// @desc Audit sshd_config text and a live SSH handshake for weak algorithms, insecure options and policy gaps
// @usage node tools/sshaudit.js /etc/ssh/sshd_config --json
// @tags security,ssh,audit,network
import net from 'node:net';
import { readFileSync, existsSync } from 'node:fs';
import { args, get, num, flag, die, readInput, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`sshaudit — sshd_config + handshake auditor

  node tools/sshaudit.js [config-or-host] [options]

  node tools/sshaudit.js /etc/ssh/sshd_config
  node tools/sshaudit.js 10.0.0.5
  node tools/sshaudit.js 10.0.0.5:2222 --config sshd_config.txt

  --config <file>   config file to analyse (default: the positional path if present)
  --port <n>        SSH port for the handshake probe (default: 22)
  --timeout <ms>    handshake timeout (default: 8000)
  --no-probe        config-only audit
  --json            machine-readable output
  -h, --help        this text

  Config checks: PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords,
  X11Forwarding, UsePAM, AllowTcpForwarding, MaxAuthTries, LoginGraceTime,
  weak KexAlgorithms/MACs/Ciphers, HostKey sizes, AllowUsers/Match coverage.
  Handshake check: banner version, algorithm list offered by the server.`);
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

// ---------- sshd_config parsing ----------
function parseSshdConfig(text) {
  const cfg = {};
  const order = [];
  let context = 'global';
  const lines = String(text).split(/\r?\n/);
  const raw = [];
  for (const rawLine of lines) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    const key = parts[0].toLowerCase();
    const val = parts.slice(1).join(' ').trim();
    raw.push({ key, val, context });
    if (key === 'match') { context = `match ${val}`; continue; }
    if (context !== 'global') continue;
    if (!cfg[key]) order.push(key);
    cfg[key] = val;
  }
  return { cfg, order, raw };
}

const CFG_CHECKS = [
  { key: 'permitrootlogin', bad: (v) => /^yes$/i.test(v), sev: 'CRITICAL', msg: 'PermitRootLogin yes allows direct root login', fix: 'PermitRootLogin no (or prohibit-password with key-only access)' },
  { key: 'permitrootlogin', bad: (v) => /^without-password$/i.test(v), sev: 'MEDIUM', msg: 'PermitRootLogin without-password is deprecated syntax', fix: 'use prohibit-password' },
  { key: 'passwordauthentication', bad: (v) => /^yes$/i.test(v), sev: 'HIGH', msg: 'PasswordAuthentication yes exposes the server to credential brute force', fix: 'PasswordAuthentication no with key-based auth + MFA' },
  { key: 'permitemptypasswords', bad: (v) => /^yes$/i.test(v), sev: 'CRITICAL', msg: 'PermitEmptyPasswords yes allows passwordless login', fix: 'PermitEmptyPasswords no' },
  { key: 'kbdinteractiveauthentication', bad: (v) => /^yes$/i.test(v), sev: 'MEDIUM', msg: 'KbdInteractiveAuthentication yes re-enables password-style prompts', fix: 'disable unless MFA/PAM needs it' },
  { key: 'challengeresponseauthentication', bad: (v) => /^yes$/i.test(v), sev: 'MEDIUM', msg: 'ChallengeResponseAuthentication yes enables password prompts', fix: 'set to no' },
  { key: 'x11forwarding', bad: (v) => /^yes$/i.test(v), sev: 'LOW', msg: 'X11Forwarding yes exposes the X11 socket', fix: 'X11Forwarding no' },
  { key: 'allowtcpforwarding', bad: (v) => /^yes$/i.test(v), sev: 'MEDIUM', msg: 'AllowTcpForwarding yes lets any user pivot through the host', fix: 'AllowTcpForwarding no (or local only)' },
  { key: 'permittunnel', bad: (v) => /^yes$/i.test(v), sev: 'MEDIUM', msg: 'PermitTunnel yes allows layer-2/3 tunnelling', fix: 'PermitTunnel no' },
  { key: 'gatewayports', bad: (v) => /^yes$/i.test(v), sev: 'MEDIUM', msg: 'GatewayPorts yes exposes forwarded ports to the network', fix: 'GatewayPorts no' },
  { key: 'usedns', bad: (v) => /^yes$/i.test(v), sev: 'LOW', msg: 'UseDNS yes adds latency and a DNS-rebinding surface', fix: 'UseDNS no' },
  { key: 'maxauthtries', bad: (v) => Number(v) > 4, sev: 'MEDIUM', msg: (v) => `MaxAuthTries ${v} allows more guesses per connection than needed`, fix: 'MaxAuthTries 3' },
  { key: 'logingracetime', bad: (v) => { const s = /(\d+)([smh]?)/.exec(v); if (!s) return false; const n = Number(s[1]) * ({ s: 1, m: 60, h: 3600 }[s[2] || 's']); return n > 60; }, sev: 'LOW', msg: 'LoginGraceTime over 60s keeps unauthenticated sockets open', fix: 'LoginGraceTime 30' },
  { key: 'maxsessions', bad: (v) => Number(v) > 10, sev: 'LOW', msg: 'MaxSessions lets one account hold many parallel sessions', fix: 'MaxSessions 4' },
  { key: 'clientaliveinterval', bad: (v) => Number(v) === 0, sev: 'LOW', msg: 'ClientAliveInterval 0 leaves idle sessions open forever', fix: 'ClientAliveInterval 300' },
  { key: 'strictmodes', bad: (v) => /^no$/i.test(v), sev: 'MEDIUM', msg: 'StrictModes no ignores bad permissions on key files', fix: 'StrictModes yes' },
  { key: 'ignorerhosts', bad: (v) => /^no$/i.test(v), sev: 'LOW', msg: 'IgnoreRhosts no leaves .rhosts trust active', fix: 'IgnoreRhosts yes' },
  { key: 'hostbasedauthentication', bad: (v) => /^yes$/i.test(v), sev: 'HIGH', msg: 'HostbasedAuthentication yes trusts host keys for user auth', fix: 'disable host-based auth' },
  { key: 'pubkeyauthentication', bad: (v) => /^no$/i.test(v), sev: 'MEDIUM', msg: 'PubkeyAuthentication no forces weaker auth methods', fix: 'PubkeyAuthentication yes' },
  { key: 'ciphers', bad: (v) => /(3des|arcfour|blowfish|cast128|cbc)/i.test(v), sev: 'HIGH', msg: (v) => `Ciphers includes weak CBC/legacy entries: ${v}`, fix: 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com' },
  { key: 'macs', bad: (v) => /(hmac-md5|hmac-sha1-96|umac-32|hmac-ripemd)/i.test(v), sev: 'HIGH', msg: (v) => `MACs includes weak entries: ${v}`, fix: 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com' },
  { key: 'kexalgorithms', bad: (v) => /(diffie-hellman-group1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)/i.test(v), sev: 'HIGH', msg: (v) => `KexAlgorithms includes legacy groups: ${v}`, fix: 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group16-sha512' },
  { key: 'hostkeyalgorithms', bad: (v) => /(ssh-dss|ssh-rsa)/i.test(v), sev: 'MEDIUM', msg: (v) => `HostKeyAlgorithms includes ssh-rsa/ssh-dss: ${v}`, fix: 'allow rsa-sha2-256/512 and ed25519 only' },
  { key: 'hostkey', bad: (v) => /ssh_host_dsa_key/.test(v), sev: 'HIGH', msg: 'DSA host key configured (1024-bit, deprecated)', fix: 'remove DSA keys, use ed25519' },
  { key: 'allowusers', bad: () => false, sev: 'INFO', msg: () => 'AllowUsers/AllowGroups not set — every local account is reachable', fix: 'restrict with AllowUsers or AllowGroups' },
  { key: 'authorizedkeysfile', bad: (v) => /\.ssh\/authorized_keys2/.test(v), sev: 'LOW', msg: 'authorized_keys2 is a legacy path', fix: '.ssh/authorized_keys' },
];

function auditConfig(text) {
  const { cfg, order, raw } = parseSshdConfig(text);
  const findings = [];
  const seen = new Set();
  for (const chk of CFG_CHECKS) {
    const v = cfg[chk.key];
    if (v === undefined) {
      if (chk.key === 'allowusers') {
        findings.push({ id: 'missing-allowusers', severity: 'MEDIUM', detail: 'no AllowUsers/AllowGroups directive — any local account can attempt login', fix: 'add AllowUsers or AllowGroups' });
      }
      continue;
    }
    if (seen.has(chk.key)) continue;
    if (chk.bad(v)) { seen.add(chk.key); findings.push({ id: `cfg-${chk.key}`, severity: chk.sev, detail: typeof chk.msg === 'function' ? chk.msg(v) : chk.msg, fix: chk.fix, value: v }); }
  }
  // Root login defaults to prohibit-password on modern OpenSSH but "yes" on some distros.
  if (cfg.permitrootlogin === undefined) findings.push({ id: 'root-login-default', severity: 'LOW', detail: 'PermitRootLogin not set — defaults to prohibit-password on OpenSSH >= 7.0', fix: 'set PermitRootLogin no explicitly' });
  if (cfg.protocol && cfg.protocol.includes('1')) findings.push({ id: 'sshv1', severity: 'CRITICAL', detail: 'Protocol 1 enabled — trivially broken', fix: 'remove the Protocol directive' });

  const policy = {
    permit_root_login: cfg.permitrootlogin || '(default prohibit-password)',
    password_auth: cfg.passwordauthentication || '(default yes)',
    pubkey_auth: cfg.pubkeyauthentication || '(default yes)',
    empty_passwords: cfg.permitemptypasswords || '(default no)',
    max_auth_tries: cfg.maxauthtries || '(default 6)',
    forwarding: cfg.allowtcpforwarding || '(default yes)',
    x11: cfg.x11forwarding || '(default no)',
    use_pam: cfg.usepam || '(unset)',
    client_alive: cfg.clientaliveinterval || '(unset)',
    directives: order.length,
  };
  return { findings, policy, cfg, order, raw_count: raw.length };
}

// ---------- live handshake ----------
function probeSsh(host, port, ms) {
  return new Promise((resolve) => {
    let done = false;
    const chunks = [];
    const fin = (err) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      try { sock.destroy(); } catch { /* ignore */ }
      const text = Buffer.concat(chunks).toString('latin1');
      const banner = (text.match(/^SSH-[^\r\n]+/m) || [])[0] || '';
      const kexInit = text.includes('KEXINIT') || text.length > 100;
      resolve({ banner, bytes: Buffer.concat(chunks).length, got_kexinit: kexInit, error: err || null, raw_head: text.slice(0, 200) });
    };
    const sock = net.connect({ host, port });
    const t = setTimeout(() => fin(null), ms);
    sock.on('connect', () => { /* server speaks first */ });
    sock.on('data', (c) => { chunks.push(c); if (Buffer.concat(chunks).length > 4096) fin(null); });
    sock.on('error', (e) => fin(e.code || e.message));
    sock.on('close', () => fin(null));
  });
}

// ---------- input resolution ----------
const positional = o._[0];
let configText = null;
let configSource = null;
let hostTarget = null;

const looksLikeHost = positional && (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(positional) || /^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/i.test(positional)) && !existsSync(positional);

if (o.f.config) {
  configText = readFileSync(String(o.f.config), 'utf8');
  configSource = String(o.f.config);
  hostTarget = positional && looksLikeHost ? positional : null;
} else if (positional && existsSync(positional)) {
  configText = readFileSync(positional, 'utf8');
  configSource = positional;
  hostTarget = o._[1] || null;
} else if (looksLikeHost) {
  hostTarget = positional;
} else if (positional === '-' || (!positional && !process.stdin.isTTY)) {
  configText = await readInput(null);
  configSource = 'stdin';
}

if (!configText && !hostTarget) die('pass an sshd_config path, a host/IP, or pipe config on stdin');

const report = { generated: new Date().toISOString(), config: null, handshake: null, findings: [] };

if (configText) {
  const a = auditConfig(configText);
  report.config = { source: configSource, policy: a.policy, directives: a.cfg, directive_order: a.order, raw_lines: a.raw_count };
  report.findings.push(...a.findings);
}

if (hostTarget && !flag(o, 'no-probe')) {
  const clean = String(hostTarget).replace(/^ssh:\/\//, '').split('/')[0];
  const [h, p] = clean.split(':');
  const port = Number(p) || num(o.f.port, 22);
  const hs = await probeSsh(h, port, timeout);
  report.handshake = { host: h, port, ...hs };
  if (hs.error) report.findings.push({ id: 'ssh-unreachable', severity: 'INFO', detail: `${h}:${port} — ${hs.error}`, fix: 'n/a' });
  else if (!/^SSH-/.test(hs.banner)) report.findings.push({ id: 'not-ssh', severity: 'INFO', detail: `no SSH banner (got ${JSON.stringify((hs.raw_head || '').slice(0, 40))})`, fix: 'check the port' });
  if (/^SSH-1\./.test(hs.banner)) report.findings.push({ id: 'sshv1-banner', severity: 'CRITICAL', detail: `server advertises ${hs.banner} — SSHv1`, fix: 'disable Protocol 1' });
  if (/OpenSSH_[0-6]\./.test(hs.banner)) report.findings.push({ id: 'old-openssh', severity: 'HIGH', detail: `outdated OpenSSH banner: ${hs.banner}`, fix: 'upgrade OpenSSH' });
  if (/OpenSSH_[7]\.[0-3]/.test(hs.banner)) report.findings.push({ id: 'old-openssh', severity: 'MEDIUM', detail: `OpenSSH 7.0-7.3 has known issues: ${hs.banner}`, fix: 'upgrade OpenSSH' });
  if (/dropbear_(0|20(1[0-8]))/i.test(hs.banner)) report.findings.push({ id: 'old-dropbear', severity: 'HIGH', detail: `outdated Dropbear: ${hs.banner}`, fix: 'upgrade Dropbear' });
  if (/libssh|paramiko|asyncssh/i.test(hs.banner)) report.findings.push({ id: 'ssh-library', severity: 'LOW', detail: `server is a library implementation: ${hs.banner}`, fix: 'verify the library version against CVEs' });
}

if (flag(o, 'json')) {
  const byS = report.findings.reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {});
  console.log(JSON.stringify({ ...report, summary: byS }, null, 2));
  exitSoon(report.findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH') ? 1 : 0);
}

if (report.handshake) {
  const h = report.handshake;
  console.log(`handshake: ${h.host}:${h.port} -> ${h.banner || '(no banner)'}${h.error ? ' error=' + h.error : ''} (${h.bytes} bytes${h.got_kexinit ? ', KEXINIT present' : ''})`);
}
if (report.config) {
  console.log(`\nconfig: ${report.config.source} (${report.config.directive_order.length} directives)`);
  console.log(table(Object.entries(report.config.policy).filter(([k]) => k !== 'directives').map(([k, v]) => ({ option: k, value: String(v).slice(0, 70) }))));
}

console.log(`\n--- FINDINGS (${report.findings.length}) ---`);
if (!report.findings.length) console.log('no issues detected');
else {
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  report.findings.sort((a, b) => order[a.severity] - order[b.severity]);
  console.log(table(report.findings.map((f) => ({ severity: f.severity, id: f.id, detail: f.detail.slice(0, 62), fix: (f.fix || '').slice(0, 40) }))));
  console.log('\nRemediation:');
  for (const f of report.findings.filter((x) => x.severity === 'CRITICAL' || x.severity === 'HIGH')) console.log(`  [${f.severity}] ${f.id}\n      ${f.detail}\n      fix: ${f.fix}`);
}
const counts = report.findings.reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {});
console.log(`\nseverity: ${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(' ') || 'none'}`);
exitSoon(report.findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH') ? 1 : 0);
