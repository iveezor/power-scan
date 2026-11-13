'use strict';
/*
 * Linux platform module. Files: ClamAV (+ rkhunter if installed). Kernel: /proc/modules, /sys/module,
 * modinfo. Drivers: lspci, sysfs, fwupd and the package manager. Network: ip, iw, nmcli, resolvectl.
 * Anything that needs root runs through one pkexec (polkit) prompt with a script built from constants
 * and shell-quoted values.
 */
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const path = require('path');
const { run, exists, readText, shQuote, sleep } = require('../util');

const ENV = { ...process.env, LC_ALL: 'C', LANG: 'C' };
const sh = (cmd, args, opts = {}) => run(cmd, args, { env: ENV, ...opts });
const HOME = os.homedir();
const USER_QUARANTINE = path.join(HOME, '.local', 'share', 'power-scan', 'quarantine');
const ROOT_QUARANTINE = '/var/lib/power-scan/quarantine';
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const base = (p) => path.basename(String(p || ''));
const dirOf = (p) => { const b = base(p); return b ? String(p).slice(0, String(p).length - b.length) : ''; };

const tools = {};
async function has(tool) {
  if (tool in tools) return tools[tool];
  const r = await sh('sh', ['-c', 'command -v "$1"', 'sh', tool], { timeout: 5000 });
  tools[tool] = r.code === 0 ? r.stdout.trim() : null;
  return tools[tool];
}

/** Runs a /bin/sh script as root through polkit. */
async function root(script, opts = {}) {
  if (!(await has('pkexec'))) return { code: -1, stdout: '', stderr: 'pkexec is not installed', unavailable: true };
  const r = await sh('pkexec', ['/bin/sh', '-c', script], opts);
  return { ...r, cancelled: r.code === 126 || (r.code === 127 && /dismiss|not authorized|cancel/i.test(r.stderr)) };
}

function osRelease() {
  const out = {};
  for (const line of readText('/etc/os-release').split('\n')) {
    const m = line.match(/^(\w+)=("?)(.*)\2$/);
    if (m) out[m[1]] = m[3];
  }
  return out;
}

let pmCache;
async function packageManager() {
  if (pmCache !== undefined) return pmCache;
  if (await has('apt-get')) {
    pmCache = {
      name: 'apt', install: (p) => `sudo apt install ${p}`,
      upgradable: async () => (await sh('apt', ['list', '--upgradable'], { timeout: 60000 })).stdout.split('\n')
        .map((l) => l.match(/^([^/\s]+)\/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]/)).filter(Boolean)
        .map((m) => ({ name: m[1], to: m[2], from: m[3] })),
      upgrade: (pkgs) => `DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade ${pkgs.map(shQuote).join(' ')}`,
    };
  } else if (await has('dnf')) {
    pmCache = {
      name: 'dnf', install: (p) => `sudo dnf install ${p}`,
      upgradable: async () => (await sh('dnf', ['-q', 'check-update'], { timeout: 120000 })).stdout.split('\n')
        .map((l) => l.trim().split(/\s+/)).filter((p) => p.length === 3 && /\./.test(p[0]))
        .map((p) => ({ name: p[0].replace(/\.[^.]+$/, ''), to: p[1], from: '' })),
      upgrade: (pkgs) => `dnf upgrade -y ${pkgs.map(shQuote).join(' ')}`,
    };
  } else if (await has('zypper')) {
    pmCache = {
      name: 'zypper', install: (p) => `sudo zypper install ${p}`,
      upgradable: async () => (await sh('zypper', ['-q', 'lu'], { timeout: 120000 })).stdout.split('\n')
        .map((l) => l.split('|').map((x) => x.trim())).filter((c) => c.length >= 6 && c[2] && c[2] !== 'Name')
        .map((c) => ({ name: c[2], from: c[3], to: c[4] })),
      upgrade: (pkgs) => `zypper --non-interactive update ${pkgs.map(shQuote).join(' ')}`,
    };
  } else if (await has('pacman')) {
    pmCache = {
      name: 'pacman', install: (p) => `sudo pacman -S ${p}`,
      upgradable: async () => {
        const tool = (await has('checkupdates')) ? 'checkupdates' : null;
        if (!tool) return [];
        return (await sh(tool, [], { timeout: 120000 })).stdout.split('\n').map((l) => l.match(/^(\S+) (\S+) -> (\S+)/)).filter(Boolean)
          .map((m) => ({ name: m[1], from: m[2], to: m[3] }));
      },
      upgrade: null, // Arch does not support partial upgrades; the user runs pacman -Syu.
    };
  } else pmCache = null;
  return pmCache;
}

async function info() {
  const [clam, clamd, rkh, fwupd, pk] = await Promise.all(['clamscan', 'clamdscan', 'rkhunter', 'fwupdmgr', 'pkexec'].map(has));
  const pm = await packageManager();
  const lock = (readText('/sys/kernel/security/lockdown').match(/\[(\w+)\]/) || [])[1] || null;
  let ver = '';
  if (clam) ver = ((await sh(clam, ['--version'], { timeout: 20000 })).stdout.match(/ClamAV ([\d.]+)/) || [])[1] || '';
  const notes = [];
  const install = (p) => (pm ? pm.install(p) : `install ${p} with your package manager`);
  if (!clam) notes.push(`ClamAV is not installed, so the file pass and Traffic cannot check files. Install it with: ${install('clamav')}`);
  if (!pk) notes.push('pkexec (polkit) is not installed, so Power Scan cannot make changes that need administrator rights.');
  const os_ = osRelease();
  return {
    platform: 'linux',
    osName: os_.PRETTY_NAME || 'Linux',
    engineLabel: clam ? `ClamAV ${ver}${rkh ? ' · rkhunter' : ''}` : 'ClamAV not installed',
    fileScanner: !!clam,
    glance: [
      ['Kernel lockdown', lock ? lock[0].toUpperCase() + lock.slice(1) : 'Unknown', lock && lock !== 'none' ? 'ok' : 'warn'],
      ['Virus scanner', clam ? `ClamAV ${ver}` : 'Not installed', clam ? 'ok' : 'warn'],
    ],
    driverSource: `Source · ${fwupd ? 'fwupd + ' : ''}${pm ? pm.name : 'packages'}`,
    driverGlance: [
      ['Update source', `${fwupd ? 'fwupd + ' : ''}${pm ? pm.name : 'packages'}`, pm ? 'ok' : 'warn'],
      ['Undo', 'Old kernel kept in boot menu', 'ok'],
    ],
    restoreOn: false,
    notes,
    tools: { clamscan: !!clam, clamdscan: !!clamd, rkhunter: !!rkh, fwupdmgr: !!fwupd, pkexec: !!pk },
  };
}

/* ======================= scan passes ======================= */

async function kernel(ctx) {
  const mods = readText('/proc/modules').split('\n').filter(Boolean).map((l) => ({ name: l.split(' ')[0], taint: (l.match(/\(([A-Z]+)\)\s*$/) || [])[1] || '' }));
  const loaded = new Set(mods.map((m) => m.name));
  let sysmods = [];
  try { sysmods = (await fsp.readdir('/sys/module')).filter((m) => exists(`/sys/module/${m}/initstate`)); } catch (_) { /* no sysfs */ }
  const hidden = sysmods.filter((m) => !loaded.has(m));
  const total = mods.length + hidden.length || 1;
  let done = 0;
  const queue = mods.slice();
  const worker = async () => {
    while (queue.length && !ctx.signal.aborted) {
      const m = queue.shift();
      const r = await sh('modinfo', [m.name], { timeout: 10000 });
      const field = (k) => ((r.stdout.match(new RegExp(`^${k}:\\s*(.*)$`, 'm')) || [])[1] || '').trim();
      const signer = field('signer');
      const file = field('filename');
      const intree = field('intree') === 'Y';
      const unsigned = m.taint.includes('E');
      ctx.item({ file: m.name, sub: unsigned ? 'not signed' : `${intree ? 'in-tree' : 'out-of-tree'}${signer ? ' · signed' : ''}`, tone: unsigned ? 'bad' : '' });
      ctx.count(1);
      ctx.progress(++done / total);
      if (unsigned) {
        ctx.finding({
          kind: 'driver', sev: 'Medium', name: 'Unsigned kernel module', path: file || m.name,
          what: `The kernel module "${m.name}" is loaded without a valid signature. Some legitimate drivers (for example graphics or virtualization drivers built on this computer) do this, so check that you recognise it.`,
          primary: { action: 'remove', label: 'Disable' }, secondary: { action: 'keep', label: 'Keep' },
          confirm: { title: `Disable ${m.name}?`, body: 'Power Scan unloads the module and blacklists it so it does not load again. Linux asks for your password. Delete the file in /etc/modprobe.d to undo it.' },
          restart: true, key: 'module:' + m.name, data: { root: `modprobe -r ${shQuote(m.name)} 2>/dev/null; echo blacklist ${shQuote(m.name)} > /etc/modprobe.d/power-scan-blacklist-${m.name.replace(/[^\w-]/g, '')}.conf` },
        });
      }
    }
  };
  await Promise.all(Array.from({ length: 6 }, worker));
  for (const h of hidden) {
    ctx.item({ file: h, sub: 'hidden from /proc/modules', tone: 'bad' });
    ctx.count(1);
    ctx.finding({
      kind: 'driver', sev: 'Severe', name: 'Hidden kernel module', path: `/sys/module/${h}`,
      what: `The module "${h}" is loaded but hides itself from the module list. Rootkits do this. Remove it by booting from a rescue USB and scanning the disk, then reinstalling the affected system if it is confirmed.`,
      primary: null, secondary: { action: 'keep', label: 'Dismiss' }, key: 'hidden-module:' + h, data: {},
    });
  }
  const taint = parseInt(readText('/proc/sys/kernel/tainted').trim() || '0', 10);
  ctx.item({ file: 'Kernel taint flags', sub: taint ? String(taint) : '0 · clean', tone: taint & (1 << 13) ? 'bad' : '' });
}

async function boot(ctx) {
  let sb = null;
  if (await has('mokutil')) {
    const r = await sh('mokutil', ['--sb-state'], { timeout: 10000 });
    sb = /enabled/i.test(r.stdout) ? true : /disabled/i.test(r.stdout) ? false : null;
  }
  const lock = (readText('/sys/kernel/security/lockdown').match(/\[(\w+)\]/) || [])[1] || 'unknown';
  const sig = readText('/sys/module/module/parameters/sig_enforce').trim();
  const preload = readText('/etc/ld.so.preload').trim();
  const lines = [
    ['Secure Boot', sb === true ? 'enabled' : sb === false ? 'disabled' : 'unknown', sb === false],
    ['Kernel lockdown', lock, false],
    ['Module signatures', sig === 'Y' ? 'enforced' : sig === 'N' ? 'not enforced' : 'unknown', false],
    ['/etc/ld.so.preload', preload ? preload.split('\n').join(', ') : 'empty', !!preload],
  ];
  lines.forEach(([file, sub, bad], i) => { ctx.item({ file, sub, tone: bad ? 'bad' : '' }); ctx.count(1); ctx.progress((i + 1) / lines.length); });
  if (sb === false) {
    ctx.finding({
      kind: 'boot', sev: 'Medium', name: 'Secure Boot is off', path: 'Firmware (UEFI) setting',
      what: "Code that runs before Linux starts is not checked. Turn Secure Boot on in your computer's UEFI settings if your distribution supports it.",
      primary: null, secondary: { action: 'keep', label: 'Dismiss' }, key: 'boot:secureboot', data: {},
    });
  }
  if (preload) {
    ctx.finding({
      kind: 'startup', sev: 'High', name: 'Libraries are injected into every program', path: '/etc/ld.so.preload',
      what: `/etc/ld.so.preload loads ${preload.split('\n').join(', ')} into every program. Rootkits use it to hide.`,
      primary: { action: 'remove', label: 'Remove' }, secondary: { action: 'keep', label: 'Keep' },
      confirm: { title: 'Remove /etc/ld.so.preload?', body: 'Power Scan moves the file to quarantine. Linux asks for your password.' },
      key: 'preload:' + preload, data: { rootQuarantine: '/etc/ld.so.preload' },
    });
  }
}

const SUSPICIOUS_PATH = /^\/(tmp|dev\/shm|var\/tmp)\//;
const PIPE_TO_SHELL = /(curl|wget)[^|\n]*\|\s*(ba|z|da)?sh\b/;

function desktopExec(text) {
  const m = text.match(/^Exec=(.*)$/m);
  if (!m) return '';
  return m[1].trim().replace(/^"([^"]+)".*/, '$1').split(/\s+/)[0];
}

async function startup(ctx) {
  const entries = [];
  const userAuto = path.join(HOME, '.config', 'autostart');
  for (const [dir, scope] of [[userAuto, 'user'], ['/etc/xdg/autostart', 'system']]) {
    let names = [];
    try { names = await fsp.readdir(dir); } catch (_) { continue; }
    for (const n of names.filter((x) => x.endsWith('.desktop'))) {
      const file = path.join(dir, n);
      const exe = desktopExec(readText(file));
      const bad = n.startsWith('.') || base(exe).startsWith('.') || SUSPICIOUS_PATH.test(exe);
      entries.push({ where: `Autostart (${scope})`, name: n, exe, bad, kind: 'autostart', scope, file });
    }
  }
  const unitDirs = [['/etc/systemd/system', 'system'], [path.join(HOME, '.config', 'systemd', 'user'), 'user']];
  for (const [dir, scope] of unitDirs) {
    let names = [];
    try { names = await fsp.readdir(dir); } catch (_) { continue; }
    for (const n of names.filter((x) => x.endsWith('.service'))) {
      const file = path.join(dir, n);
      let real = file;
      try { real = await fsp.realpath(file); } catch (_) { /* broken link */ }
      const text = readText(real);
      const exe = ((text.match(/^ExecStart=[-@+!:]*(\S+)/m) || [])[1] || '');
      const bad = SUSPICIOUS_PATH.test(exe) || base(exe).startsWith('.') || PIPE_TO_SHELL.test(text);
      entries.push({ where: `systemd (${scope})`, name: n, exe, bad, kind: 'unit', scope, file });
    }
  }
  const cronTexts = [];
  if (await has('crontab')) cronTexts.push(['your crontab', (await sh('crontab', ['-l'], { timeout: 10000 })).stdout]);
  cronTexts.push(['/etc/crontab', readText('/etc/crontab')]);
  try { for (const n of await fsp.readdir('/etc/cron.d')) cronTexts.push([`/etc/cron.d/${n}`, readText(`/etc/cron.d/${n}`)]); } catch (_) { /* none */ }
  for (const [where, text] of cronTexts) {
    const lines = text.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
    const badLine = lines.find((l) => PIPE_TO_SHELL.test(l) || /\s\/(tmp|dev\/shm)\//.test(l));
    entries.push({ where: 'cron', name: where, exe: badLine || `${plural(lines.length, 'job')}`, bad: !!badLine, kind: 'cron' });
  }
  for (const n of ['.bashrc', '.profile', '.bash_profile', '.zshrc']) {
    const text = readText(path.join(HOME, n));
    if (!text) continue;
    const badLine = text.split('\n').find((l) => !l.trim().startsWith('#') && (PIPE_TO_SHELL.test(l) || /LD_PRELOAD=/.test(l)));
    entries.push({ where: 'shell profile', name: `~/${n}`, exe: badLine || 'no changes found', bad: !!badLine, kind: 'profile' });
  }
  entries.forEach((e, i) => {
    ctx.item({ file: `${e.where}: ${e.name}`, sub: e.bad ? 'suspicious' : base(e.exe) || e.exe, tone: e.bad ? 'bad' : '' });
    ctx.count(1);
    ctx.progress((i + 1) / entries.length);
    if (!e.bad) return;
    let data = {};
    let primary = { action: 'remove', label: 'Remove from startup' };
    let body = 'Power Scan moves the startup entry to quarantine so it can be put back.';
    if (e.kind === 'autostart') data = e.scope === 'user' ? { userQuarantine: e.file } : { rootQuarantine: e.file };
    else if (e.kind === 'unit') {
      data = e.scope === 'user'
        ? { userUnit: e.name, userQuarantine: e.file }
        : { root: `systemctl disable --now ${shQuote(e.name)}; mkdir -p ${ROOT_QUARANTINE}; mv -- ${shQuote(e.file)} ${ROOT_QUARANTINE}/; systemctl daemon-reload` };
      body = 'Power Scan stops and disables the service, then moves its file to quarantine.' + (e.scope === 'system' ? ' Linux asks for your password.' : '');
    } else {
      primary = null;
      body = '';
    }
    if (data.rootQuarantine) body += ' Linux asks for your password.';
    ctx.finding({
      kind: 'startup', sev: 'High',
      name: e.kind === 'cron' || e.kind === 'profile' ? `Suspicious command in ${e.name}` : 'Suspicious program starts automatically',
      path: e.kind === 'cron' || e.kind === 'profile' ? e.exe.trim() : e.exe || e.file,
      what: e.kind === 'cron' || e.kind === 'profile'
        ? `This line downloads and runs code, or loads code into other programs. Open ${e.name} in a text editor and delete it if you did not add it.`
        : `${e.where} "${e.name}" starts a program from a temporary or hidden location. Malware often hides there.`,
      primary, secondary: { action: 'keep', label: primary ? 'Keep' : 'Dismiss' },
      confirm: primary ? { title: `Stop "${e.name}" from starting?`, body } : null,
      key: 'startup:' + e.kind + ':' + (e.file || e.name) + ':' + e.exe, data,
    });
  });
}

async function processes(ctx) {
  let pids = [];
  try { pids = (await fsp.readdir('/proc')).filter((d) => /^\d+$/.test(d)); } catch (_) { return; }
  const psList = async () => new Set((await sh('ps', ['-e', '-o', 'pid='], { timeout: 10000 })).stdout.split(/\s+/).filter(Boolean));
  const listed = await psList();
  const byExe = new Map();
  let suspectHidden = [];
  for (const pid of pids) {
    let exe;
    try { exe = await fsp.readlink(`/proc/${pid}/exe`); } catch (_) { continue; }
    if (!listed.has(pid)) suspectHidden.push(pid);
    const g = byExe.get(exe) || { exe, pids: [], name: readText(`/proc/${pid}/comm`).trim() };
    g.pids.push(Number(pid));
    byExe.set(exe, g);
  }
  if (suspectHidden.length) {
    const again = await psList();
    suspectHidden = suspectHidden.filter((p) => exists(`/proc/${p}`) && !again.has(p));
  }
  const groups = [...byExe.values()];
  groups.forEach((g, i) => {
    ctx.count(1);
    ctx.progress((i + 1) / groups.length);
    const deleted = g.exe.endsWith(' (deleted)');
    const real = g.exe.replace(/ \(deleted\)$/, '');
    const replaced = deleted && exists(real);
    const tmp = SUSPICIOUS_PATH.test(real);
    const hidden = g.pids.some((p) => suspectHidden.includes(String(p)));
    const bad = (deleted && !replaced) || tmp || hidden;
    ctx.item({ dir: dirOf(real), file: base(real), sub: hidden ? 'hidden from ps' : deleted ? (replaced ? 'updated since start' : 'file deleted') : tmp ? 'runs from a temp folder' : '', tone: bad ? 'bad' : '' });
    if (!bad) return;
    ctx.finding({
      kind: 'process', sev: hidden ? 'Severe' : 'High',
      name: hidden ? 'Program hidden from the process list' : tmp ? 'Program running from a temporary folder' : 'Program running from a deleted file',
      path: real,
      what: hidden ? 'This program runs but does not show up in ps. Rootkits hide programs this way.' : tmp ? 'Programs rarely run from /tmp or /dev/shm. Malware does this to avoid leaving files behind.' : 'This program is running but its file is gone from disk. Malware does this to avoid being scanned.',
      primary: { action: 'remove', label: tmp ? 'End and quarantine' : 'End it' }, secondary: { action: 'keep', label: 'Keep' },
      confirm: { title: `End ${g.name || base(real)}?`, body: 'Power Scan closes the program' + (tmp ? ' and moves its file to quarantine.' : '.') + ' Programs owned by another user need your password.' },
      key: 'process:' + real, data: { pids: g.pids, quarantine: tmp ? real : null },
    });
  });
}

async function estimateFiles() {
  const r = await sh('df', ['--output=iused,fstype', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs', '-x', 'overlay'], { timeout: 10000 });
  const n = r.stdout.split('\n').slice(1).map((l) => parseInt(l, 10)).filter((x) => x > 0).reduce((a, b) => a + b, 0);
  return n > 1000 ? Math.round(n * 0.85) : 400000;
}

async function files(ctx) {
  const clam = await has('clamscan');
  if (!clam) {
    const pm = await packageManager();
    ctx.note('warn', `ClamAV is not installed, so the file pass was skipped. Install it with: ${pm ? pm.install('clamav') : 'your package manager'}`);
    return;
  }
  const estimate = await estimateFiles();
  const excludes = ['^/proc', '^/sys', '^/dev', '^/run', '^/snap', '^' + ROOT_QUARANTINE];
  const clamArgs = ['-r', '--stdout', '--no-summary', ...excludes.map((e) => `--exclude-dir=${e}`), '/'];
  const rkh = await has('rkhunter');
  const script = `${shQuote(clam)} ${clamArgs.map(shQuote).join(' ')}; echo __POWERSCAN_RKH__; ${rkh ? `${shQuote(rkh)} --check --sk --nocolors --rwo 2>&1` : 'true'}`;
  let scanned = 0;
  let section = 'clam';
  let warning = null;
  const flushWarning = () => {
    if (!warning) return;
    ctx.finding({
      kind: 'rootkit', sev: 'Medium', name: 'rkhunter warning', path: warning.slice(0, 160),
      what: `rkhunter reported: ${warning}. Many of these are harmless after system updates; check it if it mentions a file you did not change.`,
      primary: null, secondary: { action: 'keep', label: 'Dismiss' }, key: 'rkh:' + warning, data: {},
    });
    warning = null;
  };
  const onLine = (line) => {
    if (line === '__POWERSCAN_RKH__') { section = 'rkh'; ctx.item({ file: 'Checking for known rootkits (rkhunter)', sub: '' }); return; }
    if (section === 'rkh') {
      if (/^Warning:/i.test(line)) { flushWarning(); warning = line.replace(/^Warning:\s*/i, ''); }
      else if (warning && /^\s+\S/.test(line)) warning += ' ' + line.trim();
      return;
    }
    const m = line.match(/^(.*): (.+) FOUND$/);
    if (m) {
      scanned++;
      ctx.item({ dir: dirOf(m[1]), file: base(m[1]), sub: m[2], tone: 'bad' });
      ctx.finding({
        kind: 'file', sev: /PUA|Adware/i.test(m[2]) ? 'Low' : 'High', name: m[2], path: m[1],
        what: 'ClamAV matched this file to a known malware signature.',
        primary: { action: 'remove', label: 'Remove' }, secondary: { action: 'keep', label: 'Keep' },
        confirm: { title: `Remove ${m[2]}?`, body: 'Power Scan moves the file to quarantine and removes all its permissions. Files outside your home folder need your password.' },
        key: 'threat:' + m[2] + ':' + m[1], data: { file: m[1] },
      });
    } else if (/^\//.test(line)) {
      scanned++;
      const p = line.replace(/: (OK|Empty file|Symbolic link|Excluded|Access denied)$/, '');
      ctx.item({ dir: dirOf(p), file: base(p), sub: '' });
    }
    if (scanned % 200 === 0) ctx.progress(Math.min(0.99, scanned / estimate), scanned);
  };
  let r = await root(script, { signal: ctx.signal, collect: false, onLine });
  if (r.unavailable || r.cancelled) {
    ctx.note('warn', 'Scanning as your user because administrator access was not given, so some system files could not be read.');
    section = 'clam';
    r = await sh(clam, clamArgs, { signal: ctx.signal, collect: false, onLine });
  }
  flushWarning();
  if (!ctx.signal.aborted) ctx.progress(1, scanned);
}

async function quarantineAsUser(file) {
  try {
    fs.mkdirSync(USER_QUARANTINE, { recursive: true, mode: 0o700 });
    const dest = path.join(USER_QUARANTINE, `${Date.now()}_${base(file)}.quarantined`);
    fs.renameSync(file, dest);
    fs.chmodSync(dest, 0o000);
    return { ok: true, dest };
  } catch (e) { return { ok: false, code: e.code }; }
}

function rootQuarantineScript(file) {
  const dest = `${ROOT_QUARANTINE}/${Date.now()}_${base(file).replace(/[^\w.-]/g, '_')}.quarantined`;
  return `mkdir -p ${ROOT_QUARANTINE} && chmod 700 ${ROOT_QUARANTINE} && mv -- ${shQuote(file)} ${shQuote(dest)} && chmod 000 ${shQuote(dest)}`;
}

async function remove(f) {
  const d = f.data || {};
  const viaRoot = async (script, okText) => {
    const r = await root(script);
    if (r.cancelled) return { state: 'open', message: 'This change needs your password.' };
    if (r.unavailable) return { state: 'failed', message: 'pkexec is not installed, so Power Scan cannot get administrator access.' };
    return r.code === 0 ? { state: f.restart ? 'removed-restart' : 'removed', message: okText } : { state: 'failed', message: (r.stderr || 'The change did not finish.').trim().split('\n').pop() };
  };
  if (f.kind === 'file') {
    const q = await quarantineAsUser(d.file);
    if (q.ok) return { state: 'removed', message: 'Moved to quarantine', backup: { from: d.file, to: q.dest } };
    return viaRoot(rootQuarantineScript(d.file), 'Moved to quarantine');
  }
  if (f.kind === 'process') {
    let all = true;
    for (const pid of d.pids || []) { try { process.kill(pid, 'SIGKILL'); } catch (_) { all = false; } }
    if (!all) {
      const r = await viaRoot(`kill -9 ${(d.pids || []).map((p) => Number(p)).join(' ')}`, 'Ended');
      if (r.state !== 'removed') return r;
    }
    if (d.quarantine) {
      const q = await quarantineAsUser(d.quarantine);
      if (!q.ok) return viaRoot(rootQuarantineScript(d.quarantine), 'Ended · file moved to quarantine');
      return { state: 'removed', message: 'Ended · file moved to quarantine' };
    }
    return { state: 'removed', message: 'Ended' };
  }
  if (d.userUnit) await sh('systemctl', ['--user', 'disable', '--now', d.userUnit], { timeout: 30000 });
  if (d.userQuarantine) {
    const q = await quarantineAsUser(d.userQuarantine);
    return q.ok ? { state: 'removed', message: 'Removed from startup · kept in quarantine', backup: { from: d.userQuarantine, to: q.dest } } : { state: 'failed', message: 'Could not move the file.' };
  }
  if (d.rootQuarantine) return viaRoot(rootQuarantineScript(d.rootQuarantine), 'Moved to quarantine');
  if (d.root) return viaRoot(d.root, f.restart ? 'Done · takes effect after restart' : 'Done');
  return { state: 'failed', message: 'Nothing to change automatically.' };
}

/* ======================= Traffic ======================= */
const originalModes = new Map();
async function hold(file) {
  try {
    const st = fs.statSync(file);
    originalModes.set(file, st.mode & 0o7777);
    if (st.mode & 0o111) fs.chmodSync(file, st.mode & 0o7666);
    return true;
  } catch (_) { return false; }
}
async function release(file) {
  const mode = originalModes.get(file);
  originalModes.delete(file);
  try { if (mode != null && mode & 0o111) fs.chmodSync(file, mode); return true; } catch (_) { return false; }
}
async function check(file, signal) {
  const clamd = await has('clamdscan');
  const clam = await has('clamscan');
  if (!clam && !clamd) return { clean: false, error: 'ClamAV is not installed, so this file was not checked.' };
  let r = clamd ? await sh(clamd, ['--no-summary', '--stdout', '--fdpass', file], { signal, timeout: 120000 }) : null;
  if (!r || r.code === 2 || r.code < 0) r = clam ? await sh(clam, ['--no-summary', '--stdout', file], { signal, timeout: 300000 }) : r;
  const m = r.stdout.match(/: (.+) FOUND\s*$/m);
  if (m) return { clean: false, threat: m[1], what: 'ClamAV matched this file to a known malware signature.' };
  if (r.code === 0) return { clean: true };
  return { clean: false, error: 'ClamAV could not check this file.' };
}
async function removeHeld(file) {
  const q = await quarantineAsUser(file);
  return q.ok ? { ok: true, message: 'Moved to quarantine · it never ran' } : { ok: false, message: 'Could not move it.' };
}

/* ======================= network ======================= */
async function netInfo() {
  const route = (await sh('ip', ['route', 'show', 'default'], { timeout: 5000 })).stdout.split('\n')[0] || '';
  const gw = (route.match(/via (\S+)/) || [])[1] || null;
  const dev = (route.match(/dev (\S+)/) || [])[1] || null;
  if (!dev) return { connected: false };
  const isWifi = exists(`/sys/class/net/${dev}/wireless`) || exists(`/sys/class/net/${dev}/phy80211`);
  let signal = null, powerSaving = null;
  if (isWifi && (await has('iw'))) {
    const link = (await sh('iw', ['dev', dev, 'link'], { timeout: 5000 })).stdout;
    const dbm = (link.match(/signal:\s*(-?\d+)/) || [])[1];
    if (dbm != null) signal = Math.max(0, Math.min(100, 2 * (Number(dbm) + 100)));
    const ps = (await sh('iw', ['dev', dev, 'get', 'power_save'], { timeout: 5000 })).stdout;
    powerSaving = /:\s*on/i.test(ps) ? true : /:\s*off/i.test(ps) ? false : null;
  }
  let dnsServers = [];
  if (await has('resolvectl')) {
    const r = await sh('resolvectl', ['dns', dev], { timeout: 5000 });
    dnsServers = (r.stdout.split(':').slice(1).join(':').match(/\d+\.\d+\.\d+\.\d+/g) || []);
  }
  if (!dnsServers.length) dnsServers = (readText('/etc/resolv.conf').match(/^nameserver\s+(\d+\.\d+\.\d+\.\d+)/gm) || []).map((l) => l.split(/\s+/)[1]);
  let connection = null;
  if (await has('nmcli')) {
    const r = await sh('nmcli', ['-t', '-f', 'NAME,DEVICE', 'connection', 'show', '--active'], { timeout: 5000 });
    for (const line of r.stdout.split('\n')) {
      const parts = line.split(/(?<!\\):/);
      if (parts[1] === dev) connection = parts[0].replace(/\\:/g, ':');
    }
  }
  return { connected: true, gateway: gw, adapter: dev, connection, isWifi, signal, powerSaving, dns: dnsServers };
}

async function ping(ip) {
  const r = await sh('ping', ['-c', '1', '-W', '1', ip], { timeout: 3000 });
  const ok = r.code === 0 && /ttl=/i.test(r.stdout);
  const m = r.stdout.match(/time[=<]([\d.]+)\s*ms/);
  return { ok, ms: ok ? Math.max(1, Math.round(m ? Number(m[1]) : 1)) : null };
}

const FIX = {
  power: { label: 'Turn off Wi-Fi power saving', cmd: (n) => `iw dev ${n.adapter} set power_save off`, script: (n) => `iw dev ${shQuote(n.adapter)} set power_save off; mkdir -p /etc/NetworkManager/conf.d && printf '[connection]\\nwifi.powersave = 2\\n' > /etc/NetworkManager/conf.d/99-power-scan-wifi-powersave.conf` },
  flush: { label: 'Clear the DNS cache', cmd: () => 'resolvectl flush-caches', script: () => 'resolvectl flush-caches 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null || true' },
  dns: { label: 'Use faster DNS (Cloudflare 1.1.1.1)', cmd: (n) => `nmcli con mod "${n.connection}" ipv4.dns "1.1.1.1 1.0.0.1"`, script: (n) => `nmcli con mod ${shQuote(n.connection)} ipv4.dns '1.1.1.1 1.0.0.1' ipv4.ignore-auto-dns yes && nmcli con up ${shQuote(n.connection)}`, needs: 'connection' },
  renew: { label: 'Renew the IP address', cmd: (n) => `nmcli con up "${n.connection}"`, script: (n) => `nmcli con up ${shQuote(n.connection)}`, needs: 'connection' },
  reset: { label: 'Restart the network adapter', cmd: (n) => (n.isWifi ? 'nmcli radio wifi off && nmcli radio wifi on' : `nmcli dev disconnect ${n.adapter} && nmcli dev connect ${n.adapter}`), script: (n) => (n.isWifi ? 'nmcli radio wifi off; sleep 2; nmcli radio wifi on' : `nmcli dev disconnect ${shQuote(n.adapter)}; sleep 2; nmcli dev connect ${shQuote(n.adapter)}`) },
};
const ORDER = ['power', 'flush', 'dns', 'renew', 'reset'];
const usable = (id, n) => FIX[id] && (!FIX[id].needs || n[FIX[id].needs]);

function fixDefs(ids, n) {
  return ORDER.filter((id) => ids.includes(id) && usable(id, n)).map((id) => ({ id, label: FIX[id].label, cmd: FIX[id].cmd(n) }));
}

async function applyFixes(ids, n, onStep) {
  const chosen = ORDER.filter((id) => ids.includes(id) && usable(id, n));
  let previous = null;
  if (chosen.includes('dns') && n.connection) {
    const r = await sh('nmcli', ['-g', 'ipv4.dns,ipv4.ignore-auto-dns', 'connection', 'show', n.connection], { timeout: 5000 });
    const [dnsLine = '', ignore = 'no'] = r.stdout.split('\n');
    previous = { servers: dnsLine.split(/[,\s]+/).filter(Boolean), ignoreAuto: /yes/.test(ignore) };
  }
  const script = chosen.map((id) => `echo __STEP__ ${id}; (${FIX[id].script(n)}) >/dev/null 2>&1; echo __RESULT__ ${id} $?`).join('\n');
  const results = [];
  const r = await root(script, {
    onLine: (line) => {
      const s = line.match(/^__STEP__ (\w+)/);
      if (s) onStep(s[1], 'running');
      const x = line.match(/^__RESULT__ (\w+) (\d+)/);
      if (x) results.push({ id: x[1], ok: x[2] === '0', message: x[2] === '0' ? '' : `exit ${x[2]}` });
    },
  });
  if (r.cancelled || r.unavailable) return { cancelled: true, results: [] };
  return { cancelled: false, results: chosen.map((id) => results.find((x) => x.id === id) || { id, ok: false, message: 'Did not run' }), dnsPrevious: previous };
}

async function undoDns(n, previous) {
  if (!n.connection) return { ok: false };
  const servers = (previous && previous.servers) || [];
  const r = await sh('nmcli', ['con', 'mod', n.connection, 'ipv4.dns', servers.join(' '), 'ipv4.ignore-auto-dns', previous && previous.ignoreAuto ? 'yes' : 'no'], { timeout: 15000 });
  if (r.code === 0) await sh('nmcli', ['con', 'up', n.connection], { timeout: 30000 });
  return { ok: r.code === 0 };
}

/* ======================= drivers ======================= */
const IMPORTANT_CLASS = /(Network|Ethernet|VGA|3D|Display|Audio|Multimedia|Bluetooth|Wireless|USB controller|Non-Volatile|SATA|Thunderbolt|Camera)/i;
const catOfClass = (c) => (/VGA|3D|Display/i.test(c) ? 'display' : /Network|Ethernet|Wireless|Bluetooth/i.test(c) ? 'net' : /Audio|Multimedia/i.test(c) ? 'audio' : 'chip');
const PKG_RE = /^(linux-image|linux-modules|linux-firmware|linux-generic|linux-lts|linux|kernel|kernel-core|kernel-modules|firmware-[\w-]+|[\w-]*-firmware|nvidia[\w-]*|mesa[\w-]*|libgl1-mesa[\w-]*|xserver-xorg-video-[\w-]+|intel-media[\w-]*)(:|$)/;
const pkgLabel = (name) => (/^linux-firmware|firmware/.test(name) ? 'Device firmware' : /^(linux|kernel)/.test(name) ? 'Linux kernel' : /^nvidia/.test(name) ? 'NVIDIA driver' : /mesa|xserver-xorg-video|intel-media/.test(name) ? 'Graphics drivers (Mesa)' : name);
const PATTERNS = [
  { key: 'gpu', re: /(GPU HANG|gpu hang|ring \w+ timeout|amdgpu.*(timeout|reset)|NVRM: Xid|i915.*(reset|hang)|xe .*(reset|timeout))/i, label: 'GPU hangs or resets', cat: 'display' },
  { key: 'wifi', re: /(iwlwifi.*(Microcode SW error|FW error|firmware.*crash|Hardware error)|ath1[012]k.*(firmware crashed|failed to)|mt79\w*.*(reset|timeout|error)|rtw8\w*.*(failed|error))/i, label: 'Wi-Fi firmware crashes', cat: 'net' },
  { key: 'usb', re: /(usb \S+: reset|xhci_hcd.*(died|halt|error))/i, label: 'USB resets', cat: 'chip' },
  { key: 'nvme', re: /nvme\S*.*(timeout|reset controller|I\/O error)/i, label: 'Storage (NVMe) timeouts', cat: 'chip' },
  { key: 'audio', re: /(sof-audio.*(error|fail)|snd_hda_intel.*(timeout|azx_get_response))/i, label: 'Audio errors', cat: 'audio' },
];

async function driversInventory(ctx) {
  const st = ctx.state;
  st.devices = [];
  if (await has('lspci')) {
    const out = (await sh('lspci', ['-vmmk'], { timeout: 20000 })).stdout;
    for (const rec of out.split(/\n\s*\n/)) {
      const f = {};
      for (const line of rec.split('\n')) { const m = line.match(/^(\w+):\s*(.*)$/); if (m) f[m[1]] = m[2]; }
      if (!f.Slot) continue;
      st.devices.push({ id: 'pci:' + f.Slot, name: `${f.Vendor || ''} ${f.Device || ''}`.trim(), cls: f.Class || '', driver: f.Driver || '', module: f.Module || '' });
    }
  }
  try {
    for (const d of await fsp.readdir('/sys/bus/usb/devices')) {
      const dir = `/sys/bus/usb/devices/${d}`;
      const product = readText(`${dir}/product`).trim();
      if (!product || /^usb\d/.test(d) || d.includes(':')) continue;
      let driver = '';
      for (const sub of await fsp.readdir(dir).catch(() => [])) {
        if (sub.startsWith(d + ':')) { try { driver = base(await fsp.readlink(`${dir}/${sub}/driver`)); } catch (_) { /* no driver */ } if (driver) break; }
      }
      st.devices.push({ id: 'usb:' + d, name: product, cls: readText(`${dir}/bDeviceClass`).trim() === 'e0' ? 'Bluetooth' : 'USB device', driver, module: driver });
    }
  } catch (_) { /* no usb sysfs */ }
  st.modules = readText('/proc/modules').split('\n').filter(Boolean).length;
  st.devices.forEach((d, i) => {
    ctx.count(1);
    ctx.progress((i + 1) / st.devices.length);
    if (IMPORTANT_CLASS.test(d.cls)) ctx.item({ file: d.name, sub: d.driver || 'no driver' });
  });
  if (!st.devices.length) ctx.note('warn', 'lspci is not installed, so devices could not be listed. Install the "pciutils" package.');
}

async function driversVersions(ctx) {
  const st = ctx.state;
  st.pkgUpdates = [];
  st.fw = [];
  const pm = await packageManager();
  if (pm) {
    ctx.item({ file: `Checking ${pm.name} for driver and kernel updates`, sub: '' });
    const ups = await pm.upgradable().catch(() => []);
    st.pkgUpdates = ups.filter((u) => PKG_RE.test(u.name));
    for (const u of st.pkgUpdates) { ctx.item({ file: u.name, sub: `newer ${u.to}`, tone: 'warn' }); ctx.flag('pkg:' + u.name); }
  }
  ctx.progress(0.5);
  if (await has('fwupdmgr')) {
    ctx.item({ file: 'Checking fwupd for firmware updates', sub: '' });
    await sh('fwupdmgr', ['refresh', '--assume-yes'], { timeout: 120000 });
    const r = await sh('fwupdmgr', ['get-updates', '--json', '--assume-yes'], { timeout: 180000 });
    let data = null;
    try { data = JSON.parse(r.stdout); } catch (_) { data = null; }
    for (const dev of (data && data.Devices) || []) {
      const rel = (dev.Releases || [])[0];
      if (!rel) continue;
      st.fw.push({ id: dev.DeviceId, name: dev.Name, from: dev.Version, to: rel.Version, summary: rel.Summary || '', size: rel.Size || 0 });
      ctx.item({ file: dev.Name, sub: `firmware ${dev.Version} → ${rel.Version}`, tone: 'warn' });
      ctx.flag('fw:' + dev.DeviceId);
    }
  }
  if (!pm && !(await has('fwupdmgr'))) ctx.note('warn', 'No supported package manager or fwupd was found, so versions could not be compared.');
  ctx.progress(1);
}

async function driversHealth(ctx) {
  const st = ctx.state;
  st.noDriver = st.devices.filter((d) => IMPORTANT_CLASS.test(d.cls) && !d.driver && !/USB device/.test(d.cls));
  st.missingFw = [];
  const kernelLog = await readKernelLog('-b');
  for (const m of kernelLog.matchAll(/(?:Direct firmware load for (\S+) failed|firmware: failed to load (\S+))/g)) st.missingFw.push(m[1] || m[2]);
  st.missingFw = [...new Set(st.missingFw)];
  for (const d of st.noDriver) { ctx.item({ file: d.name, sub: 'no driver in use', tone: 'bad' }); ctx.flag(d.id); }
  for (const f of st.missingFw) { ctx.item({ file: f, sub: 'firmware file missing', tone: 'bad' }); ctx.flag('fwfile:' + f); }
  st.devices.filter((d) => d.driver && IMPORTANT_CLASS.test(d.cls)).forEach((d) => ctx.item({ file: d.name, sub: 'working' }));
  ctx.progress(1);
}

let logNoted = false;
async function readKernelLog(range) {
  let r = await sh('journalctl', ['-k', ...(range === '-b' ? ['-b'] : ['--since', '7 days ago']), '--no-pager', '-o', 'short'], { timeout: 60000 });
  if (r.code !== 0 || !r.stdout.trim()) r = await sh('dmesg', [], { timeout: 20000 });
  if ((r.code !== 0 || !r.stdout.trim()) && !logNoted) logNoted = true;
  return r.stdout || '';
}

async function driversPerformance(ctx) {
  const st = ctx.state;
  const log = await readKernelLog('7d');
  st.unstable = [];
  if (!log) ctx.note('warn', 'The kernel log could not be read, so crashes and resets were not counted. Adding your user to the "adm" or "systemd-journal" group allows it.');
  for (const p of PATTERNS) {
    const n = log.split('\n').filter((l) => p.re.test(l)).length;
    ctx.item({ file: p.label, sub: n ? `${n} in 7 days` : 'none in 7 days', tone: n >= 3 ? 'bad' : '' });
    if (n >= 3) { st.unstable.push({ ...p, n }); ctx.flag('perf:' + p.key); }
  }
  ctx.progress(1);
}

function driversFinish(ctx) {
  const st = ctx.state;
  const issues = [];
  const add = (o) => issues.push({ id: 'd' + issues.length, batch: true, ...o });
  const kernelUp = st.pkgUpdates.filter((u) => /^(linux|kernel)/.test(u.name) && !/firmware/.test(u.name));
  const fwPkg = st.pkgUpdates.filter((u) => /firmware/.test(u.name));
  const gfx = st.pkgUpdates.filter((u) => /nvidia|mesa|xserver-xorg-video|intel-media/.test(u.name));
  const pmName = (pmCache && pmCache.name) || 'your package manager';
  const canInstall = !!(pmCache && pmCache.upgrade);
  const isArch = !!(pmCache && pmCache.name === 'pacman');
  const pkgIssue = (list, cat, label, restart, extraFinds = []) => {
    if (!list.length) return;
    const pkgs = list.map((u) => u.name);
    add({
      cat, name: label, tag: extraFinds.length ? ['bad', 'Unstable'] : ['warn', 'Outdated'], kind: canInstall ? 'update' : 'review',
      meta: list.map((u) => `${u.name} ${u.from ? u.from + ' → ' : ''}${u.to}`).slice(0, 3).join(' · '),
      finds: [...extraFinds, ['up', `${plural(list.length, 'package')} can be updated from ${pmName}`]].concat(canInstall ? [] : [['info', isArch ? 'Arch Linux updates everything together. Run <b>sudo pacman -Syu</b> in a terminal.' : 'Update these packages with your package manager.']]),
      note: restart ? 'Takes effect after a restart. The current kernel stays in the boot menu.' : '',
      cmd: canInstall ? pmCache.upgrade(pkgs) : isArch ? 'sudo pacman -Syu' : '',
      steps: ['Downloading', 'Installing', restart ? 'Updating the boot menu' : 'Checking'],
      restart, doneText: restart ? 'Installed · restart to use it' : 'Updated',
      key: 'pkg:' + pkgs.join(',') + ':' + list.map((u) => u.to).join(','), data: { pkgs },
    });
  };
  const perf = (key) => st.unstable.filter((u) => u.cat === key || u.key === key).map((u) => ['bad', `<b>${u.n}</b> ${u.label.toLowerCase()} in the kernel log in 7 days`]);
  pkgIssue(kernelUp, 'chip', 'Linux kernel', true, perf('gpu').concat(perf('usb'), perf('nvme')));
  pkgIssue(fwPkg, 'net', 'Device firmware (linux-firmware)', false, perf('wifi').concat(perf('audio')));
  pkgIssue(gfx, 'display', 'Graphics drivers', false, kernelUp.length ? [] : perf('gpu'));
  for (const f of st.fw) {
    add({
      cat: 'chip', name: f.name, tag: ['warn', 'Firmware'], kind: 'update', meta: `fwupd · ${f.from} → ${f.to}`,
      finds: [['up', `Firmware <b>${f.to}</b> from the maker through fwupd`], ...(f.summary ? [['info', f.summary]] : [])],
      note: 'Keep the charger connected. Some firmware updates finish during a restart.', cmd: `fwupdmgr update ${f.id}`,
      steps: ['Downloading', 'Installing', 'Checking'], batch: false, restart: true, doneText: 'Firmware updated · restart if asked',
      key: 'fw:' + f.id + ':' + f.to, data: { fw: f.id },
    });
  }
  const covered = new Set(issues.flatMap((i) => i.finds.filter((x) => x[0] === 'bad').map((x) => x[1])));
  for (const u of st.unstable) {
    const text = `<b>${u.n}</b> ${u.label.toLowerCase()} in the kernel log in 7 days`;
    if (covered.has(text)) continue;
    add({
      cat: u.cat, name: u.label, tag: ['bad', 'Unstable'], kind: 'rollback', meta: 'kernel log',
      finds: [['bad', text], ['info', 'No update is waiting. If this started after an update, pick the previous kernel under "Advanced options" in the boot menu.']],
      note: '', steps: [], doneText: 'Steps shown', key: 'perf:' + u.key + ':' + u.n, data: {},
    });
  }
  for (const d of st.noDriver) {
    add({
      cat: catOfClass(d.cls), name: d.name, tag: ['bad', 'No driver'], kind: 'review', meta: `${d.cls} · ${d.id.replace(/^pci:/, 'PCI ')}`,
      finds: [['bad', 'No driver is handling this device'], ['info', (tools['ubuntu-drivers'] ? 'Run <b>ubuntu-drivers devices</b> to see recommended drivers.' : "Check your distribution's hardware support pages for a driver package.")]],
      note: '', steps: [], doneText: 'Steps shown', key: 'nodriver:' + d.id, data: {},
    });
  }
  for (const f of st.missingFw) {
    if (fwPkg.length) continue;
    add({
      cat: 'chip', name: `Missing firmware: ${base(f)}`, tag: ['bad', 'Not working'], kind: 'review', meta: f,
      finds: [['bad', 'The kernel asked for this firmware file and could not find it'], ['info', 'Install or reinstall your distribution\'s firmware package (for example linux-firmware or firmware-misc-nonfree).']],
      note: '', steps: [], doneText: 'Steps shown', key: 'fwfile:' + f, data: {},
    });
  }
  const healthy = st.devices.filter((d) => d.driver && IMPORTANT_CLASS.test(d.cls)).slice(0, 10).map((d) => [d.name, `${d.driver} · in use`]);
  return { issues, healthy, total: st.modules || st.devices.length, devices: st.devices.length };
}

async function driversApply(issues, _opts, onStep) {
  const parts = [];
  for (const i of issues) {
    let cmd = null;
    if (i.data.pkgs && pmCache && pmCache.upgrade) cmd = pmCache.upgrade(i.data.pkgs);
    if (i.data.fw) cmd = `fwupdmgr update ${shQuote(i.data.fw)} --assume-yes --no-reboot-check`;
    if (cmd) parts.push(`echo __STEP__ ${i.id}; (${cmd}) >/tmp/power-scan-${i.id}.log 2>&1; echo __RESULT__ ${i.id} $?`);
  }
  if (!parts.length) return { cancelled: false, results: issues.map((i) => ({ id: i.id, ok: false, message: 'Run the command shown in a terminal.' })) };
  const results = [];
  const r = await root(parts.join('\n'), {
    onLine: (line) => {
      const s = line.match(/^__STEP__ (\w+)/);
      if (s) onStep(s[1], 'Installing');
      const x = line.match(/^__RESULT__ (\w+) (\d+)/);
      if (x) results.push({ id: x[1], ok: x[2] === '0', message: x[2] === '0' ? '' : `Failed (exit ${x[2]}); see /tmp/power-scan-${x[1]}.log` });
    },
  });
  if (r.cancelled || r.unavailable) return { cancelled: true };
  return { cancelled: false, results: issues.map((i) => results.find((x) => x.id === i.id) || { id: i.id, ok: false, message: 'Did not run' }) };
}

async function driversRollback(issue) {
  return { ok: true, message: issue.kind === 'rollback' ? 'Restart, open "Advanced options" in the boot menu and pick the previous kernel' : 'See the steps above' };
}

module.exports = {
  info,
  scan: { kernel, boot, startup, processes, files, remove },
  traffic: { hold, release, check, remove: removeHeld, scannerName: 'ClamAV' },
  net: { info: netInfo, ping, fixDefs, applyFixes, undoDns, askText: 'Linux asks for your password once' },
  drivers: { inventory: driversInventory, versions: driversVersions, health: driversHealth, performance: driversPerformance, finish: driversFinish, apply: driversApply, rollback: driversRollback },
};
