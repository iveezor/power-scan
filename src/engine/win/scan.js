'use strict';
/* Windows scan passes. Each pass reports feed lines, progress and findings through ctx. */
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const path = require('path');
const ps = require('./ps');
const defender = require('./defender');
const { exists } = require('../util');

const base = (p) => path.basename(String(p || ''));
const dirOf = (p) => { const b = base(p); return b ? String(p).slice(0, String(p).length - b.length) : ''; };
const BAD_SIG = new Set(['NotSigned', 'HashMismatch', 'NotTrusted', 'Incompatible']);
const USER_DIRS = [os.homedir(), os.tmpdir(), path.join(process.env.SystemDrive || 'C:', 'Users', 'Public')]
  .filter(Boolean).map((d) => d.toLowerCase().replace(/\\+$/, '') + '\\');
const inUserDir = (p) => USER_DIRS.some((d) => String(p).toLowerCase().startsWith(d));

/* ---------- pass 1: kernel drivers ---------- */
async function kernel(ctx) {
  let total = 0, done = 0;
  await ps.stream('kernel.ps1', [], (o) => {
    if (o.type === 'count') { total = o.n; return; }
    if (o.type !== 'driver') return;
    done++;
    ctx.count(1);
    ctx.progress(total ? done / total : 0);
    const who = o.signer || o.company || '';
    const unsigned = o.exists && BAD_SIG.has(o.sig);
    const userDir = o.exists && inUserDir(o.path);
    const sub = !o.exists ? 'file not found' : unsigned ? (o.sig === 'HashMismatch' ? 'signature broken' : 'not signed') : (who ? who + ' · signed' : 'signed');
    ctx.item({ file: base(o.path) || o.name, sub, tone: unsigned || userDir ? 'bad' : '' });
    if (unsigned || userDir) {
      ctx.finding({
        kind: 'driver',
        sev: o.sig === 'HashMismatch' ? 'Severe' : 'High',
        name: unsigned ? (o.sig === 'HashMismatch' ? 'Tampered kernel driver' : 'Unsigned kernel driver') : 'Kernel driver loaded from a user folder',
        path: o.path,
        what: unsigned
          ? `${o.display || o.name} runs inside the Windows kernel without a valid signature. Windows normally refuses to load drivers like this.`
          : `${o.display || o.name} runs inside the Windows kernel from a folder that normal programs can write to.`,
        primary: { action: 'remove', label: 'Disable' },
        secondary: { action: 'keep', label: 'Keep' },
        confirm: { title: `Disable ${o.name}?`, body: 'Power Scan stops this driver from loading at the next restart. Windows asks for administrator permission first. You can turn it back on later with sc.exe.' },
        restart: true,
        key: 'driver:' + String(o.path).toLowerCase() + ':' + o.sig,
        data: { ops: [{ op: 'service-disable', name: o.name }] },
      });
    }
  }, { signal: ctx.signal, timeout: 15 * 60000 });
}

/* ---------- pass 2: boot integrity ---------- */
async function boot(ctx) {
  const { objs } = await ps.json('boot.ps1', [], { signal: ctx.signal, timeout: 60000 });
  const b = objs.find((o) => o.type === 'boot') || {};
  const onOff = (v) => (v === true ? 'on' : v === false ? 'off' : 'unknown');
  const lines = [
    ['Secure Boot', onOff(b.secureBoot), b.secureBoot === false],
    ['Memory integrity (HVCI)', onOff(b.hvci), false],
    ['Test-signing mode', b.testSigning ? 'ON' : 'off', b.testSigning],
    ['Driver signature checks', b.noIntegrity ? 'DISABLED' : 'on', b.noIntegrity],
    ['Early-launch anti-malware', b.elam ? 'WdBoot.sys present' : 'missing', !b.elam],
    ['Vulnerable driver blocklist', onOff(b.blocklist), false],
  ];
  lines.forEach(([file, sub, bad], i) => { ctx.item({ file, sub, tone: bad ? 'bad' : '' }); ctx.count(1); ctx.progress((i + 1) / lines.length); });
  if (b.testSigning) {
    ctx.finding({
      kind: 'boot', sev: 'High', name: 'Test-signing mode is on', path: 'Boot configuration (BCD)',
      what: 'Windows will load kernel drivers that are not properly signed. Rootkits turn this on so they can load.',
      primary: { action: 'remove', label: 'Turn off' }, secondary: { action: 'keep', label: 'Keep' },
      confirm: { title: 'Turn off test-signing mode?', body: 'Power Scan runs "bcdedit /set testsigning off". It takes effect after a restart. Windows asks for administrator permission first.' },
      restart: true, key: 'boot:testsigning', data: { ops: [{ op: 'bcd-testsigning-off' }] },
    });
  }
  if (b.noIntegrity) {
    ctx.finding({
      kind: 'boot', sev: 'High', name: 'Driver signature checks are off', path: 'Boot configuration (BCD)',
      what: 'Windows is set to skip signature checks on drivers, so unsigned kernel code can load.',
      primary: { action: 'remove', label: 'Turn on' }, secondary: { action: 'keep', label: 'Keep' },
      confirm: { title: 'Turn signature checks back on?', body: 'Power Scan runs "bcdedit /deletevalue nointegritychecks". It takes effect after a restart. Windows asks for administrator permission first.' },
      restart: true, key: 'boot:nointegrity', data: { ops: [{ op: 'bcd-integrity-on' }] },
    });
  }
  if (b.secureBoot === false) {
    ctx.finding({
      kind: 'boot', sev: 'Medium', name: 'Secure Boot is off', path: 'Firmware (UEFI) setting',
      what: 'Code that runs before Windows starts is not checked. Turn Secure Boot on in your computer\'s UEFI settings; Power Scan cannot change firmware settings.',
      primary: null, secondary: { action: 'keep', label: 'Dismiss' }, key: 'boot:secureboot', data: {},
    });
  }
}

/* ---------- pass 3: startup entries ---------- */
async function startup(ctx) {
  const items = [];
  await ps.stream('startup.ps1', [], (o) => items.push(o), { signal: ctx.signal, timeout: 10 * 60000 });
  const n = Math.max(items.length, 1);
  items.forEach((o, i) => {
    ctx.count(1);
    ctx.progress((i + 1) / n);
    if (o.type === 'entry') startupEntry(ctx, o);
    else if (o.type === 'winlogon') {
      const shellOk = /^explorer\.exe$/i.test(String(o.shell).trim());
      const userinitOk = /^c:\\windows\\system32\\userinit\.exe,?$/i.test(String(o.userinit).trim());
      ctx.item({ file: 'Winlogon shell', sub: o.shell || '(empty)', tone: shellOk ? '' : 'bad' });
      ctx.item({ file: 'Winlogon userinit', sub: base(o.userinit) || '(empty)', tone: userinitOk ? '' : 'bad' });
      if (!shellOk) winlogonFinding(ctx, 'Shell', o.shell);
      if (!userinitOk) winlogonFinding(ctx, 'Userinit', o.userinit);
    } else if (o.type === 'winlogon-user') {
      ctx.item({ file: 'Winlogon shell (this user)', sub: o.shell, tone: 'bad' });
      ctx.finding({
        kind: 'startup', sev: 'High', name: 'Your sign-in shell was replaced', path: o.shell,
        what: 'A per-user setting starts this program instead of the normal Windows desktop when you sign in.',
        primary: { action: 'remove', label: 'Reset' }, secondary: { action: 'keep', label: 'Keep' },
        confirm: { title: 'Reset your sign-in shell?', body: 'Power Scan removes the per-user Shell value so Windows starts the normal desktop.' },
        key: 'winlogon-user:' + o.shell, data: { user: 'winlogon-shell' },
      });
    } else if (o.type === 'appinit') {
      const active = o.dlls && o.load === 1;
      ctx.item({ file: 'AppInit_DLLs', sub: active ? o.dlls : 'empty', tone: active ? 'bad' : '' });
      if (active) {
        ctx.finding({
          kind: 'startup', sev: 'High', name: 'DLLs are injected into every program', path: o.dlls,
          what: 'AppInit_DLLs loads these files into every program that starts. Malware uses it to spy on programs.',
          primary: { action: 'remove', label: 'Remove' }, secondary: { action: 'keep', label: 'Keep' },
          confirm: { title: 'Clear AppInit_DLLs?', body: 'Power Scan empties AppInit_DLLs and turns the feature off. Windows asks for administrator permission first.' },
          key: 'appinit:' + o.dlls, data: { ops: [{ op: 'appinit-reset' }] },
        });
      }
    } else if (o.type === 'ifeo') {
      ctx.item({ file: 'Debugger for ' + o.exe, sub: base(o.debugger), tone: 'bad' });
      ctx.finding({
        kind: 'startup', sev: 'Medium', name: `Another program launches instead of ${o.exe}`, path: o.debugger,
        what: `When anything starts ${o.exe}, Windows runs this program instead. Developers use it for debugging, and malware uses it to hijack programs.`,
        primary: { action: 'remove', label: 'Remove' }, secondary: { action: 'keep', label: 'Keep' },
        confirm: { title: `Remove the redirect for ${o.exe}?`, body: 'Power Scan deletes the Debugger value for this program. Windows asks for administrator permission first.' },
        key: 'ifeo:' + o.exe + ':' + o.debugger, data: { ops: [{ op: 'ifeo-remove', exe: o.exe }] },
      });
    }
  });
}

function winlogonFinding(ctx, field, value) {
  ctx.finding({
    kind: 'startup', sev: 'High', name: `Windows sign-in ${field} was changed`, path: value || '(empty)',
    what: field === 'Shell' ? 'Windows starts this instead of the normal desktop when anyone signs in.' : 'Windows runs this during every sign-in.',
    primary: { action: 'remove', label: 'Reset' }, secondary: { action: 'keep', label: 'Keep' },
    confirm: { title: `Reset ${field} to the Windows default?`, body: 'Windows asks for administrator permission first.' },
    key: 'winlogon:' + field + ':' + value, data: { ops: [{ op: 'winlogon-reset', field }] },
  });
}

function startupEntry(ctx, o) {
  const unsignedUser = o.exists && o.userWritable && BAD_SIG.has(o.sig);
  const tampered = o.exists && o.sig === 'HashMismatch';
  const sub = !o.exe ? '' : !o.exists ? 'file missing' : BAD_SIG.has(o.sig) ? 'not signed' : (o.signer ? o.signer + ' · signed' : 'signed');
  ctx.item({ file: `${o.where}: ${o.name}`, sub, tone: unsignedUser || tampered ? 'bad' : '' });
  if (!unsignedUser && !tampered) return;
  let data = null, restart = false;
  if (o.kind === 'run') data = /^HKCU/.test(o.hive) ? { user: 'run-remove', hive: o.hive, name: o.valueName, value: o.command } : { ops: [{ op: 'run-remove', hive: o.hive, name: o.valueName }] };
  else if (o.kind === 'folder') data = o.scope === 'user' ? { user: 'quarantine', file: o.file } : { ops: [{ op: 'quarantine-file', path: o.file }] };
  else if (o.kind === 'task') data = { ops: [{ op: 'task-disable', taskPath: o.taskPath, taskName: o.taskName }] };
  else if (o.kind === 'service') { data = { ops: [{ op: 'service-disable', name: o.service }] }; restart = true; }
  if (!data) return;
  ctx.finding({
    kind: 'startup', sev: tampered ? 'High' : 'Medium',
    name: tampered ? 'Tampered program starts automatically' : 'Unsigned program starts automatically',
    path: o.exe,
    what: `${o.where} "${o.name}" starts this program from a folder normal programs can write to, and it has no valid signature. Malware often hides here.`,
    primary: { action: 'remove', label: o.kind === 'service' || o.kind === 'task' ? 'Disable' : 'Remove from startup' },
    secondary: { action: 'keep', label: 'Keep' },
    confirm: {
      title: `Stop "${o.name}" from starting?`,
      body: 'The program file is not deleted, only its automatic start. Power Scan keeps a copy of the setting so it can be put back.' + (data.ops ? ' Windows asks for administrator permission first.' : ''),
    },
    restart,
    key: 'startup:' + o.kind + ':' + String(o.exe).toLowerCase(),
    data: { ...data, scanFile: o.exe },
  });
}

/* ---------- pass 4: running programs ---------- */
async function processes(ctx) {
  let total = 0, done = 0;
  await ps.stream('processes.ps1', [], (o) => {
    if (o.type === 'count') { total = o.n; return; }
    if (o.type !== 'proc') return;
    done++;
    ctx.count(1);
    ctx.progress(total ? done / total : 0);
    const missing = !o.exists;
    const unsignedUser = o.exists && o.userWritable && BAD_SIG.has(o.sig);
    const sub = missing ? 'file deleted' : BAD_SIG.has(o.sig) ? 'not signed' : (o.signer ? o.signer + ' · signed' : o.sig === 'Valid' ? 'signed' : 'packaged app');
    ctx.item({ dir: dirOf(o.path), file: base(o.path), sub, tone: missing || unsignedUser ? 'bad' : '' });
    if (!missing && !unsignedUser) return;
    ctx.finding({
      kind: 'process', sev: missing ? 'High' : 'Medium',
      name: missing ? 'Program running from a deleted file' : 'Unsigned program running from a user folder',
      path: o.path,
      what: missing
        ? 'This program is running but its file is gone from disk. Malware does this to avoid being scanned.'
        : 'This program has no valid signature and runs from a folder normal programs can write to. It may be fine, so check that you know it.',
      primary: { action: 'remove', label: missing ? 'End it' : 'End and scan' },
      secondary: { action: 'keep', label: 'Keep' },
      confirm: { title: `End ${o.name}?`, body: missing ? 'Power Scan closes the program.' : 'Power Scan closes the program, then Microsoft Defender scans its file and removes it if it is harmful. Unsaved work in that program is lost.' },
      key: 'process:' + String(o.path).toLowerCase(),
      data: { pids: o.pids, scanFile: missing ? null : o.path },
    });
  }, { signal: ctx.signal, timeout: 15 * 60000 });
}

/* ---------- pass 5: every file, scanned by Microsoft Defender ---------- */
const SPLIT = new Set(['users']);
const SKIP_ROOT_FILES = new Set(['pagefile.sys', 'hiberfil.sys', 'swapfile.sys', 'dumpstack.log', 'dumpstack.log.tmp']);

async function listDir(dir) {
  try { return await fsp.readdir(dir, { withFileTypes: true }); } catch (_) { return []; }
}

/** Splits each drive into scan units: top folders, with user profiles split one level further. */
async function buildUnits(roots) {
  const units = [];
  for (const root of roots) {
    for (const e of await listDir(root)) {
      const p = path.join(root, e.name);
      const lower = e.name.toLowerCase();
      if (e.isDirectory()) {
        if (SPLIT.has(lower)) {
          for (const prof of await listDir(p)) {
            if (!prof.isDirectory()) continue;
            const pp = path.join(p, prof.name);
            const kids = await listDir(pp);
            if (!kids.length) { units.push(pp); continue; }
            for (const k of kids) {
              if (k.isSymbolicLink()) continue;
              const kp = path.join(pp, k.name);
              if (k.isDirectory() && k.name.toLowerCase() === 'appdata') {
                for (const a of await listDir(kp)) if (a.isDirectory()) units.push(path.join(kp, a.name));
              } else if (k.isDirectory() || k.isFile()) units.push(kp);
            }
          }
        } else units.push(p);
      } else if (e.isFile() && !SKIP_ROOT_FILES.has(lower)) units.push(p);
    }
  }
  return units;
}

/** Counts files under a unit and keeps a random sample of paths for the live feed. */
async function countUnit(unit, sample, signal, max = 800) {
  let st;
  try { st = await fsp.lstat(unit); } catch (_) { return 0; }
  if (st.isFile()) { sample.push(unit); return 1; }
  let n = 0, steps = 0;
  const stack = [unit];
  while (stack.length && !signal.aborted) {
    const dir = stack.pop();
    for (const e of await listDir(dir)) {
      if (e.isSymbolicLink()) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) stack.push(p);
      else if (e.isFile()) {
        n++;
        if (sample.length < max) sample.push(p);
        else { const j = Math.floor(Math.random() * n); if (j < max) sample[j] = p; }
      }
    }
    if (++steps % 200 === 0) await new Promise((r) => setImmediate(r));
  }
  return n;
}

async function files(ctx) {
  const st = ctx.status || (await defender.status());
  const d = st.defender || {};
  if (!defender.mpcmdrun() || d.mode !== 'Normal' || !d.av) {
    ctx.note('warn', 'Microsoft Defender is not the active antivirus on this PC, so the file pass was skipped. The antivirus you use still protects your files.');
    return;
  }
  if (d.sigAge >= 1) {
    ctx.item({ file: 'Updating Microsoft Defender signatures', sub: '' });
    await defender.updateSignatures(ctx.signal);
  }
  const roots = (st.drives && st.drives.length ? st.drives : ['C:']).map((x) => x.replace(/\\?$/, '\\'));
  const units = await buildUnits(roots);
  const counts = new Array(units.length).fill(null);
  const samples = units.map(() => []);
  let counted = false;
  const counter = (async () => {
    for (let i = 0; i < units.length && !ctx.signal.aborted; i++) counts[i] = await countUnit(units[i], samples[i], ctx.signal);
    counted = true;
  })();

  let doneFiles = 0;
  let rate = 400;
  for (let i = 0; i < units.length && !ctx.signal.aborted; i++) {
    const unit = units[i];
    const t0 = Date.now();
    let k = 0;
    const tick = setInterval(() => {
      const est = counts[i] != null ? counts[i] : Math.max(samples[i].length, 1);
      const frac = Math.min(0.95, (((Date.now() - t0) / 1000) * rate) / Math.max(est, 1));
      const s = samples[i];
      if (s.length) { const p = s[k++ % s.length]; ctx.item({ dir: dirOf(p), file: base(p), sub: '' }); }
      else ctx.item({ dir: dirOf(unit), file: base(unit), sub: 'scanning' });
      const total = counted ? counts.reduce((a, b) => a + (b || 0), 0) : 0;
      const checked = doneFiles + Math.round(est * frac);
      ctx.progress(total ? Math.min(0.99, checked / total) : Math.min(0.99, (i + frac) / units.length), checked);
    }, 90);
    const r = await defender.scanPath(unit, { remediate: false, signal: ctx.signal });
    clearInterval(tick);
    if (ctx.signal.aborted) break;
    const cnt = counts[i] != null ? counts[i] : 0;
    doneFiles += cnt;
    const secs = (Date.now() - t0) / 1000;
    if (cnt > 300 && secs > 1) rate = rate * 0.4 + (cnt / secs) * 0.6;
    for (const t of r.threats) ctx.finding(threatFinding(t));
    if (r.error && !r.threats.length) ctx.note('warn', `Defender could not scan ${unit}: ${r.error}`);
  }
  await Promise.race([counter, new Promise((r) => setTimeout(r, 50))]);
  if (ctx.signal.aborted) { await defender.cancelScans(); return; }
  ctx.progress(1, doneFiles);
}

function threatFinding(t) {
  const shown = (t.resources.find((r) => /file/.test(r.type)) || t.resources[0] || { path: '' }).path;
  const filesToFix = [...new Set(t.resources.filter((r) => /file/.test(r.type)).map((r) => r.path.split('->')[0]))];
  const { sev, what } = defender.describe(t.name);
  return {
    kind: 'file', sev, name: t.name, path: shown, what,
    primary: { action: 'remove', label: 'Remove' },
    secondary: { action: 'keep', label: 'Keep' },
    confirm: { title: `Remove ${t.name}?`, body: 'Microsoft Defender moves it to quarantine. You can restore it from Windows Security, Protection history.' },
    key: 'threat:' + t.name + ':' + String(shown).toLowerCase(),
    data: { files: filesToFix },
  };
}

/* ---------- actions on findings ---------- */
async function remove(f) {
  const d = f.data || {};
  if (f.kind === 'file') {
    for (const p of d.files || []) await defender.scanPath(p, { remediate: true });
    let left = (d.files || []).filter(exists);
    if (!d.files || !d.files.length) {
      const r = await ps.elevated([{ op: 'defender-remove' }]);
      if (r.cancelled) return { state: 'open', message: 'Removing it needs administrator permission.' };
      return r.results.every((x) => x.ok) ? { state: 'removed', message: 'Removed by Microsoft Defender' } : { state: 'failed', message: 'Open Windows Security to remove it.' };
    }
    if (left.length) {
      const r = await ps.elevated(left.map((p) => ({ op: 'quarantine-file', path: p })));
      if (r.cancelled) return { state: 'open', message: 'Removing it needs administrator permission.' };
      left = left.filter(exists);
    }
    return left.length ? { state: 'failed', message: 'Could not remove it. Open Windows Security, Virus & threat protection.' } : { state: 'removed', message: 'Removed · in quarantine' };
  }
  if (d.user === 'run-remove') {
    const key = d.hive === 'HKCU-Once' ? 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' : 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
    const r = await ps.command(`Remove-ItemProperty -LiteralPath ${ps.psq(key)} -Name ${ps.psq(d.name)} -ErrorAction Stop`);
    return r.code === 0 ? { state: 'removed', message: 'Removed from startup · setting saved', backup: { key, name: d.name, value: d.value } } : { state: 'failed', message: 'Windows did not allow the change.' };
  }
  if (d.user === 'quarantine') return quarantineUserFile(d.file);
  if (d.user === 'winlogon-shell') {
    const r = await ps.command("Remove-ItemProperty -LiteralPath 'HKCU:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name Shell -ErrorAction Stop");
    return r.code === 0 ? { state: 'removed', message: 'Reset · takes effect at next sign-in' } : { state: 'failed', message: 'Windows did not allow the change.' };
  }
  if (f.kind === 'process') {
    let ended = true;
    for (const pid of d.pids || []) { try { process.kill(pid); } catch (_) { ended = false; } }
    if (!ended) {
      const r = await ps.elevated((d.pids || []).map((pid) => ({ op: 'kill', pid })));
      if (r.cancelled) return { state: 'open', message: 'Ending it needs administrator permission.' };
    }
    if (d.scanFile) {
      await new Promise((r) => setTimeout(r, 800));
      const r = await defender.scanPath(d.scanFile, { remediate: true });
      if (r.threats.length) return { state: 'removed', message: 'Ended · Defender removed the file' };
      return { state: 'removed', message: 'Ended · Defender found nothing harmful in the file' };
    }
    return { state: 'removed', message: 'Ended' };
  }
  if (d.ops) {
    const r = await ps.elevated(d.ops);
    if (r.cancelled) return { state: 'open', message: 'This change needs administrator permission.' };
    const failed = r.results.filter((x) => !x.ok);
    if (failed.length || !r.results.length) return { state: 'failed', message: failed[0] ? failed[0].message : 'The change did not finish.' };
    const backup = r.results.find((x) => x.backup);
    return { state: f.restart ? 'removed-restart' : 'removed', message: f.restart ? 'Done · takes effect after restart' : 'Done', backup: backup ? { op: backup.op, value: backup.backup } : undefined };
  }
  return { state: 'failed', message: 'Nothing to change automatically.' };
}

function quarantineUserFile(file) {
  try {
    const dir = path.join(process.env.LOCALAPPDATA || os.homedir(), 'PowerScan', 'Quarantine');
    fs.mkdirSync(dir, { recursive: true });
    const dest = path.join(dir, `${Date.now()}_${base(file)}.quarantined`);
    fs.renameSync(file, dest);
    return { state: 'removed', message: 'Moved to quarantine', backup: { from: file, to: dest } };
  } catch (e) {
    return { state: 'failed', message: e.code === 'EBUSY' ? 'The file is in use.' : 'Could not move the file.' };
  }
}

module.exports = { kernel, boot, startup, processes, files, remove, buildUnits, countUnit };
