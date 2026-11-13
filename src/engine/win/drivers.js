'use strict';
/* Windows driver check: inventory, Windows Update versions, device health and event-log performance. */
const ps = require('./ps');
const { run, sleep } = require('../util');

const MAIN_CLASSES = new Set(['DISPLAY', 'NET', 'MEDIA', 'BLUETOOTH', 'CAMERA', 'IMAGE', 'SCSIADAPTER', 'HDC', 'USB', 'HIDCLASS', 'BIOMETRIC', 'AUDIOENDPOINT', 'SYSTEM']);
const FEED_CLASSES = new Set(['DISPLAY', 'NET', 'MEDIA', 'BLUETOOTH', 'CAMERA', 'IMAGE', 'SCSIADAPTER', 'HDC', 'BIOMETRIC']);
const SKIP_CODES = new Set([22, 24, 45]);
const CODE_TEXT = {
  1: 'the device is not set up correctly', 3: 'the driver may be corrupted', 10: 'the device cannot start',
  12: 'not enough free resources', 14: 'Windows needs a restart', 18: 'the drivers need reinstalling',
  19: 'the device settings are damaged', 28: 'no driver is installed', 31: 'the device is not working properly',
  32: 'the driver is turned off', 37: 'the driver failed to start', 39: 'the driver is missing or corrupted',
  41: 'Windows cannot find the hardware', 43: 'the device reported a problem', 48: 'the driver is blocked',
  52: 'the driver signature cannot be verified',
};
const catOf = (cls) => {
  const c = String(cls || '').toUpperCase();
  if (c === 'DISPLAY') return 'display';
  if (c === 'NET' || c === 'BLUETOOTH') return 'net';
  if (c === 'MEDIA' || c === 'AUDIOENDPOINT') return 'audio';
  return 'chip';
};
const noteOf = (cat) => ({
  display: 'The screen goes black for a moment while it installs.',
  net: 'The connection drops for a few seconds while it installs.',
  audio: 'Sound stops for a few seconds while it installs.',
}[cat] || '');
const monthYear = (iso) => {
  if (!iso) return '';
  const d = new Date(iso + 'T00:00:00');
  return isNaN(d) ? iso : d.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
};
const mb = (bytes) => (bytes > 0 ? (bytes >= 1e9 ? (bytes / 1e9).toFixed(1) + ' GB' : Math.max(1, Math.round(bytes / 1e6)) + ' MB') : '');
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
/** Compares dotted versions; null when either is not purely numeric. */
function cmpDotted(a, b) {
  const pa = String(a || '').split('.').map(Number), pb = String(b || '').split('.').map(Number);
  if (!a || !b || pa.some(isNaN) || pb.some(isNaN)) return null;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; }
  return 0;
}
/** Windows Update sometimes offers a package that is not newer than what is installed; skip those. */
function isNewer(up, d) {
  const c = cmpDotted(up.version, d.version);
  if (c !== null) return c > 0;
  if (up.date && d.date) return up.date > d.date;
  return true;
}
const packageName = (title) => String(title || '').replace(/\s*\(?\d+(?:\.\d+){1,4}\)?\s*$/, '').trim();
const BORING = /^(WAN Miniport|Microsoft Kernel Debug|Microsoft Wi-Fi Direct|Bluetooth Device \(|Teredo|Microsoft ISATAP|Generic software|Microsoft Hyper-V)/i;
const HEALTHY_ORDER = ['DISPLAY', 'NET', 'MEDIA', 'BLUETOOTH', 'CAMERA', 'BIOMETRIC', 'SCSIADAPTER', 'HDC', 'USB', 'HIDCLASS'];

async function inventory(ctx) {
  const st = ctx.state;
  st.drivers = []; st.problems = [];
  let total = 0;
  await ps.stream('drivers-inventory.ps1', [], (o) => {
    if (o.type === 'count') { total = o.n; st.devices = o.devices; return; }
    if (o.type === 'driver') {
      st.drivers.push(o);
      ctx.count(1);
      ctx.progress(total ? st.drivers.length / total : 0);
      if (FEED_CLASSES.has(String(o.cls).toUpperCase())) ctx.item({ file: o.name, sub: o.inf || o.version });
    } else if (o.type === 'problem') st.problems.push(o);
  }, { signal: ctx.signal, timeout: 5 * 60000 });
  st.total = st.drivers.length;
}

async function versions(ctx) {
  const st = ctx.state;
  st.updates = [];
  ctx.item({ file: 'Asking Windows Update for driver updates', sub: '' });
  const t0 = Date.now();
  const ticker = setInterval(() => ctx.progress(1 - Math.exp(-(Date.now() - t0) / 40000)), 400);
  const { objs } = await ps.json('drivers-updates.ps1', [], { signal: ctx.signal, timeout: 6 * 60000 });
  clearInterval(ticker);
  const err = objs.find((o) => o.type === 'error');
  if (err) ctx.note('warn', `Windows Update could not be checked: ${err.message}`);
  st.updates = objs.filter((o) => o.type === 'update');
  const byHw = new Map(st.updates.map((u) => [String(u.hwid).toLowerCase(), u]));
  const all = st.drivers.concat(st.problems);
  st.matches = new Map();
  for (const d of all) {
    const u = (d.hwids || []).map((h) => byHw.get(String(h).toLowerCase())).find(Boolean);
    if (u && (d.type === 'problem' || isNewer(u, d))) st.matches.set(d.id, u);
  }
  const shown = st.drivers.filter((d) => FEED_CLASSES.has(String(d.cls).toUpperCase()));
  for (const d of shown) {
    const u = st.matches.get(d.id);
    if (u) { ctx.item({ file: `${d.name} ${d.version}`, sub: `newer ${u.version || u.date}`, tone: 'warn' }); ctx.flag(d.id); }
    else ctx.item({ file: `${d.name} ${d.version}`, sub: 'up to date' });
    await sleep(25);
  }
  ctx.progress(1);
}

async function health(ctx) {
  const st = ctx.state;
  st.badDevices = st.problems.concat(st.drivers.filter((d) => d.problem)).filter((p) => !SKIP_CODES.has(p.code != null ? p.code : p.problem));
  const shown = st.drivers.filter((d) => FEED_CLASSES.has(String(d.cls).toUpperCase()));
  shown.forEach((d, i) => { if (!d.problem) ctx.item({ file: d.name, sub: 'working' }); ctx.progress((i + 1) / (shown.length + st.badDevices.length || 1)); });
  for (const p of st.badDevices) {
    const code = p.code != null ? p.code : p.problem;
    ctx.item({ file: p.name || p.id, sub: `Code ${code} · ${CODE_TEXT[code] || 'problem'}`, tone: 'bad' });
    ctx.flag(p.id);
  }
  ctx.progress(1);
}

async function performance(ctx) {
  const st = ctx.state;
  const { objs } = await ps.json('drivers-events.ps1', [], { signal: ctx.signal, timeout: 3 * 60000 });
  const ev = objs.find((o) => o.type === 'events') || { tdr: {}, providers: {}, crashes: 0, whea: 0 };
  st.events = ev;
  const tdr = ev.tdr || {};
  const prov = ev.providers || {};
  st.unstable = new Map();
  for (const d of st.drivers) {
    const svc = String(d.service || '').toLowerCase();
    if (!svc) continue;
    const isDisplay = String(d.cls).toUpperCase() === 'DISPLAY';
    let resets = 0, errors = 0;
    for (const [name, n] of Object.entries(tdr)) if (isDisplay && (name.toLowerCase() === svc || name === 'display')) resets += n;
    for (const [name, n] of Object.entries(prov)) if (name.toLowerCase() === svc) errors += n;
    if (resets >= 1 || errors >= 5) { st.unstable.set(d.id, { resets, errors }); ctx.flag(d.id); }
  }
  const shown = st.drivers.filter((d) => FEED_CLASSES.has(String(d.cls).toUpperCase()));
  for (const d of shown) {
    const u = st.unstable.get(d.id);
    if (u) ctx.item({ file: d.inf || d.name, sub: u.resets ? `${plural(u.resets, 'display reset')} in 7 days` : `${plural(u.errors, 'error')} in 7 days`, tone: 'bad' });
    else ctx.item({ file: d.inf || d.name, sub: '0 errors in 7 days' });
    await sleep(20);
  }
  ctx.item({ file: 'Crashes (bug checks)', sub: ev.crashes ? `${ev.crashes} in 30 days` : 'none in 30 days', tone: ev.crashes ? 'warn' : '' });
  ctx.item({ file: 'Hardware errors (WHEA)', sub: ev.whea ? `${ev.whea} in 7 days` : 'none in 7 days', tone: ev.whea ? 'warn' : '' });
  if (ev.crashes) ctx.note('warn', `Windows crashed ${plural(ev.crashes, 'time')} in the last 30 days. A driver is a common cause; updating the drivers flagged here may help.`);
  ctx.progress(1);
}

function finish(ctx) {
  const st = ctx.state;
  const byId = new Map(st.drivers.map((d) => [d.id, d]));
  const issues = [];
  const ids = new Set([...st.matches.keys(), ...st.badDevices.map((p) => p.id), ...st.unstable.keys()]);
  for (const id of ids) {
    const d = byId.get(id) || st.problems.find((p) => p.id === id) || {};
    const up = st.matches.get(id);
    const bad = st.badDevices.find((p) => p.id === id);
    const code = bad ? (bad.code != null ? bad.code : bad.problem) : null;
    const uns = st.unstable.get(id);
    const cat = catOf(d.cls);
    const firmware = String(d.cls).toUpperCase() === 'FIRMWARE';
    const finds = [];
    if (uns && uns.resets) finds.push(['bad', `The display driver stopped responding <b>${plural(uns.resets, 'time')}</b> in 7 days (event 4101)`]);
    if (uns && uns.errors) finds.push(['bad', `<b>${plural(uns.errors, 'error')}</b> from this driver in the event log in 7 days`]);
    if (code != null) finds.push(['bad', `Device Manager <b>Code ${code}</b>: ${CODE_TEXT[code] || 'the device has a problem'}`]);
    let kind, tag;
    if (up) {
      kind = code === 28 ? 'install' : 'update';
      finds.push(['up', `${code === 28 ? 'Windows Update has' : 'Newer version'} <b>${up.version || up.title}</b>${up.date ? ' (' + monthYear(up.date) + ')' : ''}${code === 28 ? '' : ' on Windows Update'}`]);
      if (up.version && packageName(up.title)) finds.push(['info', `Package: ${packageName(up.title)}`]);
      if (firmware) finds.push(['bad', 'This updates the computer\'s firmware (BIOS/UEFI). Keep the charger connected; it finishes during the next restart.']);
    } else if (uns) {
      kind = 'rollback';
      finds.push(['info', 'Windows Update has nothing newer. If Device Manager kept the previous version, you can roll back to it.']);
    } else {
      kind = 'review';
      finds.push(['info', "Windows Update has no driver for it. The device maker's support site may have one."]);
    }
    tag = uns ? ['bad', 'Unstable'] : code != null ? ['bad', code === 28 ? 'No driver' : 'Not working'] : firmware ? ['warn', 'Firmware'] : ['warn', 'Outdated'];
    const sizeLabel = up ? mb(up.size) : '';
    issues.push({
      id: 'd' + issues.length,
      cat, name: d.name || id, tag, kind, finds,
      batch: !firmware,
      restart: firmware,
      meta: [d.inf || d.service, d.version, monthYear(d.date)].filter(Boolean).join(' · ') || id,
      note: firmware ? 'Keep the charger connected. The update finishes while the computer restarts, so save your work first.' : kind === 'update' || kind === 'install' ? noteOf(cat) : '',
      ver: d.version || '', newVer: up ? up.version || up.title : '', newName: up ? up.title : '',
      steps: kind === 'update' || kind === 'install' ? [sizeLabel ? `Downloading ${sizeLabel}` : 'Downloading', 'Installing', 'Checking the device works'] : [],
      doneText: kind === 'install' ? 'Installed · check the device works' : up ? `Updated to ${up.version || 'the newest version'}` : 'Opened in Device Manager',
      key: `${id}|${d.version || ''}|${kind}`,
      data: { deviceId: id, updateId: up ? up.id : null },
    });
  }
  const order = { Unstable: 0, 'Not working': 1, 'No driver': 1, Outdated: 2, Firmware: 3 };
  issues.sort((a, b) => order[a.tag[1]] - order[b.tag[1]]);
  const flagged = new Set(ids);
  const rank = (d) => { const i = HEALTHY_ORDER.indexOf(String(d.cls).toUpperCase()); return i < 0 ? 99 : i; };
  const healthy = st.drivers
    .filter((d) => !flagged.has(d.id) && MAIN_CLASSES.has(String(d.cls).toUpperCase()) && String(d.cls).toUpperCase() !== 'SYSTEM' && !BORING.test(d.name))
    .sort((a, b) => rank(a) - rank(b))
    .slice(0, 10)
    .map((d) => [d.name, [d.inf, d.version].filter(Boolean).join(' ')]);
  return { issues, healthy, total: st.total, devices: st.devices || st.total };
}

/** Installs Windows Update drivers in one administrator session; a restore point comes first when asked. */
async function apply(issues, { restorePoint }, onStep) {
  const ops = [];
  if (restorePoint) ops.push({ op: 'restore-point', id: 'rp' });
  for (const i of issues) if (i.data.updateId) ops.push({ op: 'driver-install', id: i.id, updateId: i.data.updateId });
  const r = await ps.elevated(ops, {
    onProgress: (o) => {
      if (o.id === 'rp') onStep('*', 'Creating a restore point');
      else if (o.progress === 'driver-install') onStep(o.id, 'Getting ready');
      else if (o.progress === 'download') onStep(o.id, 'Downloading');
      else if (o.progress === 'install') onStep(o.id, 'Installing');
    },
  });
  if (r.cancelled) return { cancelled: true };
  const rp = r.results.find((x) => x.id === 'rp');
  return {
    cancelled: false,
    restorePoint: rp ? (rp.ok ? rp.message : 'failed: ' + rp.message) : null,
    results: issues.map((i) => {
      const x = r.results.find((y) => y.id === i.id);
      return { id: i.id, ok: !!(x && x.ok), message: x ? x.message : 'Did not run', reboot: !!(x && x.reboot) };
    }),
  };
}

/** Opens the device's Properties window, where the Driver tab has Roll Back Driver. */
async function rollback(issue) {
  const sys = process.env.SystemRoot || 'C:\\Windows';
  run(`${sys}\\System32\\rundll32.exe`, ['devmgr.dll,DeviceProperties_RunDLL', '/DeviceID', issue.data.deviceId]);
  return { ok: true, message: 'Opened in Device Manager · use Roll Back Driver on the Driver tab' };
}

module.exports = { inventory, versions, health, performance, finish, apply, rollback };
