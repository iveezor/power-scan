'use strict';
/*
 * Fast file pass for Windows.
 * 1. Survey: count every file on every drive with many directory reads in flight (about 3 s for 400k files).
 * 2. Plan: split the drives into pieces of a few thousand files. Folders that cannot be split cheaply
 *    (many files directly inside) stay whole and are scanned first, so they never finish last.
 * 3. Scan: several Microsoft Defender report-only scans run in parallel (half the processor cores, 2 to 8).
 *    Measured on a 16-core PC: 8 parallel scans are 3 to 5 times faster than one; 16 are slower than 8.
 */
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const path = require('path');
const defender = require('./defender');

const SKIP_ROOT_FILES = new Set(['pagefile.sys', 'hiberfil.sys', 'swapfile.sys', 'dumpstack.log', 'dumpstack.log.tmp']);
// Windows' own recovery and setup images and restore-point storage. Report-only Defender scans unpack
// these sealed images completely (about 37 minutes for C:\Recovery alone on a test PC), and Windows does
// not run them while it is running. They are skipped and the results say so.
const SKIP_ROOT_DIRS = new Set(['recovery', '$winreagent', '$sysreset', '$windows.~bt', '$windows.~ws', 'system volume information']);
const LOOSE_LIMIT = 400;
// Defender unpacks archives and disk images, so these cost far more than their file count suggests.
const HEAVY = /\.(wim|esd|iso|img|vhdx?|vmdk|cab|msi|msix|appx|zip|7z|rar|tar|gz|tgz|xz|bz2|jar|apk)$/i;
const HEAVY_WEIGHT_PER_MB = 40;
const workerCount = () => Math.max(2, Math.min(8, Math.floor(os.cpus().length / 2)));

/** Counts files under each root with up to 64 directory reads at once. */
function survey(roots, signal, onProgress) {
  const dirs = new Map();
  const skipped = [];
  const queue = roots.map((p) => ({ p, root: true }));
  let active = 0;
  let files = 0;
  return new Promise((done) => {
    const next = () => {
      while (active < 64 && queue.length && !signal.aborted) {
        const { p, root } = queue.pop();
        active++;
        fsp.readdir(p, { withFileTypes: true }).then(async (entries) => {
          const node = { loose: 0, kids: [], samples: [], heavyMb: 0 };
          const heavy = [];
          for (const e of entries) {
            if (e.isSymbolicLink()) continue;
            if (e.isDirectory()) {
              if (root && SKIP_ROOT_DIRS.has(e.name.toLowerCase())) { skipped.push(path.join(p, e.name)); continue; }
              const c = path.join(p, e.name); node.kids.push(c); queue.push({ p: c });
            }
            else if (e.isFile()) {
              if (root && SKIP_ROOT_FILES.has(e.name.toLowerCase())) continue;
              node.loose++;
              if (node.samples.length < 6) node.samples.push(e.name);
              if (HEAVY.test(e.name)) heavy.push(path.join(p, e.name));
            }
          }
          for (const h of heavy) { try { node.heavyMb += (await fsp.stat(h)).size / 1048576; } catch (_) { /* gone */ } }
          files += node.loose;
          dirs.set(p, node);
          onProgress(files, p);
        }, () => { dirs.set(p, { loose: 0, kids: [], samples: [], heavyMb: 0, unreadable: true }); })
          .finally(() => { active--; if ((!queue.length || signal.aborted) && !active) done({ dirs, files, skipped }); else next(); });
      }
      if (!active && (!queue.length || signal.aborted)) done({ dirs, files, skipped });
    };
    next();
  });
}

/** Files and heavy megabytes in each folder's whole subtree. */
function subtreeTotals(dirs, roots) {
  const order = [];
  const stack = roots.slice();
  while (stack.length) {
    const p = stack.pop();
    const n = dirs.get(p);
    if (!n) continue;
    order.push(p);
    for (const k of n.kids) stack.push(k);
  }
  const total = new Map();
  for (let i = order.length - 1; i >= 0; i--) {
    const n = dirs.get(order[i]);
    let t = n.loose;
    let mb = n.heavyMb || 0;
    let unreadable = !!n.unreadable;
    for (const k of n.kids) { const c = total.get(k); if (c) { t += c.files; mb += c.mb; unreadable = unreadable || c.unreadable; } }
    total.set(order[i], { files: t, mb, unreadable });
  }
  return total;
}
const weightOf = (s) => (s.unreadable ? Number.MAX_SAFE_INTEGER : s.files + s.mb * HEAVY_WEIGHT_PER_MB);

/** Collects a few file paths from a folder's subtree for the live feed. */
function samplesUnder(dirs, root, max = 240) {
  const out = [];
  const stack = [root];
  while (stack.length && out.length < max) {
    const p = stack.pop();
    const n = dirs.get(p);
    if (!n) continue;
    for (const s of n.samples) { out.push(path.join(p, s)); if (out.length >= max) break; }
    for (const k of n.kids) stack.push(k);
  }
  return out.sort(() => Math.random() - 0.5);
}

/**
 * Splits the drives into scan units of roughly `chunk` files. Kept whole: small folders, leaf folders,
 * folders with many files directly inside, folders with hundreds of tiny subfolders (each separate scan
 * costs a start-up), and folders that could not be read (their size is unknown, so they start first).
 */
async function plan(dirs, total, roots, workers) {
  const all = roots.reduce((a, r) => a + ((total.get(r) || {}).files || 0), 0);
  const chunk = Math.max(2500, Math.ceil(all / (workers * 8)));
  const units = [];
  const looseDirs = [];
  const visit = (dir, isRoot) => {
    const n = dirs.get(dir);
    const s = total.get(dir);
    if (!n || !s) return;
    if (n.unreadable) { units.push({ path: dir, files: 0, weight: Number.MAX_SAFE_INTEGER }); return; }
    if (s.files === 0 && !s.unreadable) return;
    const leaf = n.kids.length === 0;
    const manyTinyKids = n.kids.length > 300 && s.files / n.kids.length < 40;
    if (!isRoot && (s.files <= chunk || leaf || manyTinyKids || (n.loose > LOOSE_LIMIT && s.files <= chunk * 6))) {
      units.push({ path: dir, files: s.files, weight: weightOf(s) });
      return;
    }
    for (const k of n.kids) visit(k, false);
    if (n.loose) looseDirs.push(dir);
  };
  for (const r of roots) visit(r, true);
  for (const dir of looseDirs) {
    let entries = [];
    try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const e of entries) {
      if (!e.isFile() || e.isSymbolicLink()) continue;
      if (roots.includes(dir) && SKIP_ROOT_FILES.has(e.name.toLowerCase())) continue;
      const file = path.join(dir, e.name);
      let weight = 1;
      if (HEAVY.test(e.name)) { try { weight += ((await fsp.stat(file)).size / 1048576) * HEAVY_WEIGHT_PER_MB; } catch (_) { /* gone */ } }
      units.push({ path: file, files: 1, weight, single: true });
    }
  }
  units.sort((a, b) => b.weight - a.weight);
  return { units, all, chunk };
}

/**
 * Runs the whole file pass. ctx: signal, item(), progress(frac, checked), note(), finding().
 * threatFinding(t) turns a parsed Defender detection into a finding.
 */
async function run(ctx, roots, threatFinding) {
  const signal = ctx.signal;
  const workers = workerCount();

  let lastShown = 0;
  const { dirs, skipped } = await survey(roots, signal, (files, p) => {
    const now = Date.now();
    if (now - lastShown > 90) { lastShown = now; ctx.item({ dir: '', file: `Counting files · ${files.toLocaleString('en-US')}`, sub: path.basename(p) }); }
  });
  if (signal.aborted) return;
  const total = subtreeTotals(dirs, roots);
  const { units, all } = await plan(dirs, total, roots, workers);
  for (const u of units) u.samples = u.single ? [u.path] : samplesUnder(dirs, u.path);
  ctx.item({ dir: '', file: `${all.toLocaleString('en-US')} files in ${units.length.toLocaleString('en-US')} pieces`, sub: `${workers} scanners` });

  let doneFiles = 0;
  let rate = 150;
  let shown = 0;
  const activeUnits = new Map();
  const failures = [];
  let feedTurn = 0;
  const tick = setInterval(() => {
    const now = Date.now();
    let partial = 0;
    for (const a of activeUnits.values()) partial += Math.min(a.u.files * 0.95, ((now - a.t0) / 1000) * rate);
    // The estimate inside running pieces changes as the measured speed changes; never show progress going back.
    shown = Math.max(shown, Math.min(Math.round(doneFiles + partial), all));
    ctx.progress(all ? Math.min(0.99, shown / all) : 0, shown);
    const list = [...activeUnits.values()];
    if (list.length) {
      const a = list[feedTurn++ % list.length];
      const s = a.u.samples;
      const p = s.length ? s[a.k++ % s.length] : a.u.path;
      ctx.item({ dir: path.dirname(p) + path.sep, file: path.basename(p), sub: '' });
    }
  }, 70);

  let next = 0;
  try {
    await Promise.all(Array.from({ length: workers }, async (_, w) => {
      while (!signal.aborted && next < units.length) {
        const u = units[next++];
        const started = Date.now();
        activeUnits.set(w, { u, t0: started, k: 0 });
        const r = await defender.scanPath(u.path, { remediate: false, signal });
        activeUnits.delete(w);
        if (signal.aborted) break;
        doneFiles += u.files;
        const secs = (Date.now() - started) / 1000;
        if (u.files >= 200 && secs > 0.5) rate = rate * 0.6 + (u.files / secs) * 0.4;
        for (const t of r.threats) ctx.finding(threatFinding(t));
        if (r.error && fs.existsSync(u.path)) failures.push(`${u.path} (${r.error})`);
      }
    }));
  } finally {
    clearInterval(tick);
  }
  if (signal.aborted) { await defender.cancelScans(); return; }
  if (skipped.length) {
    ctx.note('info', `Skipped Windows' own recovery and setup images (${skipped.map((s) => path.basename(s)).join(', ')}). They are sealed Microsoft images that Windows does not run, and fully unpacking them can add over 30 minutes.`);
  }
  if (failures.length) {
    ctx.note('warn', `Microsoft Defender could not scan ${failures.length === 1 ? 'one item' : failures.length + ' items'}, for example ${failures[0]}. Files in use by Windows are often skipped this way.`);
  }
  ctx.progress(1, all);
}

module.exports = { run, survey, plan, subtreeTotals, workerCount };
