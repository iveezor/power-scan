'use strict';
/*
 * Windows Traffic hold. A new download gets a "deny execute" rule for Everyone, so double-clicking it
 * cannot start it, while Microsoft Defender scans it. Clean files get the rule removed again.
 */
const fs = require('fs');
const path = require('path');
const defender = require('./defender');
const { run, exists } = require('../util');

const ICACLS = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'icacls.exe');

async function hold(file) {
  const r = await run(ICACLS, [file, '/deny', '*S-1-1-0:(X)'], { timeout: 15000 });
  return r.code === 0;
}

async function release(file) {
  const r = await run(ICACLS, [file, '/remove:d', '*S-1-1-0'], { timeout: 15000 });
  return r.code === 0;
}

async function check(file, signal) {
  const r = await defender.scanPath(file, { remediate: false, signal });
  const t = r.threats[0];
  if (!t) return { clean: !r.error, error: r.error };
  const d = defender.describe(t.name);
  return { clean: false, threat: t.name, what: d.what };
}

async function remove(file) {
  await defender.scanPath(file, { remediate: true });
  if (!exists(file)) return { ok: true, message: 'Removed by Microsoft Defender · it never ran' };
  try {
    await release(file);
    fs.unlinkSync(file);
    return { ok: true, message: 'Deleted · it never ran' };
  } catch (e) {
    return { ok: false, message: 'Could not delete it: ' + e.code };
  }
}

module.exports = { hold, release, check, remove, scannerName: 'Microsoft Defender' };
