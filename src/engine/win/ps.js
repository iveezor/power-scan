'use strict';
/* Runs the bundled PowerShell scripts, and runs the administrator script through a UAC prompt. */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { run, parseJson, sleep } = require('../util');

const PS_DIR = path.join(__dirname, 'ps');
const POWERSHELL = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const BASE = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass'];

const psq = (s) => "'" + String(s).replace(/'/g, "''") + "'";
const encode = (text) => Buffer.from(text, 'utf16le').toString('base64');

/**
 * Streams JSON objects (one per line) from a bundled script. The script text is passed as an encoded
 * command, so it works wherever the app is unzipped (Windows PowerShell cannot open -File paths over 260 characters).
 */
function stream(script, args, onObj, opts = {}) {
  const body = fs.readFileSync(path.join(PS_DIR, script), 'utf8');
  const argv = args.length ? [...BASE, '-File', path.join(PS_DIR, script), ...args] : [...BASE, '-EncodedCommand', encode(body)];
  return run(POWERSHELL, argv, {
    ...opts,
    collect: false,
    onLine: (line) => { const o = parseJson(line.replace(/^\uFEFF/, '')); if (o) onObj(o); },
  });
}

/** Collects every JSON object a script prints. */
async function json(script, args = [], opts = {}) {
  const objs = [];
  const r = await stream(script, args, (o) => objs.push(o), opts);
  return { code: r.code, objs, stderr: r.stderr };
}

/** Runs a short inline PowerShell command as the current user. */
function command(text, opts = {}) {
  return run(POWERSHELL, [...BASE, '-EncodedCommand', encode(text)], opts);
}

/**
 * Runs allowlisted operations in elevated.ps1 after a UAC prompt.
 * Resolves { cancelled, results: [...], progress lines are passed to onProgress }.
 */
async function elevated(ops, { onProgress } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'powerscan-'));
  const inFile = path.join(dir, 'in.json');
  const outFile = path.join(dir, 'out.jsonl');
  fs.writeFileSync(inFile, JSON.stringify({ ops }), 'utf8');
  fs.writeFileSync(outFile, '');
  const body = fs.readFileSync(path.join(PS_DIR, 'elevated.ps1'), 'utf8');
  const inner = `& {\n${body}\n} -In ${psq(inFile)} -Out ${psq(outFile)}`;
  const outer = [
    'try {',
    `  $p = Start-Process -FilePath ${psq(POWERSHELL)} -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ' + $env:POWERSCAN_INNER) -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop`,
    '  exit $p.ExitCode',
    "} catch { [Console]::Out.WriteLine('CANCELLED'); exit 1223 }",
  ].join('\n');

  let seen = 0;
  const results = [];
  const readNew = () => {
    let text = '';
    try { text = fs.readFileSync(outFile, 'utf8'); } catch (_) { return; }
    const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/).filter(Boolean);
    for (; seen < lines.length; seen++) {
      const o = parseJson(lines[seen].replace(/^\uFEFF/, ''));
      if (!o) continue;
      if (o.progress && onProgress) onProgress(o);
      else if (o.op) results.push(o);
    }
  };
  let polling = true;
  const poller = (async () => { while (polling) { readNew(); await sleep(400); } })();
  const r = await run(POWERSHELL, [...BASE, '-EncodedCommand', encode(outer)], {
    env: { ...process.env, POWERSCAN_INNER: encode(inner) },
  });
  polling = false;
  await poller;
  readNew();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) { /* temp files */ }
  const cancelled = /CANCELLED/.test(r.stdout) || r.code === 1223;
  return { cancelled, results, code: r.code };
}

module.exports = { POWERSHELL, stream, json, command, elevated, psq };
