'use strict';
/* Shared helpers for the engine. Programs are always started without a shell. */
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Runs a program and resolves with { code, stdout, stderr }. Never rejects.
 * opts: timeout (ms), signal (AbortSignal), onLine(line) for streaming stdout,
 *       collect (default true; false keeps stdout out of memory), input (string for stdin), env, cwd.
 */
function run(cmd, args = [], opts = {}) {
  return new Promise((resolve) => {
    let out = '';
    let err = '';
    let buf = '';
    let child;
    const collect = opts.collect !== false;
    try {
      child = spawn(cmd, args, { windowsHide: true, env: opts.env || process.env, cwd: opts.cwd });
    } catch (e) {
      resolve({ code: -1, stdout: '', stderr: String(e) });
      return;
    }
    const kill = () => { try { child.kill(); } catch (_) { /* already gone */ } };
    const timer = opts.timeout ? setTimeout(kill, opts.timeout) : null;
    if (opts.signal) {
      if (opts.signal.aborted) kill();
      else opts.signal.addEventListener('abort', kill, { once: true });
    }
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => {
      if (collect) out += d;
      if (opts.onLine) {
        buf += d;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).replace(/\r$/, '');
          buf = buf.slice(i + 1);
          if (line) { try { opts.onLine(line); } catch (_) { /* a bad line must not stop the run */ } }
        }
      }
    });
    child.stderr.on('data', (d) => { if (err.length < 200000) err += d; });
    child.on('error', (e) => {
      if (timer) clearTimeout(timer);
      resolve({ code: -1, stdout: out, stderr: err + String(e) });
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      if (opts.onLine && buf.trim()) { try { opts.onLine(buf.replace(/\r$/, '')); } catch (_) { /* ignore */ } }
      resolve({ code, stdout: out, stderr: err, aborted: !!(opts.signal && opts.signal.aborted) });
    });
    if (opts.input != null) child.stdin.end(opts.input);
    else child.stdin.end();
  });
}

function parseJson(text, fallback = null) {
  try { return JSON.parse(text); } catch (_) { return fallback; }
}

let seq = 0;
const uid = (prefix) => prefix + (++seq).toString(36) + Math.floor(Math.random() * 1296).toString(36);

const sleep = (ms, signal) => new Promise((resolve) => {
  const t = setTimeout(resolve, ms);
  if (signal) signal.addEventListener('abort', () => { clearTimeout(t); resolve(); }, { once: true });
});

/** Small JSON settings file in the app's data folder. */
class Store {
  constructor(file) {
    this.file = file;
    this.data = parseJson(readText(file), {}) || {};
    this.timer = null;
  }
  get(key, fallback) { return Object.prototype.hasOwnProperty.call(this.data, key) ? this.data[key] : fallback; }
  set(key, value) {
    this.data[key] = value;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.flush(), 300);
  }
  flush() {
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify(this.data, null, 2));
    } catch (_) { /* settings are a convenience */ }
  }
}

function readText(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch (_) { return ''; }
}

function exists(p) {
  try { fs.accessSync(p); return true; } catch (_) { return false; }
}

/** Quotes a value for /bin/sh. Used only for Linux helper scripts run through pkexec. */
function shQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

/** Throttles a stream of feed items: lines with a tone go out at once, plain lines at most every `ms`. */
function makeFeed(emit, ms = 70) {
  let pending = null;
  let timer = null;
  const flush = () => { timer = null; if (pending) { emit(pending); pending = null; } };
  return {
    push(item) {
      if (item.tone) { if (pending) { emit(pending); pending = null; } emit(item); return; }
      pending = item;
      if (!timer) timer = setTimeout(flush, ms);
    },
    flush() { clearTimeout(timer); flush(); },
  };
}

module.exports = { run, parseJson, uid, sleep, Store, readText, exists, shQuote, makeFeed };
