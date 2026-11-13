'use strict';
/*
 * Traffic: watches download folders. Every new file is held (it cannot be run), scanned, then
 * released if clean or kept held until the user chooses Remove or Keep.
 */
const { EventEmitter } = require('events');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { uid, sleep } = require('./util');

const TEMP_NAME = /(\.(crdownload|part|partial|download|tmp|opdownload|filepart|!ut|aria2)$)|(^~\$)|(^\.~)|(^desktop\.ini$)|(^thumbs\.db$)|(^\.ds_store$)/i;

const humanSize = (n) => (n >= 1e9 ? (n / 1e9).toFixed(1) + ' GB' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' MB' : n >= 1e3 ? Math.round(n / 1e3) + ' KB' : n + ' B');

class Traffic extends EventEmitter {
  constructor(platform) {
    super();
    this.P = platform;
    this.items = [];
    this.watchers = [];
    this.known = new Set();
    this.pending = new Map();
    this.active = false;
  }

  publicItem(it) {
    const { file, ...rest } = it;
    return rest;
  }

  snapshot() { return this.items.slice(0, 30).map((it) => this.publicItem(it)); }

  async start(dirs) {
    this.stop();
    this.active = true;
    this.dirs = dirs.filter((d) => { try { return fs.statSync(d).isDirectory(); } catch (_) { return false; } });
    for (const dir of this.dirs) {
      try {
        for (const name of await fsp.readdir(dir)) this.known.add(path.join(dir, name).toLowerCase());
      } catch (_) { /* unreadable folder */ }
      try {
        const w = fs.watch(dir, { persistent: true }, (_ev, name) => { if (name) this.onEvent(dir, String(name)); });
        w.on('error', () => { /* folder removed */ });
        this.watchers.push(w);
      } catch (_) { /* cannot watch */ }
    }
    return this.dirs;
  }

  stop() {
    this.active = false;
    for (const w of this.watchers) { try { w.close(); } catch (_) { /* closed */ } }
    this.watchers = [];
    for (const t of this.pending.values()) clearTimeout(t);
    this.pending.clear();
  }

  onEvent(dir, name) {
    if (!this.active || TEMP_NAME.test(path.basename(name))) return;
    const file = path.join(dir, name);
    clearTimeout(this.pending.get(file));
    this.pending.set(file, setTimeout(() => { this.pending.delete(file); this.consider(file); }, 900));
  }

  async consider(file) {
    const key = file.toLowerCase();
    let st;
    try { st = await fsp.stat(file); } catch (_) { this.known.delete(key); return; }
    if (!st.isFile() || this.known.has(key)) return;
    for (let i = 0; i < 90; i++) {
      await sleep(700);
      let st2;
      try { st2 = await fsp.stat(file); } catch (_) { return; }
      if (st2.size === st.size && st2.mtimeMs === st.mtimeMs) break;
      st = st2;
    }
    if (this.known.has(key) || !this.active) return;
    this.known.add(key);
    this.process(file, st.size);
  }

  update(it) { this.emit('event', { type: 'update', item: this.publicItem(it) }); }

  async process(file, size) {
    const it = {
      id: uid('t'), file, name: path.basename(file), size: humanSize(size),
      from: path.basename(path.dirname(file)), state: 'locked', pct: 0, at: Date.now(),
    };
    this.items.unshift(it);
    if (this.items.length > 60) this.items.length = 60;
    this.emit('event', { type: 'add', item: this.publicItem(it) });
    const held = await this.P.traffic.hold(file);
    if (!fs.existsSync(file)) return this.gone(it);
    it.state = 'checking';
    it.holdFailed = !held;
    this.update(it);
    const t0 = Date.now();
    const expect = 1500 + Math.min(20000, size / 4e6 * 1000);
    const ticker = setInterval(() => { it.pct = Math.min(0.95, (Date.now() - t0) / expect); this.update(it); }, 250);
    let res;
    try { res = await this.P.traffic.check(file); } catch (e) { res = { clean: false, error: e.message }; }
    clearInterval(ticker);
    it.pct = 1;
    if (!fs.existsSync(file)) return this.gone(it);
    if (res.threat) {
      it.state = 'held';
      it.threat = res.threat;
      it.what = res.what;
      this.update(it);
      this.emit('held', this.publicItem(it));
      return;
    }
    if (res.error && !res.clean) {
      if (held) await this.P.traffic.release(file);
      it.state = 'unchecked';
      it.what = res.error;
      this.update(it);
      return;
    }
    if (held) await this.P.traffic.release(file);
    it.state = 'cleared';
    this.update(it);
  }

  gone(it) {
    it.state = 'gone';
    it.what = `${this.P.traffic.scannerName} removed it as it arrived. It never ran.`;
    this.update(it);
    this.emit('held', this.publicItem(it));
  }

  async act(id, action) {
    const it = this.items.find((x) => x.id === id);
    if (!it || it.state !== 'held') return null;
    if (action === 'remove') {
      const r = await this.P.traffic.remove(it.file);
      it.state = r.ok ? 'removed' : 'held';
      it.message = r.message;
    } else if (action === 'keep') {
      await this.P.traffic.release(it.file);
      it.state = 'released';
    } else return null;
    this.update(it);
    return this.publicItem(it);
  }
}

module.exports = { Traffic };
