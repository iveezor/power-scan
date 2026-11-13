'use strict';
/* Runs the five scan passes, keeps findings, and turns everything into events for the window. */
const { EventEmitter } = require('events');
const { makeFeed } = require('./util');

const PHASES = [
  { key: 'kernel', label: 'Kernel', w: 0.07 },
  { key: 'boot', label: 'Boot', w: 0.01 },
  { key: 'startup', label: 'Startup', w: 0.05 },
  { key: 'processes', label: 'Programs', w: 0.04 },
  { key: 'files', label: 'Files', w: 0.83 },
];

const publicFinding = (f) => {
  const { data, key, ...rest } = f;
  return rest;
};

class ScanRunner extends EventEmitter {
  constructor(platform, store) {
    super();
    this.P = platform;
    this.store = store;
    this.findings = new Map();
    this.state = { status: 'idle' };
    this.ctrl = null;
  }

  snapshot() {
    return { ...this.state, findings: [...this.findings.values()].map(publicFinding) };
  }

  get running() { return this.state.status === 'running'; }

  async start(info) {
    if (this.running) return;
    this.ctrl = new AbortController();
    const signal = this.ctrl.signal;
    this.findings.clear();
    const ignored = new Set(this.store.get('ignoredFindings', []));
    const notes = [];
    this.state = { status: 'running', phaseIdx: 0, progress: 0, checked: 0, startedAt: Date.now() };
    this.emit('event', { type: 'start', startedAt: this.state.startedAt, phases: PHASES.map((p) => p.label) });
    const feed = makeFeed((it) => this.emit('event', { type: 'item', ...it }));
    let phaseBase = 0;
    let lastProgress = 0;
    const emitProgress = () => {
      const now = Date.now();
      if (now - lastProgress < 120) return;
      lastProgress = now;
      this.emit('event', { type: 'progress', progress: this.state.progress, phaseFrac: this.state.phaseFrac || 0, checked: this.state.checked });
    };
    const ctx = {
      signal,
      status: info && info.status,
      item: (it) => feed.push(it),
      count: (n) => { this.state.checked += n; emitProgress(); },
      progress: (frac, checkedAbsolute) => {
        const f = Math.max(0, Math.min(1, frac || 0));
        this.state.phaseFrac = f;
        this.state.progress = phaseBase + PHASES[this.state.phaseIdx].w * f;
        if (typeof checkedAbsolute === 'number') this.state.checked = this.state.filesBase + checkedAbsolute;
        emitProgress();
      },
      finding: (f) => {
        if (f.key && ignored.has(f.key)) return;
        const id = 'f' + (this.findings.size + 1);
        const full = { id, state: 'open', ...f };
        this.findings.set(id, full);
        this.emit('event', { type: 'finding', finding: publicFinding(full) });
      },
      note: (tone, text) => { notes.push({ tone, text }); },
    };
    let error = null;
    for (let i = 0; i < PHASES.length && !signal.aborted; i++) {
      this.state.phaseIdx = i;
      this.state.phaseFrac = 0;
      this.state.progress = phaseBase;
      if (PHASES[i].key === 'files') this.state.filesBase = this.state.checked;
      this.emit('event', { type: 'phase', idx: i, progress: phaseBase });
      try {
        await this.P.scan[PHASES[i].key](ctx);
      } catch (e) {
        error = e;
        notes.push({ tone: 'warn', text: `The ${PHASES[i].label.toLowerCase()} pass stopped early: ${e.message}` });
      }
      feed.flush();
      phaseBase += PHASES[i].w;
    }
    if (signal.aborted) {
      this.state.status = 'stopped';
      this.emit('event', { type: 'stopped', progress: this.state.progress, findings: [...this.findings.values()].map(publicFinding) });
      return;
    }
    const list = [...this.findings.values()];
    this.state = {
      status: list.length ? 'threats' : 'clean',
      progress: 1,
      checked: this.state.checked,
      startedAt: this.state.startedAt,
      finishedAt: Date.now(),
      notes,
    };
    this.store.set('lastScanAt', this.state.finishedAt);
    this.emit('event', { type: 'done', ...this.snapshot(), error: error ? error.message : null });
  }

  stop() { if (this.ctrl) this.ctrl.abort(); }

  async act(id, action) {
    const f = this.findings.get(id);
    if (!f || (f.state !== 'open' && f.state !== 'failed')) return null;
    if (action === 'keep') {
      if (f.key) {
        const list = this.store.get('ignoredFindings', []);
        if (!list.includes(f.key)) this.store.set('ignoredFindings', list.concat(f.key).slice(-500));
      }
      f.state = 'kept';
      f.message = 'Kept · future scans skip it';
    } else if (action === 'remove' && f.primary) {
      f.state = 'removing';
      this.emit('event', { type: 'finding-update', finding: publicFinding(f) });
      let r;
      try { r = await this.P.scan.remove(f); } catch (e) { r = { state: 'failed', message: e.message }; }
      f.state = r.state;
      f.message = r.message;
      if (r.backup) {
        const q = this.store.get('quarantine', []);
        this.store.set('quarantine', q.concat({ at: Date.now(), name: f.name, path: f.path, backup: r.backup }).slice(-200));
      }
    } else return null;
    this.emit('event', { type: 'finding-update', finding: publicFinding(f) });
    const open = [...this.findings.values()].filter((x) => x.state === 'open' || x.state === 'removing' || x.state === 'failed');
    if (this.state.status === 'threats' && !open.length) {
      this.state.status = 'resolved';
      this.emit('event', { type: 'resolved' });
    }
    return publicFinding(f);
  }
}

module.exports = { ScanRunner, PHASES };
