'use strict';
/* Driver check: four passes, then issues the user can update, install, roll back or ignore. */
const { EventEmitter } = require('events');
const { makeFeed } = require('./util');

const PHASES = [
  { key: 'inventory', label: 'Inventory', w: 0.15 },
  { key: 'versions', label: 'Versions', w: 0.5 },
  { key: 'health', label: 'Health', w: 0.1 },
  { key: 'performance', label: 'Performance', w: 0.25 },
];

const pub = (i) => { const { data, key, ...rest } = i; return rest; };

class DriverRunner extends EventEmitter {
  constructor(platform, store) {
    super();
    this.P = platform;
    this.store = store;
    this.state = { status: 'idle', issues: [] };
    this.issues = new Map();
    this.queue = [];
    this.busy = false;
  }

  snapshot() { return { ...this.state, issues: [...this.issues.values()].map(pub) }; }

  stop() { if (this.ctrl) this.ctrl.abort(); }

  async start() {
    if (this.state.status === 'running' || this.busy) return;
    this.ctrl = new AbortController();
    const signal = this.ctrl.signal;
    this.issues.clear();
    const flagged = new Set();
    const notes = [];
    this.state = { status: 'running', phaseIdx: 0, progress: 0, checked: 0, startedAt: Date.now(), flagged: 0, issues: [] };
    const emit = (e) => this.emit('event', e);
    emit({ type: 'start', startedAt: this.state.startedAt });
    const feed = makeFeed((it) => emit({ type: 'item', ...it }));
    let base = 0;
    let last = 0;
    const progress = () => {
      const now = Date.now();
      if (now - last < 120) return;
      last = now;
      emit({ type: 'progress', progress: this.state.progress, phaseFrac: this.state.phaseFrac || 0, checked: this.state.checked, flagged: flagged.size });
    };
    const ctx = {
      signal,
      state: {},
      item: (it) => feed.push(it),
      count: (n) => { this.state.checked += n; progress(); },
      progress: (f) => {
        this.state.phaseFrac = Math.max(0, Math.min(1, f || 0));
        this.state.progress = base + PHASES[this.state.phaseIdx].w * this.state.phaseFrac;
        progress();
      },
      flag: (id) => { flagged.add(id); progress(); },
      note: (tone, text) => notes.push({ tone, text }),
    };
    try {
      for (let i = 0; i < PHASES.length && !signal.aborted; i++) {
        this.state.phaseIdx = i;
        this.state.phaseFrac = 0;
        emit({ type: 'phase', idx: i, progress: base });
        await this.P.drivers[PHASES[i].key](ctx);
        feed.flush();
        base += PHASES[i].w;
      }
      if (signal.aborted) { this.state = { status: 'stopped', issues: [] }; emit({ type: 'stopped' }); return; }
      const res = this.P.drivers.finish(ctx);
      const ignored = new Set(this.store.get('ignoredDrivers', []));
      for (const issue of res.issues) {
        if (issue.key && ignored.has(issue.key)) continue;
        this.issues.set(issue.id, { ...issue, state: 'open' });
      }
      this.state = {
        status: this.issues.size ? 'issues' : 'clean',
        progress: 1, finishedAt: Date.now(), startedAt: this.state.startedAt,
        total: res.total, devices: res.devices, healthy: res.healthy, notes, restoreAt: null,
      };
      this.store.set('lastDriverCheckAt', this.state.finishedAt);
      emit({ type: 'done', ...this.snapshot() });
    } catch (e) {
      this.state = { status: 'error', message: e.message, issues: [] };
      emit({ type: 'error', message: e.message });
    }
  }

  update(i) { this.emit('event', { type: 'issue', issue: pub(i) }); }

  ignore(id) {
    const i = this.issues.get(id);
    if (!i || i.state !== 'open') return;
    i.state = 'ignored';
    const list = this.store.get('ignoredDrivers', []);
    if (i.key && !list.includes(i.key)) this.store.set('ignoredDrivers', list.concat(i.key).slice(-300));
    this.update(i);
    this.checkResolved();
  }

  async act(ids) {
    const todo = ids.map((id) => this.issues.get(id)).filter((i) => i && i.state === 'open');
    const rollbacks = todo.filter((i) => i.kind === 'rollback' || i.kind === 'review');
    for (const i of rollbacks) {
      const r = await this.P.drivers.rollback(i);
      i.state = r.ok ? 'done' : 'failed';
      i.doneText = r.message;
      this.update(i);
    }
    const installs = todo.filter((i) => i.kind === 'update' || i.kind === 'install');
    for (const i of installs) { i.state = 'queued'; this.update(i); this.queue.push(i); }
    this.pump();
    this.checkResolved();
  }

  async pump() {
    if (this.busy || !this.queue.length) return;
    this.busy = true;
    const batch = this.queue.splice(0);
    const wantRestore = !!this.P.drivers.restorePoints && !this.state.restoreAsked;
    this.state.restoreAsked = this.state.restoreAsked || wantRestore;
    batch.forEach((i) => { i.state = 'working'; i.stepLabel = 'Waiting for permission'; this.update(i); });
    const r = await this.P.drivers.apply(batch, { restorePoint: wantRestore }, (id, label) => {
      for (const i of batch) {
        if (id === '*' || i.id === id) { i.stepLabel = label; this.update(i); }
        else if (i.stepLabel === 'Waiting for permission' || i.stepLabel === 'Creating a restore point') { i.stepLabel = 'Waiting for the driver before it'; this.update(i); }
      }
    });
    if (r.cancelled) {
      for (const i of batch) { i.state = 'open'; i.message = 'Installing drivers needs administrator permission.'; this.update(i); }
      this.state.restoreAsked = false;
    } else {
      if (r.restorePoint) { this.state.restoreAt = /^failed/.test(r.restorePoint) ? null : Date.now(); this.state.restoreNote = r.restorePoint; }
      for (const i of batch) {
        const x = r.results.find((y) => y.id === i.id) || { ok: false, message: 'Did not run' };
        i.state = x.ok ? 'done' : 'failed';
        if (!x.ok) i.doneText = x.message;
        if (x.ok && x.reboot) { i.restart = true; i.doneText += ' · restart to finish'; }
        this.update(i);
      }
      this.emit('event', { type: 'restore', restoreAt: this.state.restoreAt, note: this.state.restoreNote });
    }
    this.busy = false;
    this.checkResolved();
    if (this.queue.length) this.pump();
  }

  checkResolved() {
    if (this.state.status !== 'issues') return;
    const open = [...this.issues.values()].filter((i) => ['open', 'queued', 'working', 'failed'].includes(i.state));
    if (!open.length) { this.state.status = 'resolved'; this.emit('event', { type: 'resolved' }); }
  }
}

module.exports = { DriverRunner, PHASES };
