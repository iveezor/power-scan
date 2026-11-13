'use strict';
/* Speed Test: ping, download, upload, a 30-second drop monitor, a diagnosis, and confirmed fixes. */
const { EventEmitter } = require('events');
const st = require('./speedtest');

const round1 = (n) => Math.round(n * 10) / 10;
const avg = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

function diagnose(r, net, samples, platform) {
  const n = samples.length || 1;
  const netOk = samples.map((s) => s.net && s.net.ok);
  const runs = [];
  let start = -1;
  netOk.forEach((ok, i) => {
    if (!ok && start < 0) start = i;
    if (ok && start >= 0) { runs.push([start, i - 1]); start = -1; }
  });
  if (start >= 0) runs.push([start, netOk.length - 1]);
  const drops = runs.length;
  const loss = round1((100 * netOk.filter((x) => !x).length) / n);
  const gwAnswers = samples.some((s) => s.gw && s.gw.ok);
  const linkDrops = runs.filter(([a, b]) => {
    const seg = samples.slice(a, b + 1);
    return gwAnswers && seg.filter((s) => s.gw && !s.gw.ok).length >= Math.ceil(seg.length / 2);
  }).length;
  const dnsSamples = samples.filter((s) => s.net && s.net.ok);
  const dnsOk = dnsSamples.filter((s) => s.dns && s.dns.ok);
  const dnsAvg = dnsOk.length ? Math.round(st.median(dnsOk.map((s) => s.dns.ms))) : null;
  const dnsFails = dnsSamples.length - dnsOk.length;
  const dnsBad = dnsAvg == null ? dnsSamples.length > 0 : dnsAvg > 150 || dnsFails >= 3;
  const gwMs = st.median(samples.filter((s) => s.gw && s.gw.ok).map((s) => s.gw.ms));
  const netMs = st.median(samples.filter((s) => s.net && s.net.ok).map((s) => s.net.ms));
  const weak = net.isWifi && net.signal != null && net.signal < 45;
  const powerSave = net.isWifi && net.powerSaving === true;
  const jitterHigh = r.jitter > 30;
  const usesCloudflare = (net.dns || []).includes('1.1.1.1');

  const checks = [];
  checks.push([drops ? 'warn' : 'ok', 'Connection', drops ? `dropped ${drops}x (${runs.map(([a, b]) => `${b - a + 1} s`).join(', ')})` : 'no drops in 30 s']);
  if (net.gateway) checks.push([gwAnswers ? (linkDrops ? 'warn' : 'ok') : 'warn', `Router ${net.gateway}`, gwAnswers ? (linkDrops ? `${gwMs} ms, silent during drops` : `${gwMs} ms`) : 'does not answer pings']);
  if (net.isWifi && net.signal != null) checks.push([weak ? 'warn' : 'ok', 'Wi-Fi signal', `${net.signal}%${weak ? ' · weak' : ''}`]);
  if (net.isWifi && net.powerSaving != null) checks.push([powerSave && (drops || weak) ? 'warn' : 'ok', 'Wi-Fi power saving', powerSave ? 'on' : 'off']);
  checks.push([dnsBad ? 'bad' : 'ok', 'DNS lookups', dnsAvg != null ? `${dnsAvg} ms typical${dnsFails ? `, ${dnsFails} failed` : ''}` : 'not answering']);
  checks.push([jitterHigh ? 'warn' : 'ok', 'Internet 1.1.1.1', netMs != null ? `${netMs} ms${jitterHigh ? `, jitter ${Math.round(r.jitter)} ms` : ''}` : 'not answering']);

  const text = [];
  if (drops && linkDrops) {
    text.push(`The router stopped answering during ${drops === 1 ? 'the drop' : 'the drops'}, so the problem is the link between this computer and the router, not your internet provider.`);
    if (powerSave) text.push('Power saving on the Wi-Fi adapter often causes this.');
    if (weak) text.push('The Wi-Fi signal is weak, so moving closer to the router also helps.');
  } else if (drops && gwAnswers) {
    text.push(`The router kept answering while the internet stopped ${plural(drops, 'time')}, so the drops are between the router and your provider. Restarting the router is the usual first step; this computer cannot fix that part.`);
  } else if (drops) {
    text.push(`The internet stopped answering ${plural(drops, 'time')}. Your router does not answer pings, so Power Scan cannot tell whether the problem is the Wi-Fi link or your provider.`);
  }
  if (dnsBad) text.push(dnsAvg != null ? `DNS lookups are slow (${dnsAvg} ms typical), so pages take longer to start loading.` : 'Your DNS server is not answering, so websites cannot be found.');
  if (jitterHigh) text.push(`Ping varies a lot (${Math.round(r.jitter)} ms jitter), which makes calls and games stutter.`);
  const bad = drops > 0 || loss >= 3 || dnsBad || jitterHigh || weak;
  if (!bad) text.push('No drops in 30 seconds and speeds held steady. Nothing needs fixing.');

  const ids = [];
  if (powerSave && (linkDrops || weak || drops)) ids.push('power');
  if (dnsBad) ids.push('flush');
  if (dnsBad && !usesCloudflare) ids.push('dns');
  if (linkDrops || (drops && !gwAnswers)) ids.push('renew');
  if (linkDrops) ids.push('reset');
  const fixes = bad && net.adapter ? platform.net.fixDefs(ids, net) : [];

  return {
    status: bad ? 'bad' : 'good',
    result: { ...r, loss, drops, dns: dnsAvg, dropText: runs.map(([a, b]) => `${b - a + 1} s`).join(' and ') },
    checks,
    text: text.join(' '),
    fixes,
    askText: platform.net.askText,
  };
}

class SpeedRunner extends EventEmitter {
  constructor(platform, store) {
    super();
    this.P = platform;
    this.store = store;
    this.state = { status: 'idle' };
    this.ctrl = null;
  }

  snapshot() { return this.state; }

  stop() { if (this.ctrl) this.ctrl.abort(); }

  async start(retest = false) {
    if (this.state.status === 'running' || this.state.status === 'retest' || this.state.status === 'fixing') return;
    const prev = this.state;
    this.ctrl = new AbortController();
    const signal = this.ctrl.signal;
    this.state = { status: retest ? 'retest' : 'running', phase: 0, startedAt: Date.now(), before: retest ? prev.diagnosis && prev.diagnosis.result : null, applied: retest ? prev.applied : null, fixSteps: retest ? prev.fixSteps : null, dnsPrevious: retest ? prev.dnsPrevious : this.store.get('dnsPrevious', null) };
    const emit = (e) => this.emit('event', e);
    emit({ type: 'start', retest });
    try {
      const net = await this.P.net.info();
      this.state.net = net;
      if (!net.connected) throw new Error('This computer is not connected to a network.');
      const r = {};
      emit({ type: 'phase', idx: 0 });
      const lat = await st.latency(20, signal, (ms) => emit({ type: 'live', idx: 0, value: ms }));
      if (signal.aborted) throw new Error('stopped');
      if (!lat) throw new Error("Could not reach Cloudflare's speed test servers. Check the internet connection.");
      r.ping = Math.round(lat.ping);
      r.jitter = Math.round(lat.jitter);
      emit({ type: 'value', key: 'ping', value: r.ping });
      emit({ type: 'value', key: 'jitter', value: r.jitter });

      emit({ type: 'phase', idx: 1 });
      const down = await st.transfer('down', 9000, 6, signal, (v) => emit({ type: 'live', idx: 1, value: v }));
      if (signal.aborted) throw new Error('stopped');
      r.down = Math.round(down.mbps * 10) / 10;
      emit({ type: 'value', key: 'down', value: r.down });

      emit({ type: 'phase', idx: 2 });
      const up = await st.transfer('up', 8000, 4, signal, (v) => emit({ type: 'live', idx: 2, value: v }));
      if (signal.aborted) throw new Error('stopped');
      r.up = Math.round(up.mbps * 10) / 10;
      emit({ type: 'value', key: 'up', value: r.up });

      emit({ type: 'phase', idx: 3, gateway: net.gateway });
      const samples = await st.monitor(30, { gateway: net.gateway, ping: this.P.net.ping, dnsServers: net.dns }, signal, (i, s) => emit({ type: 'sample', i, sample: s }));
      if (signal.aborted) throw new Error('stopped');
      const diagnosis = diagnose(r, net, samples, this.P);
      this.state = { ...this.state, status: retest ? 'fixed' : diagnosis.status, diagnosis, samples, finishedAt: Date.now() };
      emit({ type: 'done', state: this.state });
    } catch (e) {
      if (signal.aborted || e.message === 'stopped') {
        this.state = { status: 'stopped' };
        emit({ type: 'stopped' });
      } else {
        this.state = { status: 'error', message: e.message };
        emit({ type: 'error', message: e.message });
      }
    }
  }

  async fix(ids) {
    const s = this.state;
    if (!s.diagnosis || !s.net || s.status === 'fixing') return;
    const allowed = new Set(s.diagnosis.fixes.map((f) => f.id));
    const chosen = ids.filter((id) => allowed.has(id));
    if (!chosen.length) return;
    s.status = 'fixing';
    s.applied = chosen;
    s.fixSteps = s.diagnosis.fixes.filter((f) => chosen.includes(f.id)).map((f) => ({ ...f, st: 'pending' }));
    this.emit('event', { type: 'fixing', steps: s.fixSteps });
    const r = await this.P.net.applyFixes(chosen, s.net, (id, state) => {
      for (const step of s.fixSteps) {
        if (step.st === 'running') step.st = 'done';
        if (step.id === id) step.st = state;
      }
      this.emit('event', { type: 'fixing', steps: s.fixSteps });
    });
    if (r.cancelled) {
      s.status = s.diagnosis.status;
      this.emit('event', { type: 'fix-cancelled', state: s });
      return;
    }
    for (const step of s.fixSteps) {
      const x = r.results.find((y) => y.id === step.id);
      step.st = x && x.ok ? 'done' : 'failed';
      step.message = x ? x.message : '';
    }
    if (r.dnsPrevious) { s.dnsPrevious = r.dnsPrevious; this.store.set('dnsPrevious', r.dnsPrevious); }
    this.emit('event', { type: 'fixing', steps: s.fixSteps, waiting: true });
    await new Promise((res) => setTimeout(res, 6000));
    s.status = 'idle-before-retest';
    this.start(true);
  }

  async undoDns() {
    const prev = this.state.dnsPrevious || this.store.get('dnsPrevious', null);
    const net = this.state.net || (await this.P.net.info());
    if (!prev || !net.adapter) return { ok: false };
    const r = await this.P.net.undoDns(net, prev);
    if (r.ok) { this.store.set('dnsPrevious', null); this.state.dnsPrevious = null; }
    return r;
  }
}

module.exports = { SpeedRunner, diagnose };
