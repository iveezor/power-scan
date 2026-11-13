'use strict';
/* Speed measurements against Cloudflare's public speed test endpoints (speed.cloudflare.com). */
const https = require('https');
const crypto = require('crypto');
const dns = require('dns');

const HOST = 'speed.cloudflare.com';
const UA = 'PowerScan/1.0';
const agent = (n) => new https.Agent({ keepAlive: true, maxSockets: n });
const median = (a) => { if (!a.length) return null; const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };

/** Round-trip time of tiny requests on a warm connection, minus Cloudflare's own processing time. */
async function latency(count, signal, onSample) {
  const ag = agent(1);
  const vals = [];
  for (let i = 0; i <= count && !signal.aborted; i++) {
    const t0 = process.hrtime.bigint();
    const ms = await new Promise((resolve) => {
      const req = https.get({ host: HOST, path: '/__down?bytes=0', agent: ag, headers: { 'User-Agent': UA } }, (res) => {
        const t1 = process.hrtime.bigint();
        const serverMs = [...String(res.headers['server-timing'] || '').matchAll(/dur=([\d.]+)/g)].reduce((a, m) => a + parseFloat(m[1]), 0);
        res.resume();
        res.on('end', () => resolve(Number(t1 - t0) / 1e6 - serverMs));
      });
      req.on('error', () => resolve(null));
      req.setTimeout(4000, () => { req.destroy(); resolve(null); });
    });
    if (ms != null && i > 0) { vals.push(Math.max(0.5, ms)); onSample(ms); }
  }
  ag.destroy();
  if (!vals.length) return null;
  let jit = 0;
  for (let i = 1; i < vals.length; i++) jit += Math.abs(vals[i] - vals[i - 1]);
  return { ping: median(vals), jitter: vals.length > 1 ? jit / (vals.length - 1) : 0 };
}

/** Measures throughput: parallel streams for durationMs; result ignores the first 1.5 s of ramp-up. */
function transfer(kind, durationMs, streams, signal, onRate) {
  return new Promise((resolveAll) => {
    const ag = agent(streams);
    const start = Date.now();
    const end = start + durationMs;
    const reqs = new Set();
    const chunk = kind === 'up' ? crypto.randomBytes(256 * 1024) : null;
    const perUpload = 16 * 1024 * 1024;
    let bytes = 0;
    let done = false;
    let errors = 0;
    const one = () => new Promise((resolve) => {
      let req;
      const finish = () => { reqs.delete(req); resolve(); };
      if (kind === 'down') {
        req = https.get({ host: HOST, path: '/__down?bytes=25000000', agent: ag, headers: { 'User-Agent': UA } }, (res) => {
          res.on('data', (c) => { bytes += c.length; if (done) req.destroy(); });
          res.on('end', finish);
          res.on('close', finish);
        });
      } else {
        req = https.request({ method: 'POST', host: HOST, path: '/__up', agent: ag, headers: { 'User-Agent': UA, 'Content-Type': 'text/plain', 'Content-Length': perUpload } }, (res) => {
          res.resume();
          res.on('end', finish);
          res.on('close', finish);
        });
        let sent = 0;
        const pump = () => {
          while (sent < perUpload && !done) {
            const n = Math.min(chunk.length, perUpload - sent);
            sent += n;
            const ok = req.write(n === chunk.length ? chunk : chunk.subarray(0, n), () => { bytes += n; });
            if (!ok) { req.once('drain', pump); return; }
          }
          if (done) req.destroy(); else req.end();
        };
        pump();
      }
      req.on('error', () => { errors++; finish(); });
      req.on('close', finish);
      req.setTimeout(15000, () => req.destroy());
      reqs.add(req);
    });
    const loops = Array.from({ length: streams }, async () => {
      while (!done && !signal.aborted && Date.now() < end) {
        await one();
        if (errors > streams * 4) break;
      }
    });
    const samples = [];
    let last = 0;
    let lastT = start;
    const timer = setInterval(() => {
      const now = Date.now();
      const mbps = ((bytes - last) * 8) / ((now - lastT) / 1000) / 1e6;
      last = bytes;
      lastT = now;
      samples.push({ t: now - start, mbps });
      const recent = samples.slice(-4);
      onRate(recent.reduce((a, s) => a + s.mbps, 0) / recent.length);
      if (now >= end || signal.aborted) {
        done = true;
        for (const r of reqs) { try { r.destroy(); } catch (_) { /* gone */ } }
      }
    }, 250);
    Promise.all(loops).then(() => {
      clearInterval(timer);
      done = true;
      ag.destroy();
      const steady = samples.filter((s) => s.t > 1500);
      const mbps = steady.length ? steady.reduce((a, s) => a + s.mbps, 0) / steady.length : 0;
      resolveAll({ mbps, failed: bytes === 0 });
    });
  });
}

/**
 * Watches the connection once a second: ICMP ping to the router and to 1.1.1.1, and a DNS lookup
 * of a random name (so caches cannot answer). onSample(i, sample) after each second.
 */
async function monitor(seconds, { gateway, ping, dnsServers }, signal, onSample) {
  const resolver = new dns.promises.Resolver({ timeout: 1500, tries: 1 });
  if (dnsServers && dnsServers.length) { try { resolver.setServers(dnsServers); } catch (_) { /* keep defaults */ } }
  // Let the line settle after the upload test so leftover queues are not mistaken for a drop.
  await new Promise((r) => setTimeout(r, 2500));
  const samples = [];
  for (let i = 0; i < seconds && !signal.aborted; i++) {
    const t0 = Date.now();
    const lookup = (async () => {
      const s = Date.now();
      try {
        await resolver.resolve4(`ps${crypto.randomBytes(4).toString('hex')}.cloudflare.com`);
        return { ok: true, ms: Date.now() - s };
      } catch (e) {
        if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return { ok: true, ms: Date.now() - s };
        return { ok: false, ms: null };
      }
    })();
    const [gw, net, d] = await Promise.all([gateway ? ping(gateway) : Promise.resolve(null), ping('1.1.1.1'), lookup]);
    const sample = { gw, net, dns: d };
    samples.push(sample);
    onSample(i, sample);
    const wait = 1000 - (Date.now() - t0);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }
  return samples;
}

module.exports = { latency, transfer, monitor, median };
