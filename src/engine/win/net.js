'use strict';
/* Windows network facts, ping, and the fixes Speed Test can apply. */
const path = require('path');
const ps = require('./ps');
const { run } = require('../util');

const PING = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'PING.EXE');

async function info() {
  const { objs } = await ps.json('net.ps1', [], { timeout: 60000 });
  const n = objs.find((o) => o.type === 'net') || { connected: false };
  return {
    connected: !!n.connected,
    gateway: n.gateway && n.gateway !== '0.0.0.0' ? n.gateway : null,
    adapter: n.alias || null,
    desc: n.desc || '',
    isWifi: !!n.isWifi,
    signal: typeof n.signal === 'number' ? n.signal : null,
    powerSaving: /enabled/i.test(n.powerSaving || '') ? true : /disabled/i.test(n.powerSaving || '') ? false : null,
    dns: n.dns || [],
    driverFile: n.driverFile || '',
    pnpId: n.pnpId || '',
  };
}

/** One ICMP echo. Success means a reply that carries TTL= (works in every Windows language). */
async function ping(ip) {
  const t0 = Date.now();
  const r = await run(PING, ['-n', '1', '-w', '900', ip], { timeout: 3000 });
  const ok = /TTL=/i.test(r.stdout);
  const m = r.stdout.match(/[=<]\s?(\d+)\s?ms/i);
  return { ok, ms: ok ? (m ? Math.max(1, Number(m[1])) : Date.now() - t0) : null };
}

const q = (s) => `"${s}"`;
const FIXES = {
  power: { label: 'Turn off Wi-Fi power saving', cmd: (a) => `Set-NetAdapterPowerManagement -Name ${q(a)} -AllowComputerToTurnOffDevice Disabled`, op: (a) => ({ op: 'wifi-powersave-off', alias: a }) },
  flush: { label: 'Clear the DNS cache', cmd: () => 'ipconfig /flushdns', op: () => ({ op: 'flushdns' }) },
  dns: { label: 'Use faster DNS (Cloudflare 1.1.1.1)', cmd: (a) => `Set-DnsClientServerAddress -InterfaceAlias ${q(a)} -ServerAddresses 1.1.1.1,1.0.0.1`, op: (a) => ({ op: 'dns-set', alias: a, servers: ['1.1.1.1', '1.0.0.1'] }) },
  renew: { label: 'Renew the IP address', cmd: (a) => `ipconfig /release ${q(a)}; ipconfig /renew ${q(a)}`, op: (a) => ({ op: 'renew', alias: a }) },
  reset: { label: 'Restart the network adapter', cmd: (a) => `Restart-NetAdapter -Name ${q(a)}`, op: (a) => ({ op: 'adapter-restart', alias: a }) },
};
const ORDER = ['power', 'flush', 'dns', 'renew', 'reset'];

function fixDefs(ids, net) {
  return ORDER.filter((id) => ids.includes(id)).map((id) => ({ id, label: FIXES[id].label, cmd: FIXES[id].cmd(net.adapter || 'Wi-Fi') }));
}

const askText = 'Windows asks for administrator permission once';

async function applyFixes(ids, net, onStep) {
  const chosen = ORDER.filter((id) => ids.includes(id) && FIXES[id]);
  const ops = chosen.map((id) => ({ ...FIXES[id].op(net.adapter), id }));
  const r = await ps.elevated(ops, { onProgress: (o) => { if (o.id) onStep(o.id, 'running'); } });
  if (r.cancelled) return { cancelled: true, results: [] };
  const dnsRes = r.results.find((x) => x.op === 'dns-set' && x.ok);
  return {
    cancelled: false,
    results: chosen.map((id) => {
      const x = r.results.find((y) => y.id === id);
      return { id, ok: !!(x && x.ok), message: x ? x.message : 'Did not run' };
    }),
    dnsPrevious: dnsRes ? dnsRes.previous : null,
  };
}

async function undoDns(net, previous) {
  const r = await ps.elevated([{ op: 'dns-restore', alias: net.adapter, static: !!(previous && previous.static), servers: (previous && previous.servers) || [] }]);
  if (r.cancelled) return { ok: false, cancelled: true };
  return { ok: r.results.length > 0 && r.results.every((x) => x.ok) };
}

module.exports = { info, ping, fixDefs, applyFixes, undoDns, askText };
