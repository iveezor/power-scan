'use strict';
/*
 * Headless engine check. Read-only: runs the audits, a report-only Defender scan of this project's
 * assets folder, the driver check, a short speed test, and a Traffic hold on a temporary file.
 * Usage: node tools/check.js [scan|drivers|speed|traffic|parse|all]
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const which = process.argv[2] || 'all';
const P = process.platform === 'win32' ? require('../src/engine/win') : require('../src/engine/linux');

function fakeCtx(label) {
  const c = { items: 0, bad: [], findings: [], notes: [], checked: 0, last: 0 };
  const ctx = {
    signal: new AbortController().signal,
    state: {},
    item: (it) => { c.items++; if (it.tone) c.bad.push(`${it.file} -> ${it.sub}`); },
    count: (n) => { c.checked += n; },
    progress: (f) => { c.last = f; },
    finding: (f) => c.findings.push(`${f.sev} | ${f.name} | ${f.path}`),
    flag: () => {},
    note: (tone, text) => c.notes.push(`${tone}: ${text}`),
  };
  return { ctx, report: () => console.log(`  ${label}: ${c.items} feed lines, ${c.checked} checked, progress ${c.last.toFixed(2)}\n` + [...c.bad.map((b) => '    flagged line: ' + b), ...c.findings.map((f) => '    FINDING: ' + f), ...c.notes.map((n) => '    note: ' + n)].join('\n')) };
}

async function timed(label, fn) {
  const t0 = Date.now();
  try { await fn(); console.log(`  (${label} took ${((Date.now() - t0) / 1000).toFixed(1)} s)`); }
  catch (e) { console.log(`  ${label} FAILED: ${e.stack}`); }
}

async function main() {
  console.log('== info');
  const info = await P.info();
  console.log(JSON.stringify(info, null, 1).slice(0, 1500));

  if (which === 'parse' || which === 'all') {
    console.log('== Defender output parser');
    const sample = 'Scan starting...\nScan finished.\nScanning C:\\x found 1 threats.\n\n<===========================LIST OF DETECTED THREATS==========================>\n----------------------------- Threat information ------------------------------\nThreat                  : Virus:DOS/EICAR_Test_File\nResources               : 2 total\n    file                : C:\\Users\\demo\\Downloads\\eicar.com\n    containerfile       : C:\\Users\\demo\\Downloads\\test.zip\n-------------------------------------------------------------------------------\n';
    if (P.defender) console.log(' ', JSON.stringify(P.defender.parseThreats(sample)));
  }

  if (which === 'scan' || which === 'all') {
    console.log('== scan passes');
    for (const pass of ['kernel', 'boot', 'startup', 'processes']) {
      const { ctx, report } = fakeCtx(pass);
      await timed(pass, () => P.scan[pass](ctx));
      report();
    }
    if (P.defender) {
      console.log('== report-only Defender scan of the assets folder');
      await timed('defender', async () => {
        const r = await P.defender.scanPath(path.join(__dirname, '..', 'assets'), { remediate: false });
        console.log(`  exit ${r.code}, threats ${r.threats.length}, error ${r.error}`);
      });
    }
  }

  if (which === 'files') {
    console.log('== full file pass (report-only Defender scans, timed)');
    const t0 = Date.now();
    let lastLog = 0, lastLine = '', checked = 0, frac = 0;
    const ctx = {
      signal: new AbortController().signal,
      item: (it) => { lastLine = `${it.dir || ''}${it.file}${it.sub ? ' · ' + it.sub : ''}`; },
      progress: (f, c) => {
        frac = f; if (typeof c === 'number') checked = c;
        if (Date.now() - lastLog > 30000) { lastLog = Date.now(); console.log(`  ${((Date.now() - t0) / 60000).toFixed(1)} min: ${(f * 100).toFixed(0)}%, ${checked.toLocaleString('en-US')} files · ${lastLine.slice(0, 90)}`); }
      },
      count: () => {}, finding: (f) => console.log('  FINDING:', f.name, f.path), note: (tone, text) => console.log('  note:', text),
    };
    ctx.item = ((orig) => (it) => { orig(it); if (/pieces/.test(it.file)) console.log(`  ${((Date.now() - t0) / 1000).toFixed(1)} s: ${it.file} · ${it.sub}`); })(ctx.item);
    await P.scan.files(ctx);
    console.log(`  finished in ${((Date.now() - t0) / 60000).toFixed(1)} min, ${checked.toLocaleString('en-US')} files, ${(checked / ((Date.now() - t0) / 1000)).toFixed(0)} files/s`);
  }

  if (which === 'drivers' || which === 'all') {
    console.log('== driver check');
    const { ctx, report } = fakeCtx('drivers');
    for (const pass of ['inventory', 'versions', 'health', 'performance']) await timed(pass, () => P.drivers[pass](ctx));
    report();
    const res = P.drivers.finish(ctx);
    console.log(`  total ${res.total}, devices ${res.devices}, issues ${res.issues.length}`);
    for (const i of res.issues) console.log(`    ISSUE ${i.tag[1]} | ${i.kind} | ${i.name} | ${i.meta} | ${i.finds.map((f) => f[1].replace(/<\/?b>/g, '')).join(' / ')}`);
    console.log('  healthy sample:', res.healthy.slice(0, 5).map((h) => h.join(' ')).join(' | '));
  }

  if (which === 'speed' || which === 'all') {
    console.log('== network + short speed test');
    const st = require('../src/engine/speedtest');
    const { diagnose } = require('../src/engine/speed');
    const net = await P.net.info();
    console.log('  net', JSON.stringify(net));
    const sig = new AbortController().signal;
    const lat = await st.latency(8, sig, () => {});
    console.log('  latency', lat && { ping: lat.ping.toFixed(1), jitter: lat.jitter.toFixed(1) });
    const down = await st.transfer('down', 4000, 4, sig, () => {});
    console.log('  download Mbps', down.mbps.toFixed(1));
    const up = await st.transfer('up', 4000, 3, sig, () => {});
    console.log('  upload Mbps', up.mbps.toFixed(1));
    const samples = await st.monitor(5, { gateway: net.gateway, ping: P.net.ping, dnsServers: net.dns }, sig, (i, s) => console.log('   sample', i, JSON.stringify(s)));
    const d = diagnose({ ping: lat ? lat.ping : 0, jitter: lat ? lat.jitter : 0, down: down.mbps, up: up.mbps }, net, samples, P);
    console.log('  diagnosis', d.status, '|', d.text, '| fixes:', d.fixes.map((f) => f.id).join(','));
    console.log('  checks', JSON.stringify(d.checks));
  }

  if (which === 'traffic' || which === 'all') {
    console.log('== Traffic hold on a temporary file');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-traffic-'));
    const f = path.join(dir, 'harmless-test.txt');
    fs.writeFileSync(f, 'Power Scan traffic test\n');
    const held = await P.traffic.hold(f);
    console.log('  held:', held);
    if (process.platform === 'win32') {
      const { run } = require('../src/engine/util');
      console.log('  ACL while held:', (await run('icacls', [f])).stdout.split(/\r?\n/).filter((l) => /Everyone|S-1-1-0|\(DENY\)/i.test(l)).join(' | ').trim());
    }
    const c = await P.traffic.check(f);
    console.log('  check:', JSON.stringify(c));
    console.log('  released:', await P.traffic.release(f));
    if (process.platform === 'win32') {
      const { run } = require('../src/engine/util');
      console.log('  ACL after release:', (await run('icacls', [f])).stdout.split(/\r?\n/).filter((l) => /DENY/i.test(l)).join(' | ').trim() || 'no deny rule');
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });
