'use strict';
/*
 * Drives the real app for a visual check and saves screenshots. Read-only: it opens confirmation
 * sheets and cancels them, and stops the virus scan early in the file pass.
 * Run: POWERSCAN_TEST_SCRIPT=tools/ui-test.js POWERSCAN_TEST_OUT=<dir> electron .
 */
module.exports = async (t) => {
  const q = (sel, prop = 'textContent') => t.exec(`(document.querySelector(${JSON.stringify(sel)}) || {})[${JSON.stringify(prop)}] || ''`);
  const click = (sel) => t.exec(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (el) el.click(); return !!el; })()`);
  const until = async (fn, maxMs) => { const end = Date.now() + maxMs; while (Date.now() < end) { if (await fn()) return true; await t.wait(700); } return false; };
  const steps = (process.env.POWERSCAN_TEST_STEPS || 'drivers,speed,scan').split(',');

  await t.wait(2500);
  await t.shot('01-scan-idle');
  t.log('scan chip:', await q('#scanChip'), '| engine:', await q('#scanEngine'), '| glance:', (await q('#scanGlance', 'innerText')).replace(/\n+/g, ' / '));

  if (steps.includes('drivers')) {
    await click('#tabDrivers');
    await t.wait(400);
    await t.shot('02-drivers-idle');
    await click('#drvPower');
    await t.wait(9000);
    await t.shot('03-drivers-running');
    await until(async () => !/Checking/.test(await q('#drvChip')), 240000);
    await t.wait(800);
    await t.shot('04-drivers-results');
    t.log('drivers chip:', await q('#drvChip'), '| caption:', await q('#drvCaption'));
    await click('[data-act="drv-do"]');
    await t.wait(600);
    await t.shot('05-drivers-confirm');
    t.log('driver confirm sheet:', (await q('#sheet', 'innerText')).replace(/\n+/g, ' / '));
    await click('[data-sheet="cancel"]');
    await t.exec("document.querySelector('#drvScroll').scrollTo({ top: 99999 })");
    await t.wait(800);
    await t.shot('06-drivers-bottom');
  }

  if (steps.includes('speed')) {
    await click('#tabSpeed');
    await t.wait(300);
    await click('#speedPower');
    await t.wait(7000);
    await t.shot('07-speed-running');
    await until(async () => !/Testing/.test(await q('#speedChip')), 120000);
    await t.wait(1000);
    await t.exec("document.querySelector('#speedScroll').scrollTo({ top: 0 })");
    await t.wait(600);
    await t.shot('08-speed-result');
    t.log('speed chip:', await q('#speedChip'), '| readouts:', (await q('#readouts', 'innerText')).replace(/\n+/g, ' '));
    await t.exec("document.querySelector('#speedScroll').scrollTo({ top: 99999 })");
    await t.wait(800);
    await t.shot('09-speed-diagnosis');
    t.log('diagnosis:', (await q('#diag', 'innerText')).replace(/\n+/g, ' / '));
  }

  if (steps.includes('scan')) {
    await click('#tabScan');
    await t.wait(300);
    await click('#scanPower');
    await t.wait(4000);
    await t.shot('10-scan-kernel');
    await until(async () => /pass 5/.test(await q('#scanChip')), 180000);
    await t.wait(15000);
    await t.shot('11-scan-files');
    t.log('scan chip during files:', await q('#scanChip'), '| counters:', (await q('#scanFeed .counters', 'innerText')).replace(/\n+/g, ' '));
    await click('#scanPower');
    await until(async () => /Stopped/.test(await q('#scanChip')), 30000);
    await t.wait(1200);
    await t.shot('12-scan-stopped');
    t.log('after stop:', (await q('#scanResults', 'innerText')).replace(/\n+/g, ' / ').slice(0, 600));
    await click('[data-act="f-remove"]');
    await t.wait(600);
    await t.shot('13-finding-confirm');
    t.log('finding confirm sheet:', (await q('#sheet', 'innerText')).replace(/\n+/g, ' / '));
    await click('[data-sheet="cancel"]');
  }
  t.log('done');
};
