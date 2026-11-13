'use strict';
/* Windows platform module: Microsoft Defender, PowerShell audits, Windows Update and network tools. */
const defender = require('./defender');
const scan = require('./scan');
const net = require('./net');
const drivers = require('./drivers');
const traffic = require('./traffic');

async function info() {
  const st = await defender.status();
  const d = st.defender || {};
  const active = d.mode === 'Normal' && d.av;
  return {
    platform: 'win',
    osName: 'Windows',
    engineLabel: active ? `Defender ${d.engine || ''}`.trim() : 'Defender not active',
    fileScanner: active,
    status: st,
    glance: [
      ['Real-time protection', d.rtp ? 'On' : 'Off', d.rtp ? 'ok' : 'warn'],
      ['Memory integrity', st.hvci ? 'On' : 'Off', st.hvci ? 'ok' : 'warn'],
    ],
    driverSource: 'Source · Windows Update',
    driverGlance: [
      ['Update source', 'Windows Update', 'ok'],
      ['Restore point first', st.restoreOn ? 'On' : 'System Restore off', st.restoreOn ? 'ok' : 'warn'],
    ],
    restoreOn: !!st.restoreOn,
    notes: active ? [] : ['Microsoft Defender is not the active antivirus, so Power Scan checks the kernel, boot, startup and running programs but skips the file pass.'],
  };
}

module.exports = { info, scan, net, drivers, traffic, defender };
