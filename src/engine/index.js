'use strict';
/* Picks the platform module and wires the four features to it. */
const { ScanRunner, PHASES: SCAN_PHASES } = require('./scan');
const { SpeedRunner } = require('./speed');
const { DriverRunner, PHASES: DRIVER_PHASES } = require('./drivers');
const { Traffic } = require('./traffic');

function loadPlatform() {
  if (process.platform === 'win32') return require('./win');
  if (process.platform === 'linux') return require('./linux');
  throw new Error('Power Scan runs on Windows and Linux.');
}

function createEngine(store) {
  const P = loadPlatform();
  const engine = {
    platform: P,
    scan: new ScanRunner(P, store),
    speed: new SpeedRunner(P, store),
    drivers: new DriverRunner(P, store),
    traffic: new Traffic(P),
    info: null,
    async refreshInfo() {
      engine.info = await P.info();
      P.drivers.restorePoints = !!engine.info.restoreOn;
      return engine.info;
    },
    phases: { scan: SCAN_PHASES.map((p) => p.label), drivers: DRIVER_PHASES.map((p) => p.label) },
  };
  return engine;
}

module.exports = { createEngine };
