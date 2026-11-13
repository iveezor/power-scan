'use strict';
/* The only bridge between the window and the app. The window passes ids and choices, never commands or paths. */
const { contextBridge, ipcRenderer } = require('electron');

const CHANNELS = new Set(['scan', 'speed', 'drivers', 'traffic', 'listener', 'win', 'info']);
const call = (name) => (...args) => ipcRenderer.invoke(name, ...args);

contextBridge.exposeInMainWorld('powerScan', {
  init: call('app:init'),
  on(channel, fn) {
    if (!CHANNELS.has(channel)) return () => {};
    const handler = (_event, data) => fn(data);
    ipcRenderer.on(channel, handler);
    return () => ipcRenderer.removeListener(channel, handler);
  },
  scan: { start: call('scan:start'), stop: call('scan:stop'), act: call('scan:act') },
  listener: { set: call('listener:set') },
  traffic: { act: call('traffic:act') },
  speed: { start: call('speed:start'), stop: call('speed:stop'), fix: call('speed:fix'), undoDns: call('speed:undoDns') },
  drivers: { start: call('drivers:start'), stop: call('drivers:stop'), act: call('drivers:act'), ignore: call('drivers:ignore') },
  win: { minimize: call('win:minimize'), toggleMaximize: call('win:maximize'), close: call('win:close') },
});
