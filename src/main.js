'use strict';
/* Power Scan main process: window, tray, Passive Listener, notifications and the bridge to the engine. */
const { app, BrowserWindow, ipcMain, Tray, Menu, Notification, nativeImage, nativeTheme } = require('electron');
const fs = require('fs');
const path = require('path');
const { Store } = require('./engine/util');
const { createEngine } = require('./engine');

const ASSETS = path.join(__dirname, '..', 'assets');
const startHidden = process.argv.includes('--hidden');

if (process.env.POWERSCAN_TEST_SCRIPT) app.setPath('userData', path.join(app.getPath('temp'), 'power-scan-test-profile'));
if (!app.requestSingleInstanceLock()) { app.quit(); process.exit(0); }
if (process.platform === 'win32') app.setAppUserModelId('com.powerscan.app');

let win = null;
let tray = null;
let store = null;
let engine = null;
let quitting = false;
const listener = { on: false, phase: 'off', note: '', watch: [] };

const send = (channel, data) => { if (win && !win.isDestroyed()) win.webContents.send(channel, data); };
const visible = () => !!(win && !win.isDestroyed() && win.isVisible() && !win.isMinimized());

function notify(title, body) {
  if (process.platform === 'win32' && tray) {
    tray.displayBalloon({ title, content: body, iconType: 'none', icon: nativeImage.createFromPath(path.join(ASSETS, 'icon.png')) });
    return;
  }
  if (Notification.isSupported()) new Notification({ title, body, icon: path.join(ASSETS, 'icon.png') }).show();
}

/* ---------- window ---------- */
function createWindow() {
  const testMode = !!process.env.POWERSCAN_TEST_SCRIPT;
  win = new BrowserWindow({
    width: 360, height: 680, minWidth: 340, minHeight: 560,
    x: testMode ? 40 : undefined, y: testMode ? 40 : undefined,
    frame: false, show: false, resizable: true, maximizable: true,
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#1a1d21' : '#f3f5f7',
    title: 'Power Scan',
    icon: path.join(ASSETS, process.platform === 'win32' ? 'icon.ico' : 'icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true, spellcheck: false },
  });
  win.removeMenu();
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.once('ready-to-show', () => {
    if (!startHidden || testMode) win.show();
    if (testMode) runTestScript();
  });
  win.on('maximize', () => send('win', { maximized: true }));
  win.on('unmaximize', () => send('win', { maximized: false }));
  win.on('close', (e) => {
    if (!quitting && listener.on) {
      e.preventDefault();
      win.hide();
      if (!store.get('trayHintShown')) {
        store.set('trayHintShown', true);
        notify('Power Scan is still running', 'Passive Listener keeps checking downloads from the tray.');
      }
    }
  });
  win.on('closed', () => { win = null; });
}

function showWindow() {
  if (!win) createWindow();
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
}

/* ---------- tray (exists while Passive Listener is on) ---------- */
function updateTray() {
  if (!listener.on) {
    if (tray) { tray.destroy(); tray = null; }
    return;
  }
  if (!tray) {
    tray = new Tray(nativeImage.createFromPath(path.join(ASSETS, 'tray.png')));
    tray.on('click', showWindow);
    tray.on('balloon-click', showWindow);
  }
  tray.setToolTip(listener.phase === 'listening' ? 'Power Scan · Passive Listener on' : 'Power Scan · running the first full scan');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Open Power Scan', click: showWindow },
    { label: 'Passive Listener', type: 'checkbox', checked: listener.on, click: (item) => setListener(item.checked) },
    { type: 'separator' },
    { label: 'Quit Power Scan', click: () => { quitting = true; app.quit(); } },
  ]));
}

/* ---------- start with the computer while Passive Listener is on ---------- */
function setStartAtLogin(on) {
  try {
    if (process.platform === 'win32') {
      app.setLoginItemSettings({ openAtLogin: on, args: ['--hidden'] });
    } else if (process.platform === 'linux') {
      const dir = path.join(app.getPath('home'), '.config', 'autostart');
      const file = path.join(dir, 'power-scan.desktop');
      if (on) {
        const exe = process.env.APPIMAGE || process.execPath;
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(file, `[Desktop Entry]\nType=Application\nName=Power Scan\nExec="${exe}" --hidden\nIcon=${path.join(ASSETS, 'icon.png')}\nX-GNOME-Autostart-enabled=true\n`);
      } else if (fs.existsSync(file)) fs.unlinkSync(file);
    }
  } catch (_) { /* optional convenience */ }
}

/* ---------- Passive Listener ---------- */
function sendListener() {
  send('listener', { ...listener });
  updateTray();
}

async function startTraffic() {
  const dirs = [app.getPath('downloads'), app.getPath('desktop')];
  const watched = await engine.traffic.start(dirs);
  listener.phase = 'listening';
  listener.watch = watched.map((d) => path.basename(d));
  sendListener();
}

async function setListener(on) {
  listener.note = '';
  if (on) {
    listener.on = true;
    store.set('listenerOn', true);
    setStartAtLogin(true);
    if (store.get('lastScanAt') && !engine.scan.running) await startTraffic();
    else {
      listener.phase = 'baseline';
      sendListener();
      if (!engine.scan.running) engine.scan.start(engine.info);
    }
  } else {
    listener.on = false;
    listener.phase = 'off';
    store.set('listenerOn', false);
    setStartAtLogin(false);
    engine.traffic.stop();
    sendListener();
  }
  return { ...listener };
}

/* ---------- engine events ---------- */
function wireEngine() {
  engine.scan.on('event', (e) => {
    send('scan', e);
    if (e.type === 'done') {
      if (listener.on && listener.phase === 'baseline') startTraffic();
      if (!visible()) {
        const n = (e.findings || []).length;
        notify('Scan finished', n ? `${n} item${n === 1 ? '' : 's'} need your decision.` : 'No threats found.');
      }
    }
    if (e.type === 'stopped' && listener.phase === 'baseline') {
      listener.on = false;
      listener.phase = 'off';
      listener.note = 'needs one full scan first';
      store.set('listenerOn', false);
      setStartAtLogin(false);
      sendListener();
    }
  });
  engine.speed.on('event', (e) => send('speed', e));
  engine.drivers.on('event', (e) => {
    send('drivers', e);
    if (e.type === 'done' && !visible()) notify('Driver check finished', e.issues.length ? `${e.issues.length} drivers need attention.` : 'All drivers are healthy.');
  });
  engine.traffic.on('event', (e) => send('traffic', e));
  engine.traffic.on('held', (it) => {
    send('traffic', { type: 'held', item: it });
    if (it.state === 'gone') notify('Download removed', `${engine.platform.traffic.scannerName} removed ${it.name} as it arrived. It never ran.`);
    else if (!visible()) notify('Traffic held a download', `${it.name} is ${it.threat}. It was not opened. Open Power Scan to remove or keep it.`);
  });
}

/* ---------- IPC (every input is checked here) ---------- */
const str = (v, max = 64) => typeof v === 'string' && v.length > 0 && v.length <= max;
const strList = (v, max = 50) => Array.isArray(v) && v.length <= max && v.every((x) => str(x));

function wireIpc() {
  ipcMain.handle('app:init', async () => {
    if (!engine.info) await engine.refreshInfo().catch((e) => { engine.info = { platform: process.platform === 'win32' ? 'win' : 'linux', notes: [String(e.message)], glance: [], driverGlance: [] }; });
    return {
      info: engine.info,
      phases: engine.phases,
      scan: engine.scan.snapshot(),
      speed: engine.speed.snapshot(),
      drivers: engine.drivers.snapshot(),
      traffic: engine.traffic.snapshot(),
      listener: { ...listener },
      lastScanAt: store.get('lastScanAt', null),
      lastDriverCheckAt: store.get('lastDriverCheckAt', null),
      maximized: !!(win && win.isMaximized()),
      dark: nativeTheme.shouldUseDarkColors,
    };
  });
  ipcMain.handle('scan:start', () => { if (!engine.scan.running) engine.scan.start(engine.info); return true; });
  ipcMain.handle('scan:stop', () => { engine.scan.stop(); return true; });
  ipcMain.handle('scan:act', (_e, id, action) => (str(id) && ['remove', 'keep'].includes(action) ? engine.scan.act(id, action) : null));
  ipcMain.handle('listener:set', (_e, on) => setListener(on === true));
  ipcMain.handle('traffic:act', (_e, id, action) => (str(id) && ['remove', 'keep'].includes(action) ? engine.traffic.act(id, action) : null));
  ipcMain.handle('speed:start', () => { engine.speed.start(false); return true; });
  ipcMain.handle('speed:stop', () => { engine.speed.stop(); return true; });
  ipcMain.handle('speed:fix', (_e, ids) => { if (strList(ids, 10)) engine.speed.fix(ids); return true; });
  ipcMain.handle('speed:undoDns', () => engine.speed.undoDns());
  ipcMain.handle('drivers:start', () => { engine.drivers.start(); return true; });
  ipcMain.handle('drivers:stop', () => { engine.drivers.stop(); return true; });
  ipcMain.handle('drivers:act', (_e, ids) => { if (strList(ids)) engine.drivers.act(ids); return true; });
  ipcMain.handle('drivers:ignore', (_e, id) => { if (str(id)) engine.drivers.ignore(id); return true; });
  ipcMain.handle('win:minimize', () => { if (win) win.minimize(); });
  ipcMain.handle('win:maximize', () => { if (win) { if (win.isMaximized()) win.unmaximize(); else win.maximize(); } });
  ipcMain.handle('win:close', () => { if (win) win.close(); });
}

/* ---------- development test hook (only when POWERSCAN_TEST_SCRIPT is set) ---------- */
function runTestScript() {
  const script = require(path.resolve(process.env.POWERSCAN_TEST_SCRIPT));
  const outDir = process.env.POWERSCAN_TEST_OUT || path.join(app.getPath('temp'), 'power-scan-test');
  fs.mkdirSync(outDir, { recursive: true });
  const t = {
    exec: (js) => win.webContents.executeJavaScript(js, true),
    wait: (ms) => new Promise((r) => setTimeout(r, ms)),
    shot: async (name) => { const img = await win.webContents.capturePage(); fs.writeFileSync(path.join(outDir, name + '.png'), img.toPNG()); },
    log: (...a) => console.log('[test]', ...a),
    win,
  };
  Promise.resolve(script(t)).catch((e) => console.log('[test] FAILED', e && e.stack)).finally(() => { quitting = true; app.quit(); });
}

/* ---------- lifecycle ---------- */
app.on('second-instance', showWindow);
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-navigate', (ev) => ev.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});
app.on('before-quit', () => {
  quitting = true;
  if (engine) { engine.scan.stop(); engine.speed.stop(); engine.drivers.stop(); engine.traffic.stop(); }
  if (store) store.flush();
});
app.on('window-all-closed', () => { if (!listener.on || quitting) app.quit(); });

app.whenReady().then(async () => {
  store = new Store(path.join(app.getPath('userData'), 'settings.json'));
  engine = createEngine(store);
  wireEngine();
  wireIpc();
  engine.refreshInfo().catch(() => {});
  if (store.get('listenerOn') && !process.env.POWERSCAN_TEST_SCRIPT) {
    listener.on = true;
    if (store.get('lastScanAt')) startTraffic(); else { listener.phase = 'baseline'; engine.scan.start(engine.info); }
    updateTray();
  }
  createWindow();
});
